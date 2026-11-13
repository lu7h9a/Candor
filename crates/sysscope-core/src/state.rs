//! `State`: the process table, the process tree and the global event ring.
//!
//! The daemon's core thread owns exactly one `State` and feeds it `Input`s
//! in order. Everything here is deterministic: maps are `BTreeMap`s (sorted),
//! time only comes from the inputs, and nothing reads files or clocks
//! (invariant I7). Every collection is bounded (invariant I8, `limits.rs`).

use crate::input::{Input, ProcSample};
use crate::limits;
use crate::proc::Proc;
use std::collections::{BTreeMap, HashMap, VecDeque};
use sysscope_proto::{
    DaemonMsg, Event, EventKind, Loss, Mode, ProcKey, ProcRow, Series, SystemMode,
};

/// Counters about the state itself, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateStats {
    /// New processes refused because MAX_LIVE_PROCS were live.
    pub procs_refused: u64,
    /// Exited processes evicted (age or count).
    pub procs_evicted: u64,
    /// Events whose process could not be tracked (table full).
    pub events_unattributed: u64,
    /// Parent links refused because they would create a cycle.
    pub cycles_refused: u64,
}

/// The whole core state.
#[derive(Clone, Debug, Default)]
pub struct State {
    procs: BTreeMap<ProcKey, Proc>,
    live: usize,
    global: VecDeque<Event>,
    loss: Loss,
    now: u64,
    stats: StateStats,
}

impl State {
    /// An empty state.
    pub fn new() -> State {
        State::default()
    }

    /// Latest time seen in any input (boot ns).
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Diagnostics counters.
    pub fn stats(&self) -> StateStats {
        self.stats
    }

    /// Number of tracked processes (live and exited).
    pub fn len(&self) -> usize {
        self.procs.len()
    }

    /// True if no process is tracked.
    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    /// Number of live processes.
    pub fn live_count(&self) -> usize {
        self.live
    }

    /// Number of exited processes still kept.
    pub fn exited_count(&self) -> usize {
        self.procs.len() - self.live
    }

    /// One process, if tracked.
    pub fn get(&self, key: &ProcKey) -> Option<&Proc> {
        self.procs.get(key)
    }

    /// All tracked processes in key order.
    pub fn procs(&self) -> impl Iterator<Item = &Proc> {
        self.procs.values()
    }

    /// The global event ring, oldest first.
    pub fn global_events(&self) -> &VecDeque<Event> {
        &self.global
    }

    /// Applies one input.
    pub fn apply(&mut self, input: &Input) {
        match input {
            Input::RawEvent { event } => self.apply_event(event),
            Input::Samples { ts_ns, samples } => self.apply_samples(*ts_ns, samples),
            Input::Loss { loss } => self.loss = *loss,
            Input::Decoys { .. } => {} // used by the engine (rules), not the state
            Input::ExeMeta {
                proc,
                trusted,
                system_dir,
                home,
                ..
            } => {
                if let Some(p) = self.procs.get_mut(proc) {
                    p.exe_trusted = *trusted;
                    p.exe_system = *system_dir;
                    p.home = home.clone();
                }
            }
            Input::Tick { ts_ns } => self.tick(*ts_ns),
        }
    }

    fn advance(&mut self, ts: u64) {
        self.now = self.now.max(ts);
    }

    /// Makes sure `key` is tracked; returns false if the table is full.
    fn ensure(&mut self, key: ProcKey, uid: u32, ts: u64) -> bool {
        if self.procs.contains_key(&key) {
            return true;
        }
        if self.live >= limits::MAX_LIVE_PROCS {
            self.stats.procs_refused += 1;
            return false;
        }
        self.procs.insert(key, Proc::placeholder(key, uid, ts));
        self.live += 1;
        true
    }

    fn set_exited(&mut self, key: &ProcKey, ts: u64) {
        if let Some(p) = self.procs.get_mut(key)
            && p.exited_ts.is_none()
        {
            p.exited_ts = Some(ts);
            self.live -= 1;
        }
        self.enforce_exited_cap();
    }

    /// True if making `parent` the parent of `child` would close a cycle.
    fn would_cycle(&self, child: ProcKey, parent: ProcKey) -> bool {
        let mut cur = Some(parent);
        // A walk longer than the table means a cycle already; stop there.
        for _ in 0..=self.procs.len() {
            match cur {
                None => return false,
                Some(k) if k == child => return true,
                Some(k) => cur = self.procs.get(&k).and_then(|p| p.parent),
            }
        }
        true
    }

    fn link(&mut self, child: ProcKey, parent: ProcKey) {
        if child == parent || self.would_cycle(child, parent) {
            self.stats.cycles_refused += 1;
            return;
        }
        if !self.procs.contains_key(&parent) {
            return;
        }
        if let Some(c) = self.procs.get_mut(&child) {
            if c.parent.is_some() || c.orphan {
                return; // keep the first parent we learned
            }
            c.parent = Some(parent);
        }
        if let Some(p) = self.procs.get_mut(&parent) {
            p.children.insert(child);
        }
    }

    fn push_global(&mut self, ev: &Event) {
        if self.global.len() >= limits::GLOBAL_EVENTS {
            self.global.pop_front();
        }
        self.global.push_back(ev.clone());
    }

    /// Applies one kernel event.
    pub fn apply_event(&mut self, ev: &Event) {
        self.advance(ev.ts_ns);
        self.push_global(ev);
        if !self.ensure(ev.proc, ev.uid, ev.ts_ns) {
            self.stats.events_unattributed += 1;
            return;
        }
        if let EventKind::Fork { child } = &ev.kind {
            let child = *child;
            let inherited = self
                .procs
                .get(&ev.proc)
                .map(|p| (p.exe.clone(), p.comm.clone(), p.placeholder));
            if self.ensure(child, ev.uid, ev.ts_ns) {
                if let (Some((exe, comm, placeholder)), Some(c)) =
                    (inherited, self.procs.get_mut(&child))
                    && c.placeholder
                {
                    c.exe = exe;
                    c.comm = comm;
                    c.placeholder = placeholder;
                }
                self.link(child, ev.proc);
            }
        }
        let exiting = matches!(ev.kind, EventKind::Exit {});
        if let Some(p) = self.procs.get_mut(&ev.proc) {
            if exiting {
                // set_exited below does the bookkeeping; count the event only.
                p.push_recent(ev);
                p.last_seen = p.last_seen.max(ev.ts_ns);
            } else {
                p.count_event(ev);
            }
        }
        if exiting {
            self.set_exited(&ev.proc, ev.ts_ns);
        }
    }

    /// Applies one full /proc scan taken at `ts`.
    pub fn apply_samples(&mut self, ts: u64, samples: &[ProcSample]) {
        self.advance(ts);
        let by_tgid: HashMap<u32, ProcKey> = samples.iter().map(|s| (s.key.tgid, s.key)).collect();
        let mut seen = std::collections::HashSet::new();
        for s in samples {
            if !self.ensure(s.key, s.uid, ts) {
                continue;
            }
            seen.insert(s.key);
            if let Some(p) = self.procs.get_mut(&s.key) {
                update_from_sample(p, s, ts);
            }
            if let Some(parent) = by_tgid.get(&s.ppid).copied()
                && s.ppid != 0
            {
                self.link(s.key, parent);
            }
        }
        // A live process missing from consecutive full scans has gone even
        // if its EXIT event was lost.
        let mut gone = Vec::new();
        for p in self.procs.values_mut() {
            if !p.is_live() || seen.contains(&p.key) {
                p.missed_scans = 0;
                continue;
            }
            p.missed_scans += 1;
            if p.missed_scans >= limits::MISSED_SCANS_TO_EXIT {
                gone.push(p.key);
            }
        }
        for k in gone {
            self.set_exited(&k, ts);
        }
    }

    /// Advances time: evicts exited processes past retention.
    pub fn tick(&mut self, now: u64) {
        self.advance(now);
        let old: Vec<ProcKey> = self
            .procs
            .values()
            .filter(|p| {
                p.exited_ts
                    .is_some_and(|t| self.now.saturating_sub(t) > limits::EXITED_RETENTION_NS)
            })
            .map(|p| p.key)
            .collect();
        for k in old {
            self.evict(&k);
        }
        self.enforce_exited_cap();
    }

    fn enforce_exited_cap(&mut self) {
        let excess = self.exited_count().saturating_sub(limits::MAX_EXITED_PROCS);
        if excess == 0 {
            return;
        }
        let mut exited: Vec<(u64, ProcKey)> = self
            .procs
            .values()
            .filter_map(|p| p.exited_ts.map(|t| (t, p.key)))
            .collect();
        exited.sort();
        for (_, k) in exited.into_iter().take(excess) {
            self.evict(&k);
        }
    }

    fn evict(&mut self, key: &ProcKey) {
        let Some(p) = self.procs.remove(key) else {
            return;
        };
        if p.is_live() {
            self.live -= 1;
        }
        self.stats.procs_evicted += 1;
        if let Some(parent) = p.parent
            && let Some(pp) = self.procs.get_mut(&parent)
        {
            pp.children.remove(key);
        }
        for c in &p.children {
            if let Some(cp) = self.procs.get_mut(c) {
                cp.parent = None;
                cp.orphan = true;
            }
        }
    }

    /// Snapshot rows for every tracked process, in key order.
    pub fn rows(&self) -> Vec<ProcRow> {
        self.procs
            .values()
            .map(|p| {
                let parent = p.parent.filter(|k| self.procs.contains_key(k));
                p.row(parent)
            })
            .collect()
    }

    /// A full Snapshot message.
    pub fn snapshot(&self, seq: u64) -> DaemonMsg {
        DaemonMsg::Snapshot {
            seq,
            ts_ns: self.now,
            mode: Mode::System(SystemMode::System),
            procs: self.rows(),
            loss: self.loss,
        }
    }

    /// A Detail message for one process, if tracked.
    pub fn detail(&self, key: &ProcKey) -> Option<DaemonMsg> {
        let p = self.procs.get(key)?;
        Some(DaemonMsg::Detail {
            proc: p.key,
            series: Series {
                t: p.series.iter().map(|s| s.0).collect(),
                cpu: p.series.iter().map(|s| s.1).collect(),
                rss: p.series.iter().map(|s| s.2).collect(),
            },
            recent: p.recent.iter().cloned().collect(),
            files: p.files.values().cloned().collect(),
            conns: p.conn_stats(),
            syscalls: p.syscalls.values().cloned().collect(),
            children: p.children.iter().copied().collect(),
            maps: None,
            findings: Vec::new(),
        })
    }
}

fn update_from_sample(p: &mut Proc, s: &ProcSample, ts: u64) {
    if p.placeholder || p.exe.as_bytes().is_empty() {
        p.exe = s.exe.clone();
    }
    p.placeholder = false;
    p.comm = s.comm.clone();
    p.uid = s.uid;
    p.kthread = s.kthread;
    p.rss = s.rss;
    p.threads = s.threads;
    p.io_r = s.io_r;
    p.io_w = s.io_w;
    p.last_seen = p.last_seen.max(ts);
    if let Some((t0, c0)) = p.last_cpu
        && ts > t0
    {
        let busy_ns = s.cpu_ticks.saturating_sub(c0) as f64 * (1e9 / limits::CLK_TCK as f64);
        p.cpu_pct = (busy_ns / (ts - t0) as f64 * 100.0) as f32;
    }
    p.last_cpu = Some((ts, s.cpu_ticks));
    p.push_series(ts, p.cpu_pct, p.rss);
}
