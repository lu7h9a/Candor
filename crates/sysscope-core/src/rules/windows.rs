//! Rules that look at a sliding window of events (plan 5.4):
//! R005 mass file rewrite, R006 beaconing, R007 connection fan-out,
//! R008 event flood.
//!
//! Windows use event time, never wall time, so replay gives the same answer
//! as live tracing. Every window and tracker is bounded (I8): windows keep at
//! most WINDOW_ENTRIES records, R006 keeps BEACON_POINTS timestamps for at
//! most `max_keys` destinations (least recently used dropped first).

use super::vars;
use crate::config::Rules;
use crate::detect::Hit;
use crate::limits;
use crate::state::State;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use sysscope_proto::{BStr, Event, EventKind, Family, ProcKey};

const SEC: u64 = 1_000_000_000;

/// Splits a path into (directory, file name).
fn split_path(p: &[u8]) -> (&[u8], &[u8]) {
    match p.iter().rposition(|&b| b == b'/') {
        Some(i) => (p.get(..i).unwrap_or(b""), p.get(i + 1..).unwrap_or(b"")),
        None => (b"", p),
    }
}

/// Extension of a file name ("a.docx.locked" -> "locked"), if any.
fn ext(name: &[u8]) -> Option<Vec<u8>> {
    let i = name.iter().rposition(|&b| b == b'.')?;
    if i == 0 {
        return None; // hidden file, no extension
    }
    name.get(i + 1..).map(|e| e.to_vec())
}

// ------------------------------------------------------------------ R005

/// One R005 observation in the window.
#[derive(Clone, Debug)]
enum Obs {
    /// Inode opened for writing (create = O_CREAT set).
    WriteOpen {
        ino: (u64, u64),
        dir: Vec<u8>,
        name: Vec<u8>,
        create: bool,
        trunc: bool,
    },
    /// Inode renamed.
    Rename {
        ino: (u64, u64),
        old_name: Vec<u8>,
        new_name: Vec<u8>,
    },
    /// Inode unlinked.
    Unlink {
        ino: (u64, u64),
        dir: Vec<u8>,
        name: Vec<u8>,
    },
}

#[derive(Clone, Debug, Default)]
struct R005Window {
    items: VecDeque<(u64, Event, Obs)>,
}

/// Window state of all windowed rules.
#[derive(Clone, Debug, Default)]
pub struct WindowState {
    r005: BTreeMap<ProcKey, R005Window>,
    r007: BTreeMap<ProcKey, R007Window>,
    r006: BTreeMap<BeaconKey, Beacon>,
    /// last_use -> key, so the least recently used key is found in O(log n).
    r006_lru: BTreeMap<u64, BeaconKey>,
    r006_clock: u64,
    r008: BTreeMap<ProcKey, (u64, u32)>,
}

/// R007 window with distinct-destination counts kept up to date as
/// connects enter and leave the window (incremental, no rescans).
#[derive(Clone, Debug, Default)]
struct R007Window {
    q: VecDeque<(u64, Event, String, u16)>,
    /// (addr, port) -> connects in the window.
    dests: BTreeMap<(String, u16), u32>,
    /// addr -> distinct ports in the window.
    ports_of: BTreeMap<String, usize>,
    /// port -> distinct addrs in the window.
    addrs_of: BTreeMap<u16, usize>,
}

impl R007Window {
    fn add(&mut self, ts: u64, ev: Event, addr: String, port: u16) {
        if self.q.len() >= limits::WINDOW_ENTRIES {
            self.pop();
        }
        let n = self.dests.entry((addr.clone(), port)).or_insert(0);
        *n += 1;
        if *n == 1 {
            *self.ports_of.entry(addr.clone()).or_insert(0) += 1;
            *self.addrs_of.entry(port).or_insert(0) += 1;
        }
        self.q.push_back((ts, ev, addr, port));
    }

    fn pop(&mut self) {
        let Some((_, _, addr, port)) = self.q.pop_front() else {
            return;
        };
        let key = (addr, port);
        let gone = match self.dests.get_mut(&key) {
            Some(n) => {
                *n -= 1;
                *n == 0
            }
            None => false,
        };
        if gone {
            self.dests.remove(&key);
            dec(&mut self.ports_of, key.0);
            dec(&mut self.addrs_of, key.1);
        }
    }
}

fn dec<K: Ord>(m: &mut BTreeMap<K, usize>, k: K) {
    if let Some(v) = m.get_mut(&k) {
        *v -= 1;
        if *v == 0 {
            m.remove(&k);
        }
    }
}

/// (exe, address, port) of an R006 tracker.
type BeaconKey = (Vec<u8>, String, u16);

#[derive(Clone, Debug, Default)]
struct Beacon {
    times: VecDeque<u64>,
    events: VecDeque<Event>,
    last_use: u64,
}

fn in_user_data(path: &[u8], roots: &[String], excluded: &[String]) -> bool {
    if !roots.iter().any(|r| path.starts_with(r.as_bytes())) {
        return false;
    }
    !path
        .split(|&b| b == b'/')
        .any(|c| excluded.iter().any(|x| x.as_bytes() == c))
}

fn push_bounded<T>(q: &mut VecDeque<T>, item: T) {
    if q.len() >= limits::WINDOW_ENTRIES {
        q.pop_front();
    }
    q.push_back(item);
}

impl WindowState {
    /// Forgets windows of processes that are no longer in the state.
    pub fn prune(&mut self, st: &State) {
        self.r005.retain(|k, _| st.get(k).is_some());
        self.r007.retain(|k, _| st.get(k).is_some());
        self.r008.retain(|k, _| st.get(k).is_some());
    }

    /// Number of R006 destinations tracked (for tests).
    pub fn beacon_keys(&self) -> usize {
        self.r006.len()
    }

    /// Entries in a process's R005 and R007 windows (for tests).
    pub fn window_lens(&self, k: &ProcKey) -> (usize, usize) {
        (
            self.r005.get(k).map(|w| w.items.len()).unwrap_or(0),
            self.r007.get(k).map(|w| w.q.len()).unwrap_or(0),
        )
    }

    /// Runs the event-driven windowed rules on one event.
    pub fn on_event(&mut self, rules: &Rules, st: &State, ev: &Event) -> Vec<Hit> {
        let mut hits = Vec::new();
        // R005 aggregates per process and per direct parent ("process tree").
        let mut keys = vec![ev.proc];
        if let Some(parent) = st.get(&ev.proc).and_then(|p| p.parent) {
            keys.push(parent);
        }
        for k in keys {
            hits.extend(self.r005(rules, k, ev));
        }
        hits.extend(self.r006(rules, st, ev));
        hits.extend(self.r007(rules, ev));
        hits
    }

    fn r005(&mut self, rules: &Rules, group: ProcKey, ev: &Event) -> Option<Hit> {
        let cfg = rules.rule("R005")?;
        let obs = match &ev.kind {
            EventKind::Open {
                path,
                dev,
                ino,
                write,
                create,
                trunc,
                ..
            } if *write || *create || *trunc => {
                if !in_user_data(path.as_bytes(), &cfg.roots, &cfg.excluded_components) {
                    return None;
                }
                let (dir, name) = split_path(path.as_bytes());
                Obs::WriteOpen {
                    ino: (*dev, *ino),
                    dir: dir.to_vec(),
                    name: name.to_vec(),
                    create: *create,
                    trunc: *trunc,
                }
            }
            EventKind::Rename {
                old, new, dev, ino, ..
            } => {
                if !in_user_data(old.as_bytes(), &cfg.roots, &cfg.excluded_components) {
                    return None;
                }
                Obs::Rename {
                    ino: (*dev, *ino),
                    old_name: split_path(old.as_bytes()).1.to_vec(),
                    new_name: split_path(new.as_bytes()).1.to_vec(),
                }
            }
            EventKind::Unlink { path, dev, ino, .. } => {
                if !in_user_data(path.as_bytes(), &cfg.roots, &cfg.excluded_components) {
                    return None;
                }
                let (dir, name) = split_path(path.as_bytes());
                Obs::Unlink {
                    ino: (*dev, *ino),
                    dir: dir.to_vec(),
                    name: name.to_vec(),
                }
            }
            _ => return None,
        };
        // Only renames, unlinks and truncating opens of existing files can
        // raise R005's counts; other writes are recorded but not evaluated.
        let evaluate = match &obs {
            Obs::WriteOpen { create, trunc, .. } => *trunc && !*create,
            Obs::Rename { .. } | Obs::Unlink { .. } => true,
        };
        let window_ns = cfg.window_s? * SEC;
        let w = self.r005.entry(group).or_default();
        push_bounded(&mut w.items, (ev.ts_ns, ev.clone(), obs));
        while let Some((t, _, _)) = w.items.front() {
            if ev.ts_ns.saturating_sub(*t) > window_ns {
                w.items.pop_front();
            } else {
                break;
            }
        }
        if !evaluate {
            return None;
        }
        evaluate_r005(cfg, group, ev.ts_ns, w)
    }

    fn r006(&mut self, rules: &Rules, st: &State, ev: &Event) -> Option<Hit> {
        let cfg = rules.rule("R006")?;
        let EventKind::Connect {
            family, addr, port, ..
        } = &ev.kind
        else {
            return None;
        };
        if !matches!(family, Family::Inet | Family::Inet6) {
            return None;
        }
        let ip: IpAddr = addr.parse().ok()?;
        if ip.is_loopback() && !cfg.include_loopback.unwrap_or(false) {
            return None;
        }
        let exe = st
            .get(&ev.proc)
            .map(|p| p.exe.as_bytes().to_vec())
            .unwrap_or_default();
        let key = (exe, addr.clone(), *port);
        self.r006_clock += 1;
        let clock = self.r006_clock;
        if !self.r006.contains_key(&key) && self.r006.len() >= cfg.max_keys? {
            // Drop the least recently used destination (bounded, I8).
            if let Some((_, old)) = self.r006_lru.pop_first() {
                self.r006.remove(&old);
            }
        }
        let b = self.r006.entry(key.clone()).or_default();
        self.r006_lru.remove(&b.last_use);
        b.last_use = clock;
        self.r006_lru.insert(clock, key);
        if b.times.len() >= limits::BEACON_POINTS {
            b.times.pop_front();
        }
        b.times.push_back(ev.ts_ns);
        if b.events.len() >= 10 {
            b.events.pop_front();
        }
        b.events.push_back(ev.clone());
        evaluate_r006(cfg, ev, &ip, b)
    }

    fn r007(&mut self, rules: &Rules, ev: &Event) -> Option<Hit> {
        let cfg = rules.rule("R007")?;
        let EventKind::Connect {
            family, addr, port, ..
        } = &ev.kind
        else {
            return None;
        };
        if !matches!(family, Family::Inet | Family::Inet6) {
            return None;
        }
        let window_ns = cfg.window_s? * SEC;
        let w = self.r007.entry(ev.proc).or_default();
        w.add(ev.ts_ns, ev.clone(), addr.clone(), *port);
        while let Some((t, _, _, _)) = w.q.front() {
            if ev.ts_ns.saturating_sub(*t) > window_ns {
                w.pop();
            } else {
                break;
            }
        }
        // Only this connect's address and port can have just crossed a line.
        let max_ports = w.ports_of.get(addr).copied().unwrap_or(0);
        let max_addrs = w.addrs_of.get(port).copied().unwrap_or(0);
        let fired = w.dests.len() >= cfg.distinct_dests?
            || max_ports >= cfg.ports_one_addr?
            || max_addrs >= cfg.addrs_one_port?;
        if !fired {
            return None;
        }
        let dests = &w.dests;
        let count = dests.len();
        Some(Hit {
            rule: "R007".into(),
            proc: ev.proc,
            subject: "fanout".into(),
            confidence: cfg.confidence? as f32,
            ts_ns: ev.ts_ns,
            // Newest 100 connects of the window justify the finding.
            evidence: w
                .q
                .iter()
                .rev()
                .take(100)
                .map(|(_, e, _, _)| e.clone())
                .collect(),
            summary: format!(
                "connected to {count} destinations ({max_ports} ports on one address, {max_addrs} addresses on one port)"
            ),
            vars: vars(&[
                ("count", count.to_string()),
                ("window_s", cfg.window_s?.to_string()),
            ]),
            extra_why: Vec::new(),
        })
    }

    /// R008: per-process kernel budget drops reported once per second.
    /// `drops` lists processes that lost events in the second ending at `ts`.
    pub fn on_budget_drops(
        &mut self,
        rules: &Rules,
        st: &State,
        ts: u64,
        drops: &[(ProcKey, u64)],
    ) -> Vec<Hit> {
        let Some(cfg) = rules.rule("R008") else {
            return Vec::new();
        };
        let Some(need) = cfg.consecutive_s else {
            return Vec::new();
        };
        let Some(conf) = cfg.confidence else {
            return Vec::new();
        };
        let dropping: BTreeSet<ProcKey> = drops
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(k, _)| *k)
            .collect();
        // A process without drops this second starts counting again.
        self.r008.retain(|k, _| dropping.contains(k));
        let mut hits = Vec::new();
        for k in dropping {
            let e = self.r008.entry(k).or_insert((ts, 0));
            // Consecutive means the previous report was about one second ago.
            if e.1 > 0 && ts.saturating_sub(e.0) > 3 * SEC / 2 {
                e.1 = 0;
            }
            e.0 = ts;
            e.1 += 1;
            if u64::from(e.1) >= need {
                let evidence: Vec<Event> = st
                    .get(&k)
                    .and_then(|p| p.recent.back().cloned())
                    .into_iter()
                    .collect();
                hits.push(Hit {
                    rule: "R008".into(),
                    proc: k,
                    subject: "flood".into(),
                    confidence: conf as f32,
                    ts_ns: ts,
                    evidence,
                    summary: format!(
                        "lost events to the per-process budget for {} seconds in a row",
                        e.1
                    ),
                    vars: vars(&[("consecutive_s", need.to_string())]),
                    extra_why: Vec::new(),
                });
            }
        }
        hits
    }
}

fn evaluate_r005(
    cfg: &crate::config::RuleCfg,
    group: ProcKey,
    now: u64,
    w: &R005Window,
) -> Option<Hit> {
    // Inodes opened for writing in the window, and directories with new files.
    let mut written: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut created_in_dir: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    let mut trunc_existing: BTreeMap<(u64, u64), Vec<u8>> = BTreeMap::new();
    // (a) rewritten inodes -> new extension (None if none or unchanged).
    let mut rewritten: BTreeMap<(u64, u64), Option<Vec<u8>>> = BTreeMap::new();
    let mut evidence: Vec<Event> = Vec::new();
    for (_, ev, obs) in &w.items {
        match obs {
            Obs::WriteOpen {
                ino,
                dir,
                name,
                create,
                trunc,
            } => {
                written.insert(*ino);
                if *create {
                    created_in_dir
                        .entry(dir.clone())
                        .or_default()
                        .push(name.clone());
                }
                if *trunc && !*create {
                    trunc_existing.insert(*ino, dir.clone());
                }
            }
            Obs::Rename {
                ino,
                old_name,
                new_name,
            } => {
                if written.contains(ino) {
                    let new_ext = ext(new_name).filter(|e| ext(old_name).as_ref() != Some(e));
                    rewritten.insert(*ino, new_ext);
                    evidence.push(ev.clone());
                }
            }
            Obs::Unlink { ino, dir, name } => {
                if let Some(siblings) = created_in_dir.get(dir)
                    && !siblings.is_empty()
                {
                    // The new extension is that of a sibling named "<name>.<ext>".
                    let mut prefix = name.clone();
                    prefix.push(b'.');
                    let new_ext = siblings
                        .iter()
                        .find(|s| s.starts_with(&prefix))
                        .and_then(|s| ext(s));
                    rewritten.insert(*ino, new_ext);
                    evidence.push(ev.clone());
                }
            }
        }
    }
    let n = rewritten.len();
    if n >= cfg.rename_min_files? {
        let mut counts: BTreeMap<&Vec<u8>, usize> = BTreeMap::new();
        for e in rewritten.values().flatten() {
            *counts.entry(e).or_default() += 1;
        }
        let (top_ext, top) = counts
            .iter()
            .max_by_key(|(_, c)| **c)
            .map(|(e, c)| ((*e).clone(), *c))
            .unwrap_or_default();
        let share = top as f64 / n as f64;
        let common = share >= cfg.rename_common_ext_share?;
        let c = if common {
            cfg.confidence_common_ext?
        } else {
            cfg.confidence_mixed?
        };
        let mut extra = Vec::new();
        if common {
            extra.push(format!(
                "{} of them got the same new extension \".{}\"",
                top,
                BStr::new(top_ext)
            ));
        }
        return Some(Hit {
            rule: "R005".into(),
            proc: group,
            subject: "mass_rewrite".into(),
            confidence: c as f32,
            ts_ns: now,
            evidence,
            summary: format!("{n} files were rewritten and renamed or replaced"),
            vars: vars(&[
                ("count", n.to_string()),
                ("window_s", cfg.window_s?.to_string()),
            ]),
            extra_why: extra,
        });
    }
    let dirs: BTreeSet<&Vec<u8>> = trunc_existing.values().collect();
    if trunc_existing.len() >= cfg.trunc_min_files? && dirs.len() >= cfg.trunc_min_dirs? {
        let evidence: Vec<Event> = w
            .items
            .iter()
            .filter(|(_, _, o)| {
                matches!(
                    o,
                    Obs::WriteOpen {
                        trunc: true,
                        create: false,
                        ..
                    }
                )
            })
            .map(|(_, e, _)| e.clone())
            .collect();
        let n = trunc_existing.len();
        return Some(Hit {
            rule: "R005".into(),
            proc: group,
            subject: "mass_rewrite".into(),
            confidence: cfg.confidence_trunc? as f32,
            ts_ns: now,
            evidence,
            summary: format!(
                "{n} existing files in {} directories were truncated and rewritten",
                dirs.len()
            ),
            vars: vars(&[
                ("count", n.to_string()),
                ("window_s", cfg.window_s?.to_string()),
            ]),
            extra_why: Vec::new(),
        });
    }
    None
}

/// True for addresses reachable on the public internet.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
        }
    }
}

fn evaluate_r006(cfg: &crate::config::RuleCfg, ev: &Event, ip: &IpAddr, b: &Beacon) -> Option<Hit> {
    let n = b.times.len();
    if n < cfg.min_connects? {
        return None;
    }
    let first = *b.times.front()?;
    let last = *b.times.back()?;
    if last.saturating_sub(first) < cfg.min_span_s? * SEC {
        return None;
    }
    let intervals: Vec<f64> = b
        .times
        .iter()
        .zip(b.times.iter().skip(1))
        .map(|(a, b)| b.saturating_sub(*a) as f64 / SEC as f64)
        .collect();
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < cfg.min_mean_interval_s? || mean > cfg.max_mean_interval_s? {
        return None;
    }
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let cv = var.sqrt() / mean;
    if cv > cfg.max_cv? {
        return None;
    }
    let public = is_public(ip);
    let c = if public {
        cfg.confidence_public?
    } else {
        cfg.confidence?
    };
    let EventKind::Connect { addr, port, .. } = &ev.kind else {
        return None;
    };
    let dest = format!("{addr}:{port}");
    let mut extra = vec![format!(
        "the gaps vary by only {:.0}% (coefficient of variation {cv:.2})",
        cv * 100.0
    )];
    if public {
        extra.push("the destination is a public internet address".into());
    }
    Some(Hit {
        rule: "R006".into(),
        proc: ev.proc,
        subject: dest.clone(),
        confidence: c as f32,
        ts_ns: ev.ts_ns,
        evidence: b.events.iter().cloned().collect(),
        summary: format!("connected to {dest} {n} times about every {mean:.0} seconds"),
        vars: vars(&[
            ("count", n.to_string()),
            ("dest", dest),
            ("interval", format!("{mean:.0}")),
        ]),
        extra_why: extra,
    })
}
