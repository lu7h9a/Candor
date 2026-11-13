//! The daemon proper (plan 4.2): wiring of the threads and the core loop.
//!
//! T1 poller (main thread, owns the BPF object) -> bounded channel 65536,
//! blocking send -> T3 core. T2 sampler -> bounded channel 64 -> T3. T4
//! acceptor and per-client reader/writer threads <-> T3 through `ClientCmd`
//! and per-client queues. T3 is the only owner of `Engine` (all state): no
//! locks around state, other threads talk to it by message.

use crate::collector::{self, Collector, LoadOpts, PollerCmd, PollerMsg};
use crate::hostinfo;
use crate::server::{self, ClientCmd, ClientQueue, SocketSpec};
use anyhow::{Context, Result, bail};
use crossbeam_channel::{Receiver, Sender, select};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use sysscope_core::config::{Rules, load_allow};
use sysscope_core::{Engine, Input, ProcSample};
use sysscope_proto::{
    ClientMsg, DaemonMsg, EventKind, EventSub, EventSubMode, Mode, PROTO_VERSION, ProcKey, SysStat,
};

/// /etc/sysscope/sysscoped.toml.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// "count" (default) or "off".
    #[serde(default = "default_syscalls")]
    pub syscalls: String,
}

fn default_syscalls() -> String {
    "count".into()
}

fn read_optional(path: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {path}")),
    }
}

/// Loads the daemon config and the rules/allowlist overrides. Any error
/// means the daemon refuses to start.
pub fn load_config(
    rules_file: Option<&std::path::Path>,
) -> Result<(DaemonConfig, Rules, Vec<sysscope_core::config::AllowEntry>)> {
    let cfg: DaemonConfig = match read_optional("/etc/sysscope/sysscoped.toml")? {
        Some(t) => toml::from_str(&t).context("/etc/sysscope/sysscoped.toml")?,
        None => DaemonConfig {
            syscalls: default_syscalls(),
        },
    };
    if cfg.syscalls != "count" && cfg.syscalls != "off" {
        bail!("/etc/sysscope/sysscoped.toml: syscalls must be \"count\" or \"off\"");
    }
    // `--rules FILE` (dev mode only, tests) replaces /etc/sysscope/rules.toml.
    let override_text = match rules_file {
        Some(p) => {
            Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)
        }
        None => read_optional("/etc/sysscope/rules.toml")?,
    };
    let rules = Rules::load(override_text.as_deref())?;
    let allow = load_allow(
        &rules,
        read_optional("/etc/sysscope/allow.toml")?.as_deref(),
    )?;
    Ok((cfg, rules, allow))
}

/// Daemon options from the command line.
pub struct RunOpts {
    /// Collector options.
    pub load: LoadOpts,
    /// Dev mode (socket under /run/sysscope-dev).
    pub dev: bool,
    /// Record core inputs to this file.
    pub record: Option<std::path::PathBuf>,
    /// Experimental act mode (D19).
    pub enable_act: bool,
    /// Rules override file instead of /etc/sysscope/rules.toml (dev only).
    pub rules_file: Option<std::path::PathBuf>,
}

struct Client {
    queue: Arc<ClientQueue>,
    /// SO_PEERCRED of the connection (act mode authorisation).
    peer: crate::act::Requester,
    hello: bool,
    snapshots: bool,
    alerts: bool,
    events: EventSub,
}

/// Everything the core thread (T3) owns.
struct Core {
    engine: Engine,
    clients: BTreeMap<u64, Client>,
    homes: BTreeMap<u32, Vec<u8>>,
    poller: Sender<PollerCmd>,
    follow: Option<ProcKey>,
    follow_requester: Option<u64>,
    welcome: DaemonMsg,
    record: Option<std::io::BufWriter<std::fs::File>>,
    seq: u64,
    gh: crate::glasshouse::Glasshouse,
    last_loss: sysscope_proto::Loss,
    act_enabled: bool,
    /// Processes already verified (exec or scan); see `unchecked`.
    checked: std::collections::BTreeSet<ProcKey>,
}

impl Core {
    fn apply(&mut self, input: Input) {
        if let Some(w) = self.record.as_mut()
            && let Ok(line) = serde_json::to_string(&input)
        {
            let _ = writeln!(w, "{line}");
        }
        for alert in self.engine.apply(&input) {
            for c in self.clients.values().filter(|c| c.hello && c.alerts) {
                c.queue.put_alert(&alert);
            }
        }
    }

    fn on_poller(&mut self, msg: PollerMsg) {
        match msg {
            PollerMsg::GhReady => self.gh.ready(),
            PollerMsg::Event(ev) => {
                self.gh.observe(&ev);
                for c in self.clients.values().filter(|c| c.hello) {
                    let wanted = match c.events {
                        EventSub::Simple(EventSubMode::All) => true,
                        EventSub::Simple(EventSubMode::None) => false,
                        EventSub::Proc { proc } => proc == ev.proc,
                    };
                    if wanted {
                        c.queue.put_event(&ev);
                    }
                }
                let exec = match &ev.kind {
                    EventKind::Exec { exe, argv, .. } => Some((exe.clone(), argv.clone())),
                    _ => None,
                };
                let (key, uid) = (ev.proc, ev.uid);
                self.apply(Input::RawEvent { event: ev });
                if let Some((exe, argv)) = exec {
                    // A box process's exe path names a file in the sandbox's
                    // view: never stat it on the host; it is untrusted.
                    let (trusted, system_dir, world_writable_dir) = if self.gh.in_box(&key) {
                        (false, false, false)
                    } else {
                        hostinfo::exe_facts(key, &exe, crate::follow::start_of(key.tgid))
                    };
                    // Inside the Glasshouse box "~" is the sandbox home.
                    let home = if self.gh.in_box(&key) {
                        b"/home/victim".to_vec()
                    } else {
                        self.homes.get(&uid).cloned().unwrap_or_default()
                    };
                    let script_trusted = !self.gh.in_box(&key)
                        && sysscope_core::proc::script_of(&exe, &argv)
                            .is_some_and(|s| hostinfo::script_trusted(&s));
                    self.apply(Input::ExeMeta {
                        proc: key,
                        trusted,
                        system_dir,
                        home: sysscope_proto::BStr(home),
                        world_writable_dir,
                        script_trusted,
                    });
                }
            }
            PollerMsg::Loss(loss) => {
                self.last_loss = loss;
                self.apply(Input::Loss { loss });
            }
            PollerMsg::Drops { ts_ns, per_proc } => {
                self.gh.drops(&per_proc);
                self.apply(Input::BudgetDrops {
                    ts_ns,
                    drops: per_proc,
                });
            }
            PollerMsg::Sys { ts_ns, totals } => {
                let totals = totals
                    .into_iter()
                    .map(|((key, nr), t)| {
                        (
                            key,
                            SysStat {
                                nr,
                                name: crate::syscalls::name(nr),
                                count: t.count,
                                lat_count: t.lat_count,
                                lat_total_ns: t.lat_total_ns,
                                lat_max_ns: t.lat_max_ns,
                            },
                        )
                    })
                    .collect();
                self.apply(Input::SysTotals { ts_ns, totals });
            }
            PollerMsg::FollowResult(res) => {
                let msg = match res {
                    Ok(m) => DaemonMsg::ActResult {
                        ok: true,
                        message: m,
                    },
                    Err(e) => {
                        self.follow = None;
                        DaemonMsg::Error {
                            code: "follow_failed".into(),
                            message: e,
                        }
                    }
                };
                if let Some(id) = self.follow_requester.take()
                    && let Some(c) = self.clients.get(&id)
                {
                    c.queue.put_reply(msg);
                }
            }
        }
    }

    fn on_client(&mut self, cmd: ClientCmd) {
        match cmd {
            ClientCmd::New {
                id,
                queue,
                uid,
                pid,
            } => {
                self.clients.insert(
                    id,
                    Client {
                        queue,
                        peer: crate::act::Requester { uid, pid },
                        hello: false,
                        snapshots: false,
                        alerts: false,
                        events: EventSub::Simple(EventSubMode::None),
                    },
                );
            }
            ClientCmd::Gone { id } => {
                self.gh.client_gone(id);
                if let Some(c) = self.clients.remove(&id) {
                    c.queue.close();
                }
            }
            ClientCmd::Msg { id, msg } => self.on_message(id, msg),
        }
    }

    fn on_message(&mut self, id: u64, msg: ClientMsg) {
        let Some(c) = self.clients.get_mut(&id) else {
            return;
        };
        let q = Arc::clone(&c.queue);
        if !c.hello {
            match msg {
                ClientMsg::Hello { proto, .. } if proto == PROTO_VERSION => {
                    c.hello = true;
                    q.put_reply(self.welcome.clone());
                }
                ClientMsg::Hello { proto, .. } => q.reply_and_close(DaemonMsg::Error {
                    code: "proto_mismatch".into(),
                    message: format!("daemon speaks protocol {PROTO_VERSION}, client {proto}"),
                }),
                _ => q.reply_and_close(DaemonMsg::Error {
                    code: "hello_required".into(),
                    message: "the first message must be Hello".into(),
                }),
            }
            return;
        }
        match msg {
            ClientMsg::Hello { .. } => q.put_reply(DaemonMsg::Error {
                code: "duplicate_hello".into(),
                message: "Hello was already sent".into(),
            }),
            ClientMsg::Subscribe {
                snapshots,
                alerts,
                events,
            } => {
                c.snapshots = snapshots;
                c.alerts = alerts;
                c.events = events;
            }
            ClientMsg::Ping { n } => q.put_reply(DaemonMsg::Pong { n }),
            ClientMsg::GetDetail { proc, maps } => {
                let reply = match self.engine.state.detail(&proc) {
                    Some(DaemonMsg::Detail {
                        proc,
                        series,
                        recent,
                        files,
                        conns,
                        syscalls,
                        children,
                        ..
                    }) => DaemonMsg::Detail {
                        proc,
                        series,
                        recent,
                        files,
                        conns,
                        syscalls,
                        children,
                        maps: if maps {
                            hostinfo::read_maps(proc, 5000)
                        } else {
                            None
                        },
                        findings: self.engine.detector.findings_for(&proc),
                    },
                    _ => DaemonMsg::Error {
                        code: "unknown_process".into(),
                        message: format!("process {} is not tracked", proc.tgid),
                    },
                };
                q.put_reply(fit_detail(reply));
            }
            ClientMsg::Follow { root } => {
                let known = self.engine.state.get(&root).is_some_and(|p| p.is_live());
                if !known {
                    q.put_reply(DaemonMsg::Error {
                        code: "unknown_process".into(),
                        message: format!("process {} is not running", root.tgid),
                    });
                } else if self.poller.try_send(PollerCmd::Follow(root)).is_ok() {
                    self.follow = Some(root);
                    self.follow_requester = Some(id);
                } else {
                    q.put_reply(DaemonMsg::Error {
                        code: "busy".into(),
                        message: "a follow request is already being handled".into(),
                    });
                }
            }
            ClientMsg::Unfollow {} => {
                if self.poller.try_send(PollerCmd::Unfollow).is_ok() {
                    self.follow = None;
                    self.follow_requester = Some(id);
                } else {
                    q.put_reply(DaemonMsg::Error {
                        code: "busy".into(),
                        message: "a follow request is already being handled".into(),
                    });
                }
            }
            ClientMsg::Act {
                proc,
                action,
                nonce,
            } => {
                let peer = c.peer;
                let res = if self.act_enabled {
                    crate::act::act(peer, proc, action)
                } else {
                    Err("act mode is not enabled (sysscoped --enable-act)".into())
                };
                // Every request is logged (journal under systemd).
                eprintln!(
                    "sysscoped: act {action:?} pid {} requested by uid {} pid {} (nonce {}): {}",
                    proc.tgid,
                    peer.uid,
                    peer.pid,
                    sysscope_core::display::safe_str(&nonce),
                    match &res {
                        Ok(m) => format!("done: {m}"),
                        Err(e) => format!("refused: {e}"),
                    }
                );
                let (ok, message) = match res {
                    Ok(m) => (true, m),
                    Err(e) => (false, e),
                };
                q.put_reply(DaemonMsg::ActResult { ok, message });
            }
            ClientMsg::GhUploadBegin { name, size } => {
                for m in self.gh.begin(id, &name, size) {
                    q.put_reply(m);
                }
            }
            ClientMsg::GhUploadChunk { seq, b64 } => {
                for m in self.gh.chunk(id, seq, &b64) {
                    q.put_reply(m);
                }
            }
            ClientMsg::GhRun { args, timeout_s } => {
                for m in self.gh.start(id, &args, timeout_s, self.last_loss) {
                    q.put_reply(m);
                }
            }
            ClientMsg::GhCancel {} => {
                for m in self.gh.cancel(id) {
                    q.put_reply(m);
                }
            }
        }
    }

    fn gh_effects(&mut self, fx: &crate::glasshouse::Effects) {
        for cmd in &fx.poller {
            // The poller channel is small; these commands must not be lost
            // (a lost GhBox would leave the box waiting for Go).
            let _ = self.poller.send(cmd.clone());
        }
        if let Some(inodes) = &fx.decoys {
            self.apply(Input::Decoys {
                inodes: inodes.clone(),
            });
        }
    }

    /// Processes in a scan that the daemon has not verified yet (they were
    /// running before it started, or it missed their exec). The set of
    /// checked keys is bounded by what the latest scan contains.
    fn unchecked(&mut self, samples: &[ProcSample]) -> Vec<(ProcKey, sysscope_proto::BStr, u32)> {
        let now: std::collections::BTreeSet<ProcKey> = samples.iter().map(|s| s.key).collect();
        self.checked.retain(|k| now.contains(k));
        samples
            .iter()
            .filter(|s| {
                !s.kthread && !s.exe.as_bytes().is_empty() && !self.checked.contains(&s.key)
            })
            .filter(|s| self.engine.state.get(&s.key).is_none_or(|p| !p.exe_trusted))
            .map(|s| (s.key, s.exe.clone(), s.uid))
            .collect()
    }

    /// The same verification an exec gets, for processes found by a scan.
    fn check_existing(&mut self, fresh: Vec<(ProcKey, sysscope_proto::BStr, u32)>) {
        for (key, exe, uid) in fresh {
            self.checked.insert(key);
            if self.gh.in_box(&key) {
                continue;
            }
            let (trusted, system_dir, world_writable_dir) =
                hostinfo::exe_facts(key, &exe, crate::follow::start_of(key.tgid));
            let home = self.homes.get(&uid).cloned().unwrap_or_default();
            self.apply(Input::ExeMeta {
                proc: key,
                trusted,
                system_dir,
                home: sysscope_proto::BStr(home),
                world_writable_dir,
                script_trusted: false,
            });
        }
    }

    /// One message from a Glasshouse helper thread.
    fn on_gh(&mut self, ev: crate::glasshouse::GhEvent) {
        let now = crate::sampler::boot_ns();
        let fx = self.gh.on_helper(ev, now);
        self.gh_effects(&fx);
        if fx.finish {
            let procs = self.gh.box_procs();
            let findings: Vec<sysscope_proto::Finding> = self
                .engine
                .detector
                .findings()
                .filter(|f| procs.contains(&f.proc))
                .cloned()
                .collect();
            if let Some((owner, report)) = self.gh.report(findings, self.last_loss, now)
                // Fitted first, so the saved copy is the one the client gets.
                && let DaemonMsg::GhReport { report } = fit_report(DaemonMsg::GhReport { report })
            {
                let saved = match crate::glasshouse::save_report(&report) {
                    Ok(p) => format!("report saved to {}", p.display()),
                    Err(e) => format!("the report could not be saved: {e}"),
                };
                let run_id = report.run_id.clone();
                if let Some(c) = self.clients.get(&owner) {
                    c.queue.put_reply(DaemonMsg::GhReport { report });
                    c.queue.put_reply(DaemonMsg::GhStatus {
                        state: sysscope_proto::GhState::Finished,
                        run_id,
                        message: saved,
                        decoys: Vec::new(),
                    });
                }
            }
            let done = self.gh.finished();
            self.gh_effects(&done);
        }
        for (owner, msg) in fx.replies {
            if let Some(c) = self.clients.get(&owner) {
                c.queue.put_reply(msg);
            }
        }
    }

    fn snapshot(&mut self) {
        if let Some((owner, msg)) = self.gh.live()
            && let Some(c) = self.clients.get(&owner)
        {
            c.queue.put_reply(msg);
        }
        self.seq += 1;
        let mut msg = self.engine.snapshot(self.seq);
        if let DaemonMsg::Snapshot { mode, procs, .. } = &mut msg
            && let Some(root) = self.follow
        {
            *mode = Mode::Follow { follow: root };
            // Breadth-first over a children index: linear in the table size
            // (a hostile process tree cannot make this quadratic).
            let mut children: BTreeMap<ProcKey, Vec<ProcKey>> = BTreeMap::new();
            for r in procs.iter() {
                if let Some(p) = r.parent {
                    children.entry(p).or_default().push(r.key);
                }
            }
            let mut tree = std::collections::BTreeSet::from([root]);
            let mut todo = vec![root];
            while let Some(k) = todo.pop() {
                for c in children.get(&k).into_iter().flatten() {
                    if tree.insert(*c) {
                        todo.push(*c);
                    }
                }
            }
            for r in procs.iter_mut() {
                r.followed = tree.contains(&r.key);
            }
        }
        let Some(frame) = fit_snapshot(msg) else {
            return;
        };
        for c in self.clients.values().filter(|c| c.hello && c.snapshots) {
            c.queue.put_snapshot(Arc::clone(&frame));
        }
    }
}

/// Encodes a snapshot so that it always fits in one frame (review finding
/// 2): if it is too big, exited processes are left out, then executable
/// names are shortened to 64 bytes (ending in "..."). Each step is logged.
fn fit_snapshot(mut msg: DaemonMsg) -> Option<Arc<Vec<u8>>> {
    if let Some(f) = server::snapshot_frame(&msg) {
        return Some(f);
    }
    eprintln!("sysscoped: snapshot over the frame limit; leaving out exited processes");
    if let DaemonMsg::Snapshot { procs, .. } = &mut msg {
        procs.retain(|r| r.exited_ts.is_none());
    }
    if let Some(f) = server::snapshot_frame(&msg) {
        return Some(f);
    }
    eprintln!("sysscoped: snapshot still too big; shortening executable names");
    if let DaemonMsg::Snapshot { procs, .. } = &mut msg {
        for r in procs.iter_mut() {
            shorten(&mut r.exe.0, 64);
            shorten(&mut r.comm.0, 64);
        }
    }
    server::snapshot_frame(&msg)
}

/// A report must fit one frame: the timeline is halved until it does
/// (the report says so in its notes).
fn fit_report(mut msg: DaemonMsg) -> DaemonMsg {
    let size = |m: &DaemonMsg| {
        sysscope_proto::encode(m)
            .map(|b| b.len())
            .unwrap_or(usize::MAX)
    };
    while size(&msg) > sysscope_proto::MAX_DAEMON_FRAME as usize {
        let DaemonMsg::GhReport { report } = &mut msg else {
            break;
        };
        if report.timeline.is_empty() {
            // Then the other lists, largest first; the report says so.
            let lens = [
                report.created.len(),
                report.children.len(),
                report.findings.len(),
            ];
            let Some(&max) = lens.iter().max().filter(|m| **m > 0) else {
                report.notes.truncate(50);
                break;
            };
            if max == report.created.len() {
                report.created.truncate(max / 2);
            } else if max == report.children.len() {
                report.children.truncate(max / 2);
            } else {
                report.findings.truncate(max / 2);
            }
            report
                .notes
                .push("parts of the report were left out so it fits one message".into());
            report.notes.dedup();
            continue;
        }
        let keep = report.timeline.len() / 2;
        let cut = report.timeline.len() - keep;
        report.timeline.truncate(keep);
        report.notes.push(format!(
            "{cut} timeline events were left out so the report fits one message"
        ));
    }
    msg
}

fn shorten(b: &mut Vec<u8>, max: usize) {
    if b.len() > max {
        b.truncate(max.saturating_sub(3));
        b.extend_from_slice(b"...");
    }
}

/// Shrinks a Detail until it fits in one frame (review finding 2): lists
/// are capped first (500 recent events, 1000 files, 1000 connections), then
/// halved until the encoded message is under the frame limit.
pub fn fit_detail(mut msg: DaemonMsg) -> DaemonMsg {
    if let DaemonMsg::Detail {
        recent,
        files,
        conns,
        maps,
        ..
    } = &mut msg
    {
        let skip = recent.len().saturating_sub(500);
        recent.drain(..skip);
        files.sort_by_key(|f| std::cmp::Reverse(f.last_ts));
        files.truncate(1000);
        conns.truncate(1000);
        if let Some(m) = maps.as_mut() {
            m.truncate(5000);
        }
    }
    for _ in 0..16 {
        let size = sysscope_proto::encode(&msg)
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
        if size <= sysscope_proto::MAX_DAEMON_FRAME as usize {
            break;
        }
        if let DaemonMsg::Detail {
            recent,
            files,
            conns,
            maps,
            findings,
            ..
        } = &mut msg
        {
            let skip = recent.len() / 2 + 1;
            recent.drain(..skip.min(recent.len()));
            files.truncate(files.len() / 2);
            conns.truncate(conns.len() / 2);
            if let Some(m) = maps.as_mut() {
                m.truncate(m.len() / 2);
            }
            for f in findings.iter_mut() {
                f.evidence_events.truncate(1);
            }
        }
    }
    msg
}

fn kernel_release() -> String {
    rustix::system::uname()
        .release()
        .to_string_lossy()
        .into_owned()
}

/// Realtime minus boottime, so clients can show wall-clock times.
fn boot_to_wall_ns() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    now.saturating_sub(crate::sampler::boot_ns())
}

/// Where R100 keeps its baselines (only when R100 is enabled).
const BASELINES: &str = "/var/lib/sysscope/baselines.json";

/// Loads R100 baselines; a missing, unreadable or wrong-version file starts
/// empty (and says so).
fn load_baselines() -> sysscope_core::baseline::Baselines {
    match std::fs::read(BASELINES) {
        Ok(b) if b.len() <= 16 << 20 => {
            match sysscope_core::baseline::Baselines::from_json(&String::from_utf8_lossy(&b)) {
                Ok(bl) => bl,
                Err(e) => {
                    eprintln!("sysscoped: ignoring {BASELINES} ({e}); R100 starts learning again");
                    Default::default()
                }
            }
        }
        _ => Default::default(),
    }
}

/// Saves R100 baselines atomically (0600 root).
fn save_baselines(bl: &sysscope_core::baseline::Baselines) {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{BASELINES}.tmp");
    let _ = std::fs::create_dir_all("/var/lib/sysscope");
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(bl.to_json().as_bytes()))
        .and_then(|()| std::fs::rename(&tmp, BASELINES));
    if let Err(e) = ok {
        eprintln!("sysscoped: could not save {BASELINES}: {e}");
    }
}

fn sampler_loop(tx: Sender<Vec<ProcSample>>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        // Latest wins: if the core is behind, this scan is skipped.
        let _ = tx.try_send(crate::sampler::sample_all());
        let spent = started.elapsed();
        std::thread::sleep(Duration::from_secs(1).saturating_sub(spent));
    }
}

#[allow(clippy::too_many_arguments)]
fn core_loop(
    mut core: Core,
    events: Receiver<PollerMsg>,
    samples: Receiver<Vec<ProcSample>>,
    clients: Receiver<ClientCmd>,
    gh: Receiver<crate::glasshouse::GhEvent>,
    stop: Arc<AtomicBool>,
) {
    let mut next_snapshot = Instant::now() + Duration::from_millis(500);
    let mut next_tick = Instant::now() + Duration::from_secs(1);
    let mut next_baseline_save = Instant::now() + Duration::from_secs(600);
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= next_snapshot {
            next_snapshot += Duration::from_millis(500);
            core.snapshot();
        }
        if now >= next_tick {
            next_tick += Duration::from_secs(1);
            core.apply(Input::Tick {
                ts_ns: crate::sampler::boot_ns(),
            });
            if now >= next_baseline_save {
                next_baseline_save += Duration::from_secs(600);
                if let Some(bl) = &core.engine.baselines {
                    save_baselines(bl);
                }
            }
            let fx = core.gh.watchdog();
            core.gh_effects(&fx);
            for (owner, msg) in fx.replies {
                if let Some(c) = core.clients.get(&owner) {
                    c.queue.put_reply(msg);
                }
            }
            if let Some(w) = core.record.as_mut() {
                let _ = w.flush();
            }
        }
        let wait = next_snapshot
            .min(next_tick)
            .saturating_duration_since(Instant::now());
        select! {
            recv(events) -> m => match m {
                Ok(m) => core.on_poller(m),
                Err(_) => break,
            },
            recv(samples) -> s => if let Ok(samples) = s {
                let fresh = core.unchecked(&samples);
                core.apply(Input::Samples { ts_ns: crate::sampler::boot_ns(), samples });
                core.check_existing(fresh);
            },
            recv(clients) -> c => if let Ok(c) = c {
                core.on_client(c);
            },
            recv(gh) -> g => if let Ok(g) = g {
                core.on_gh(g);
            },
            default(wait) => {}
        }
    }
    for c in core.clients.values() {
        c.queue.close();
    }
    if let Some(bl) = &core.engine.baselines {
        save_baselines(bl);
    }
    if let Some(mut w) = core.record.take() {
        let _ = w.flush();
    }
}

/// Runs the daemon until SIGINT/SIGTERM.
pub fn run(opts: RunOpts, stop: Arc<AtomicBool>) -> Result<()> {
    let (cfg, rules, allow) = load_config(opts.rules_file.as_deref())?;
    let mut load = opts.load;
    load.syscalls = load.syscalls && cfg.syscalls == "count";
    let spec = if opts.dev {
        SocketSpec::dev()
    } else {
        SocketSpec::installed()?
    };

    let mut storage = MaybeUninit::uninit();
    let mut col = Collector::load(&mut storage, load)?;
    let listener = server::bind(&spec)?;

    let mut features = vec![
        "exec".to_string(),
        "files".into(),
        "network".into(),
        "listen".into(),
    ];
    if load.syscalls {
        features.push("syscalls".into());
    }
    if col.ptrace {
        features.push("ptrace".into());
    }
    // Glasshouse is offered only where a real sandbox start works (the
    // helper's probe; it never changes a system setting).
    if crate::glasshouse::available() {
        features.push("glasshouse".into());
    }
    let boot_to_wall = boot_to_wall_ns();
    let welcome = DaemonMsg::Welcome {
        proto: PROTO_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").into(),
        kernel: kernel_release(),
        boot_to_wall_ns: boot_to_wall,
        features: features.clone(),
        act_enabled: opts.enable_act,
    };
    let record = match &opts.record {
        Some(path) => {
            let f = std::fs::File::create(path)
                .with_context(|| format!("creating {}", path.display()))?;
            let mut w = std::io::BufWriter::new(f);
            writeln!(
                w,
                "{}",
                serde_json::json!({
                    "sysscope_record": 1, "proto": PROTO_VERSION,
                    "daemon_version": env!("CARGO_PKG_VERSION"), "kernel": kernel_release(),
                    "boot_to_wall_ns": boot_to_wall, "features": features, "act_enabled": opts.enable_act,
                })
            )?;
            Some(w)
        }
        None => None,
    };

    let (ev_tx, ev_rx) = crossbeam_channel::bounded::<PollerMsg>(65536);
    let (cmd_tx, cmd_rx) = crossbeam_channel::bounded::<PollerCmd>(16);
    let (smp_tx, smp_rx) = crossbeam_channel::bounded::<Vec<ProcSample>>(64);
    let (cli_tx, cli_rx) = crossbeam_channel::bounded::<ClientCmd>(1024);
    crate::glasshouse::sweep();
    let (gh, gh_rx) = crate::glasshouse::Glasshouse::new();
    let core = Core {
        gh,
        last_loss: sysscope_proto::Loss::default(),
        act_enabled: opts.enable_act,
        checked: std::collections::BTreeSet::new(),
        engine: {
            let mut e = Engine::new(rules, allow);
            if e.r100_enabled() {
                e.baselines = Some(load_baselines());
                eprintln!("sysscoped: R100 (experimental) enabled; baselines in {BASELINES}");
            }
            e
        },
        clients: BTreeMap::new(),
        homes: hostinfo::load_homes(),
        poller: cmd_tx,
        follow: None,
        follow_requester: None,
        welcome,
        record,
        seq: 0,
    };

    let s1 = Arc::clone(&stop);
    let sampler = std::thread::Builder::new()
        .name("sampler".into())
        .spawn(move || sampler_loop(smp_tx, s1))?;
    let s2 = Arc::clone(&stop);
    let core_thread = std::thread::Builder::new()
        .name("core".into())
        .spawn(move || core_loop(core, ev_rx, smp_rx, cli_rx, gh_rx, s2))?;
    let s3 = Arc::clone(&stop);
    let count = Arc::new(AtomicUsize::new(0));
    let acceptor = std::thread::Builder::new()
        .name("acceptor".into())
        .spawn(move || server::accept_loop(listener, cli_tx, count, s3))?;

    eprintln!(
        "sysscoped: serving {} (kernel {}, pid {})",
        spec.path.display(),
        kernel_release(),
        std::process::id()
    );
    let res = collector::run_poller(&mut col, &ev_tx, &cmd_rx, &stop);
    stop.store(true, Ordering::Relaxed);
    drop(ev_tx);
    let _ = acceptor.join();
    let _ = core_thread.join();
    let _ = sampler.join();
    server::remove_socket(&spec.path);
    eprintln!("sysscoped: stopped; BPF programs detached, socket removed");
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysscope_proto::{BStr, Event, EventKind, FileStat, Loss, ProcRow, Series, SystemMode};

    /// Review finding 2: 10240 rows with 512-byte non-UTF-8 names (about
    /// 4x when escaped) still produce a frame under 16 MiB.
    #[test]
    fn hostile_snapshot_still_fits_in_a_frame() {
        let row = |i: u32, exited: bool| ProcRow {
            key: ProcKey {
                tgid: i,
                start_ticks: 1,
            },
            exe: BStr(vec![0xff; 512]),
            comm: BStr(vec![0xfe; 64]),
            exited_ts: exited.then_some(1),
            ..ProcRow::default()
        };
        let mut procs: Vec<ProcRow> = (0..8192).map(|i| row(i, false)).collect();
        procs.extend((8192..10240).map(|i| row(i, true)));
        let msg = DaemonMsg::Snapshot {
            seq: 1,
            ts_ns: 1,
            mode: Mode::System(SystemMode::System),
            procs,
            loss: Loss::default(),
        };
        assert!(
            server::snapshot_frame(&msg).is_none(),
            "test must start over the limit"
        );
        let frame = fit_snapshot(msg).expect("reduced snapshot fits");
        assert!(frame.len() <= sysscope_proto::MAX_DAEMON_FRAME as usize + 4);
    }

    #[test]
    fn hostile_detail_is_shrunk_to_fit() {
        let ev = |i: u64| Event {
            id: i,
            ts_ns: i,
            proc: ProcKey::default(),
            tid: 1,
            uid: 0,
            kind: EventKind::Exec {
                exe: BStr(vec![0xff; 512]),
                argv: BStr(vec![0x01; 256]),
                argv_trunc: true,
                fileless: false,
                dev: 1,
                ino: 1,
            },
        };
        let files = (0..5000)
            .map(|i| FileStat {
                path: BStr(vec![0xff; 512]),
                dev: 1,
                ino: i,
                opens: 1,
                read: true,
                write: false,
                rbytes: 0,
                wbytes: 0,
                last_ts: i,
            })
            .collect();
        let msg = DaemonMsg::Detail {
            proc: ProcKey::default(),
            series: Series::default(),
            recent: (0..2000).map(ev).collect(),
            files,
            conns: vec![],
            syscalls: vec![],
            children: vec![],
            maps: None,
            findings: vec![],
        };
        let out = fit_detail(msg);
        let size = sysscope_proto::encode(&out).unwrap().len();
        assert!(size <= sysscope_proto::MAX_DAEMON_FRAME as usize, "{size}");
        if let DaemonMsg::Detail { files, .. } = out {
            assert!(!files.is_empty());
            assert_eq!(files[0].last_ts, 4999, "newest files kept");
        }
    }
}
