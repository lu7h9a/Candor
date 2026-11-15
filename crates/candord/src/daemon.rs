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
use candor_core::config::{Rules, load_allow};
use candor_core::{Engine, Input, ProcSample};
use candor_proto::{
    ClientMsg, DaemonMsg, EventKind, EventSub, EventSubMode, Mode, PROTO_VERSION, ProcKey, SysStat,
};
use crossbeam_channel::{Receiver, Sender, select};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// /etc/candor/candord.toml.
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
) -> Result<(DaemonConfig, Rules, Vec<candor_core::config::AllowEntry>)> {
    let cfg: DaemonConfig = match read_optional("/etc/candor/candord.toml")? {
        Some(t) => toml::from_str(&t).context("/etc/candor/candord.toml")?,
        None => DaemonConfig {
            syscalls: default_syscalls(),
        },
    };
    if cfg.syscalls != "count" && cfg.syscalls != "off" {
        bail!("/etc/candor/candord.toml: syscalls must be \"count\" or \"off\"");
    }
    // `--rules FILE` (dev mode only, tests) replaces /etc/candor/rules.toml.
    let override_text = match rules_file {
        Some(p) => {
            Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)
        }
        None => read_optional("/etc/candor/rules.toml")?,
    };
    let rules = Rules::load(override_text.as_deref())?;
    let allow = load_allow(&rules, read_optional("/etc/candor/allow.toml")?.as_deref())?;
    Ok((cfg, rules, allow))
}

/// Daemon options from the command line.
pub struct RunOpts {
    /// Collector options.
    pub load: LoadOpts,
    /// Dev mode (socket under /run/candor-dev).
    pub dev: bool,
    /// Record core inputs to this file.
    pub record: Option<std::path::PathBuf>,
    /// Experimental act mode (D19).
    pub enable_act: bool,
    /// Rules override file instead of /etc/candor/rules.toml (dev only).
    pub rules_file: Option<std::path::PathBuf>,
}

struct Client {
    queue: Arc<ClientQueue>,
    /// SO_PEERCRED of the connection (act mode authorisation).
    peer: crate::act::Requester,
    /// This client shows syscall statistics (WatchSyscalls).
    watch_sys: bool,
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
    /// Glasshouse commands for the poller not yet accepted by its channel.
    pending_poller: std::collections::VecDeque<PollerCmd>,
    /// Executable checks with a deadline (metapool.rs).
    meta: crate::metapool::MetaPool,
    /// Modification time of /etc/passwd when `homes` was read.
    homes_mtime: Option<std::time::SystemTime>,
    poller: Sender<PollerCmd>,
    follow: Option<ProcKey>,
    follow_requester: Option<u64>,
    welcome: DaemonMsg,
    record: Option<std::io::BufWriter<std::fs::File>>,
    seq: u64,
    gh: crate::glasshouse::Glasshouse,
    last_loss: candor_proto::Loss,
    act_enabled: bool,
    /// Processes already verified (exec or scan); see `unchecked`.
    checked: std::collections::BTreeSet<ProcKey>,
    /// What the poller was last told about WatchSyscalls.
    sys_wanted: bool,
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
                    // Off the core thread with a deadline (metapool.rs).
                    let f = if self.gh.in_box(&key) {
                        crate::metapool::Facts::default()
                    } else {
                        let script = candor_core::proc::script_of(&exe, &argv);
                        self.check_exe(key, exe.clone(), script)
                    };
                    let (trusted, system_dir, world_writable_dir) =
                        (f.trusted, f.system_dir, f.world_writable_dir);
                    // Inside the Glasshouse box "~" is the sandbox home.
                    let home = if self.gh.in_box(&key) {
                        b"/home/victim".to_vec()
                    } else {
                        self.homes.get(&uid).cloned().unwrap_or_default()
                    };
                    let script_trusted = f.script_trusted;
                    self.apply(Input::ExeMeta {
                        proc: key,
                        trusted,
                        system_dir,
                        home: candor_proto::BStr(home),
                        world_writable_dir,
                        script_trusted,
                        private_view: f.private_view,
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
                        watch_sys: false,
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
                self.sync_watch_sys();
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
                // Memory maps (ASLR layout) only of the requester's own
                // processes, unless root: the rule the kernel applies to
                // /proc/<pid>/maps (review 2 finding 2).
                let peer_uid = c.peer.uid;
                let maps = maps
                    && (peer_uid == 0
                        || self
                            .engine
                            .state
                            .get(&proc)
                            .is_some_and(|p| p.uid == peer_uid));
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
                // Follow limits detection for everyone: root or candor-act
                // only (owner's Q6 answer B).
                if let Err(why) = crate::act::authorised_for(c.peer, "follow mode") {
                    eprintln!(
                        "candord: follow pid {} refused for uid {} pid {}: {why}",
                        root.tgid, c.peer.uid, c.peer.pid
                    );
                    q.put_reply(DaemonMsg::Error {
                        code: "not_authorised".into(),
                        message: why,
                    });
                } else if !known {
                    q.put_reply(DaemonMsg::Error {
                        code: "unknown_process".into(),
                        message: format!("process {} is not running", root.tgid),
                    });
                } else if self.poller.try_send(PollerCmd::Follow(root)).is_ok() {
                    // Follow mode limits detection for everyone: logged
                    // with the requester (journal under systemd).
                    eprintln!(
                        "candord: follow pid {} requested by uid {} pid {}",
                        root.tgid, c.peer.uid, c.peer.pid
                    );
                    self.follow = Some(root);
                    self.follow_requester = Some(id);
                } else {
                    q.put_reply(DaemonMsg::Error {
                        code: "busy".into(),
                        message: "a follow request is already being handled".into(),
                    });
                }
            }
            ClientMsg::WatchSyscalls { on } => {
                c.watch_sys = on;
                self.sync_watch_sys();
            }
            ClientMsg::Unfollow {} => {
                if let Err(why) = crate::act::authorised_for(c.peer, "follow mode") {
                    q.put_reply(DaemonMsg::Error {
                        code: "not_authorised".into(),
                        message: why,
                    });
                } else if self.poller.try_send(PollerCmd::Unfollow).is_ok() {
                    eprintln!(
                        "candord: unfollow requested by uid {} pid {}",
                        c.peer.uid, c.peer.pid
                    );
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
                    Err("act mode is not enabled (candord --enable-act)".into())
                };
                // Every request is logged (journal under systemd).
                eprintln!(
                    "candord: act {action:?} pid {} requested by uid {} pid {} (nonce {}): {}",
                    proc.tgid,
                    peer.uid,
                    peer.pid,
                    candor_core::display::safe_str(&nonce),
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
        // These commands must not be lost (a lost GhBox would leave the box
        // waiting for Go), but a blocking send could deadlock with the
        // poller blocked on a full event channel (review 2 finding 8): they
        // wait in order in `pending_poller`, retried by the core loop. At
        // most two per run, one run at a time.
        self.pending_poller.extend(fx.poller.iter().cloned());
        self.flush_poller();
        if let Some(inodes) = &fx.decoys {
            self.apply(Input::Decoys {
                inodes: inodes.clone(),
            });
        }
    }

    /// Sends queued poller commands, in order, as far as the channel allows.
    fn flush_poller(&mut self) {
        while let Some(cmd) = self.pending_poller.pop_front() {
            if let Err(e) = self.poller.try_send(cmd) {
                if let crossbeam_channel::TrySendError::Full(cmd) = e {
                    self.pending_poller.push_front(cmd);
                }
                break;
            }
        }
    }

    /// Tells the poller whether any client wants syscall statistics (only
    /// when that changes; the poller command channel is small).
    fn sync_watch_sys(&mut self) {
        let want = self.clients.values().any(|c| c.hello && c.watch_sys);
        if want != self.sys_wanted && self.poller.try_send(PollerCmd::WantSyscalls(want)).is_ok() {
            self.sys_wanted = want;
        }
    }

    /// Processes in a scan that the daemon has not verified yet (they were
    /// running before it started, or it missed their exec). The set of
    /// checked keys is bounded by what the latest scan contains.
    fn unchecked(&mut self, samples: &[ProcSample]) -> Vec<(ProcKey, candor_proto::BStr, u32)> {
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

    /// Trust check of an executable (and script) with a deadline; a check
    /// that hangs is logged once per process and answered "not trusted".
    fn check_exe(
        &mut self,
        key: ProcKey,
        exe: candor_proto::BStr,
        script: Option<candor_proto::BStr>,
    ) -> crate::metapool::Facts {
        let before = self.meta.timed_out;
        let shown = candor_core::display::safe(&exe);
        let f = self
            .meta
            .check(key, exe, crate::follow::start_of(key.tgid), script);
        if self.meta.timed_out != before {
            eprintln!(
                "candord: checking the executable of pid {} ({shown}) did not finish in {} ms; it is treated as not trusted",
                key.tgid,
                crate::metapool::META_TIMEOUT.as_millis()
            );
        }
        f
    }

    /// The same verification an exec gets, for processes found by a scan.
    fn check_existing(&mut self, fresh: Vec<(ProcKey, candor_proto::BStr, u32)>) {
        for (key, exe, uid) in fresh {
            self.checked.insert(key);
            if self.gh.in_box(&key) {
                continue;
            }
            let f = self.check_exe(key, exe, None);
            let (trusted, system_dir, world_writable_dir) =
                (f.trusted, f.system_dir, f.world_writable_dir);
            let home = self.homes.get(&uid).cloned().unwrap_or_default();
            self.apply(Input::ExeMeta {
                proc: key,
                trusted,
                system_dir,
                home: candor_proto::BStr(home),
                world_writable_dir,
                script_trusted: false,
                private_view: f.private_view,
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
            let findings: Vec<candor_proto::Finding> = self
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
                        state: candor_proto::GhState::Finished,
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
        // Nobody to send it to: do not build or encode it (WP14 idle CPU).
        if !self.clients.values().any(|c| c.hello && c.snapshots) {
            return;
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
    eprintln!("candord: snapshot over the frame limit; leaving out exited processes");
    if let DaemonMsg::Snapshot { procs, .. } = &mut msg {
        procs.retain(|r| r.exited_ts.is_none());
    }
    if let Some(f) = server::snapshot_frame(&msg) {
        return Some(f);
    }
    eprintln!("candord: snapshot still too big; shortening executable names");
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
        candor_proto::encode(m)
            .map(|b| b.len())
            .unwrap_or(usize::MAX)
    };
    while size(&msg) > candor_proto::MAX_DAEMON_FRAME as usize {
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
                // Only notes are left: keep a few, and say so (review 2
                // finding 12: an oversize frame closed the client silently).
                if report.notes.len() > 10 {
                    report.notes.truncate(10);
                    report
                        .notes
                        .push("most notes were left out so the report fits one message".into());
                    continue;
                }
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
        let size = candor_proto::encode(&msg)
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
        if size <= candor_proto::MAX_DAEMON_FRAME as usize {
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
    too_large_or(msg)
}

/// The message, or an Error a client can show if it still does not fit one
/// frame (sending it would fail and close the connection without a word;
/// review 2 finding 12).
fn too_large_or(msg: DaemonMsg) -> DaemonMsg {
    let size = candor_proto::encode(&msg)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if size <= candor_proto::MAX_DAEMON_FRAME as usize {
        return msg;
    }
    DaemonMsg::Error {
        code: "too_large".into(),
        message: format!(
            "the answer does not fit one message ({size} bytes, limit {})",
            candor_proto::MAX_DAEMON_FRAME
        ),
    }
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
const BASELINES: &str = "/var/lib/candor/baselines.json";

/// Loads R100 baselines; a missing, unreadable or wrong-version file starts
/// empty (and says so).
fn load_baselines() -> candor_core::baseline::Baselines {
    match std::fs::read(BASELINES) {
        Ok(b) if b.len() <= 16 << 20 => {
            match candor_core::baseline::Baselines::from_json(&String::from_utf8_lossy(&b)) {
                Ok(bl) => bl,
                Err(e) => {
                    eprintln!("candord: ignoring {BASELINES} ({e}); R100 starts learning again");
                    Default::default()
                }
            }
        }
        _ => Default::default(),
    }
}

/// Saves R100 baselines atomically (0600 root).
fn save_baselines(bl: &candor_core::baseline::Baselines) {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{BASELINES}.tmp");
    let _ = std::fs::create_dir_all("/var/lib/candor");
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(bl.to_json().as_bytes()))
        .and_then(|()| std::fs::rename(&tmp, BASELINES));
    if let Err(e) = ok {
        eprintln!("candord: could not save {BASELINES}: {e}");
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

/// sd_notify("READY=1") on $NOTIFY_SOCKET, if set (path or abstract name).
fn notify_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return;
    };
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
    let sent = match bytes.strip_prefix(b"@") {
        Some(name) => <std::os::unix::net::SocketAddr as std::os::linux::net::SocketAddrExt>::from_abstract_name(name)
            .and_then(|a| sock.send_to_addr(b"READY=1", &a)),
        None => sock.send_to(b"READY=1", std::path::Path::new(&path)),
    };
    if let Err(e) = sent {
        eprintln!("candord: telling systemd we are ready failed: {e}");
    }
}

/// The next deadline of a periodic job that was due at `due`: one period
/// later, or one period from `now` if that is already past.
fn next_period(due: Instant, now: Instant, period: Duration) -> Instant {
    let next = due + period;
    if next <= now { now + period } else { next }
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
        // Periods missed during a stall are skipped, not caught up one per
        // loop: catching up would build a burst of snapshots exactly when
        // the core is already behind (review F8).
        if now >= next_snapshot {
            next_snapshot = next_period(next_snapshot, now, Duration::from_millis(500));
            core.snapshot();
        }
        if now >= next_tick {
            next_tick = next_period(next_tick, now, Duration::from_secs(1));
            core.apply(Input::Tick {
                ts_ns: crate::sampler::boot_ns(),
            });
            // Users added or changed after start get their real home
            // (review F16); one stat per second.
            let m = hostinfo::passwd_mtime();
            if m != core.homes_mtime {
                core.homes = hostinfo::load_homes();
                core.homes_mtime = m;
            }
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
        core.flush_poller();
        let mut wait = next_snapshot
            .min(next_tick)
            .saturating_duration_since(Instant::now());
        if !core.pending_poller.is_empty() {
            wait = wait.min(Duration::from_millis(10));
        }
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
    // Optional features: offered, or listed with the reason (plan WP31).
    let mut unavailable = Vec::new();
    let note = |feature: &str, kernel: bool, reason: String| candor_proto::FeatureNote {
        feature: feature.into(),
        kernel,
        reason,
    };
    if load.syscalls {
        features.push("syscalls".into());
    } else {
        unavailable.push(note(
            "syscalls",
            false,
            "per-process syscall counts are switched off (syscalls = \"off\" in /etc/candor/candord.toml, or --syscalls off)".into(),
        ));
    }
    if col.ptrace {
        features.push("ptrace".into());
    } else {
        unavailable.push(note(
            "ptrace",
            true,
            "the kernel has no security_ptrace_access_check in its BTF, so attempts to inject into another process (R011) cannot be seen".into(),
        ));
    }
    // Glasshouse is offered only where a real sandbox start works (the
    // helper's probe; it never changes a system setting).
    match crate::glasshouse::available() {
        Ok(()) => features.push("glasshouse".into()),
        Err(why) => {
            eprintln!("candord: Glasshouse not available: {why}");
            unavailable.push(note("glasshouse", false, why));
        }
    }
    let boot_to_wall = boot_to_wall_ns();
    let welcome = DaemonMsg::Welcome {
        proto: PROTO_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").into(),
        kernel: kernel_release(),
        boot_to_wall_ns: boot_to_wall,
        features: features.clone(),
        unavailable,
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
                    "candor_record": 1, "proto": PROTO_VERSION,
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
        last_loss: candor_proto::Loss::default(),
        act_enabled: opts.enable_act,
        checked: std::collections::BTreeSet::new(),
        sys_wanted: false,
        engine: {
            let mut e = Engine::new(rules, allow);
            if e.r100_enabled() {
                e.baselines = Some(load_baselines());
                eprintln!("candord: R100 (experimental) enabled; baselines in {BASELINES}");
            }
            e
        },
        clients: BTreeMap::new(),
        homes: hostinfo::load_homes(),
        meta: crate::metapool::MetaPool::new(crate::metapool::host_check),
        pending_poller: std::collections::VecDeque::new(),
        homes_mtime: hostinfo::passwd_mtime(),
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
        "candord: serving {} (kernel {}, pid {})",
        spec.path.display(),
        kernel_release(),
        std::process::id()
    );
    // Tell systemd (Type=notify) that the socket is ready, so `systemctl
    // start` returns only when clients can connect (found by the README test
    // in a clean VM, WP33). No-op when not started by systemd.
    notify_ready();
    let res = collector::run_poller(&mut col, &ev_tx, &cmd_rx, &stop);
    stop.store(true, Ordering::Relaxed);
    drop(ev_tx);
    let _ = acceptor.join();
    let _ = core_thread.join();
    let _ = sampler.join();
    server::remove_socket(&spec.path);
    eprintln!("candord: stopped; BPF programs detached, socket removed");
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use candor_proto::{BStr, Event, EventKind, FileStat, Loss, ProcRow, Series, SystemMode};

    /// Review F8: after a 10 s stall the next snapshot is one period away,
    /// not 20 overdue snapshots in a row.
    #[test]
    fn missed_periods_are_skipped() {
        let p = Duration::from_millis(500);
        let t0 = Instant::now();
        assert_eq!(next_period(t0, t0 + Duration::from_millis(10), p), t0 + p);
        let late = t0 + Duration::from_secs(10);
        assert_eq!(next_period(t0, late, p), late + p);
    }

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
        assert!(frame.len() <= candor_proto::MAX_DAEMON_FRAME as usize + 4);
    }

    #[test]
    fn a_detail_that_cannot_shrink_becomes_a_clear_error() {
        // The series is not shrunk; 3 x 1M numbers do not fit 16 MiB.
        let n = 1_000_000;
        let msg = DaemonMsg::Detail {
            proc: ProcKey::default(),
            series: Series {
                t: (0..n).map(|i| u64::MAX - i).collect(),
                cpu: vec![123.456; n as usize],
                rss: vec![u64::MAX; n as usize],
            },
            recent: vec![],
            files: vec![],
            conns: vec![],
            syscalls: vec![],
            children: vec![],
            maps: None,
            findings: vec![],
        };
        match fit_detail(msg) {
            DaemonMsg::Error { code, .. } => assert_eq!(code, "too_large"),
            other => panic!("not an error: {:?}", std::mem::discriminant(&other)),
        }
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
        let size = candor_proto::encode(&out).unwrap().len();
        assert!(size <= candor_proto::MAX_DAEMON_FRAME as usize, "{size}");
        if let DaemonMsg::Detail { files, .. } = out {
            assert!(!files.is_empty());
            assert_eq!(files[0].last_ts, 4999, "newest files kept");
        }
    }
}
