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
pub fn load_config() -> Result<(DaemonConfig, Rules, Vec<sysscope_core::config::AllowEntry>)> {
    let cfg: DaemonConfig = match read_optional("/etc/sysscope/sysscoped.toml")? {
        Some(t) => toml::from_str(&t).context("/etc/sysscope/sysscoped.toml")?,
        None => DaemonConfig {
            syscalls: default_syscalls(),
        },
    };
    if cfg.syscalls != "count" && cfg.syscalls != "off" {
        bail!("/etc/sysscope/sysscoped.toml: syscalls must be \"count\" or \"off\"");
    }
    let rules = Rules::load(read_optional("/etc/sysscope/rules.toml")?.as_deref())?;
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
}

struct Client {
    queue: Arc<ClientQueue>,
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
            PollerMsg::Event(ev) => {
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
                    EventKind::Exec { exe, .. } => Some(exe.clone()),
                    _ => None,
                };
                let (key, uid) = (ev.proc, ev.uid);
                self.apply(Input::RawEvent { event: ev });
                if let Some(exe) = exec {
                    let (trusted, system_dir, world_writable_dir) = hostinfo::exe_facts(key, &exe);
                    let home = self.homes.get(&uid).cloned().unwrap_or_default();
                    self.apply(Input::ExeMeta {
                        proc: key,
                        trusted,
                        system_dir,
                        home: sysscope_proto::BStr(home),
                        world_writable_dir,
                    });
                }
            }
            PollerMsg::Loss(loss) => self.apply(Input::Loss { loss }),
            PollerMsg::Drops { ts_ns, per_proc } => {
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
            ClientCmd::New { id, queue, uid } => {
                let _ = uid;
                self.clients.insert(
                    id,
                    Client {
                        queue,
                        hello: false,
                        snapshots: false,
                        alerts: false,
                        events: EventSub::Simple(EventSubMode::None),
                    },
                );
            }
            ClientCmd::Gone { id } => {
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
                q.put_reply(reply);
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
            ClientMsg::Act { .. } => q.put_reply(DaemonMsg::ActResult {
                ok: false,
                message: "act mode is not enabled (sysscoped --enable-act)".into(),
            }),
            ClientMsg::GhUploadBegin { .. }
            | ClientMsg::GhUploadChunk { .. }
            | ClientMsg::GhRun { .. }
            | ClientMsg::GhCancel {} => q.put_reply(DaemonMsg::Error {
                code: "unavailable".into(),
                message: "Glasshouse is not available in this build".into(),
            }),
        }
    }

    fn snapshot(&mut self) {
        self.seq += 1;
        let mut msg = self.engine.snapshot(self.seq);
        if let DaemonMsg::Snapshot { mode, procs, .. } = &mut msg
            && let Some(root) = self.follow
        {
            *mode = Mode::Follow { follow: root };
            let mut tree = std::collections::BTreeSet::from([root]);
            // Parents come before children in creation order, not key order:
            // repeat until nothing is added (bounded by the table size).
            for _ in 0..procs.len() {
                let before = tree.len();
                for r in procs.iter() {
                    if r.parent.is_some_and(|p| tree.contains(&p)) {
                        tree.insert(r.key);
                    }
                }
                if tree.len() == before {
                    break;
                }
            }
            for r in procs.iter_mut() {
                r.followed = tree.contains(&r.key);
            }
        }
        let Some(frame) = server::snapshot_frame(&msg) else {
            return;
        };
        for c in self.clients.values().filter(|c| c.hello && c.snapshots) {
            c.queue.put_snapshot(Arc::clone(&frame));
        }
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
    stop: Arc<AtomicBool>,
) {
    let mut next_snapshot = Instant::now() + Duration::from_millis(500);
    let mut next_tick = Instant::now() + Duration::from_secs(1);
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
                core.apply(Input::Samples { ts_ns: crate::sampler::boot_ns(), samples });
            },
            recv(clients) -> c => if let Ok(c) = c {
                core.on_client(c);
            },
            default(wait) => {}
        }
    }
    for c in core.clients.values() {
        c.queue.close();
    }
    if let Some(mut w) = core.record.take() {
        let _ = w.flush();
    }
}

/// Runs the daemon until SIGINT/SIGTERM.
pub fn run(opts: RunOpts, stop: Arc<AtomicBool>) -> Result<()> {
    let (cfg, rules, allow) = load_config()?;
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
    let boot_to_wall = boot_to_wall_ns();
    let welcome = DaemonMsg::Welcome {
        proto: PROTO_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").into(),
        kernel: kernel_release(),
        boot_to_wall_ns: boot_to_wall,
        features: features.clone(),
        act_enabled: false,
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
                    "boot_to_wall_ns": boot_to_wall, "features": features, "act_enabled": false,
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
    let core = Core {
        engine: Engine::new(rules, allow),
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
        .spawn(move || core_loop(core, ev_rx, smp_rx, cli_rx, s2))?;
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
