//! Glasshouse in the daemon (plan 6.1): sample upload, the root helper,
//! attribution of the box's events, live decoy states and the report.
//!
//! The client uploads bytes (D25: the daemon never opens a client path);
//! they are streamed to `RUNS/<run_id>.sample` (0600 root), never held in
//! memory. The helper (`candor-glasshouse run <run_id>`) runs as its own
//! transient unit through `systemd-run --wait --pipe`, so the daemon keeps
//! no extra privileges for it; its stdout is parsed line by line with the
//! same length cap and strictness as client frames.
//!
//! Attribution: the helper reports the box unit's main pid; every process
//! forked from it (Fork events, in kernel order) belongs to the box. The
//! box cgroup is also put into `followed_cgroup`, so a run is traced even
//! while the user follows something else.

use candor_proto::helper::{GhJob, HelperIn, HelperOut, MAX_HELPER_LINE};
use candor_proto::{
    BStr, ConnStat, DaemonMsg, DecoyState, DecoyStatus, Event, EventKind, Finding, GhReport,
    GhState, Loss, ProcKey,
};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Where uploads and run directories live.
pub const RUNS: &str = "/var/lib/candor/glasshouse";
/// Where reports are kept (0640 root:candor).
pub const REPORTS: &str = "/var/lib/candor/reports";
/// Largest sample.
pub const MAX_SAMPLE: u64 = 256 * 1024 * 1024;
/// Largest decoded chunk.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Events kept in a report's timeline.
pub const TIMELINE_CAP: usize = 20_000;
/// Box processes tracked per run (a fork chain cannot grow this forever).
pub const MAX_BOX_PROCS: usize = 10_000;
/// Processes listed in a report.
pub const MAX_CHILDREN_LISTED: usize = 1_000;
/// Reports kept in REPORTS (oldest removed first).
pub const MAX_REPORTS: usize = 200;
/// An upload with no progress for this long is dropped (frees the slot).
const UPLOAD_IDLE: Duration = Duration::from_secs(60);
/// Slowest accepted upload rate: a client that trickles one chunk a minute
/// cannot hold the only run slot for hours (review 2 finding 7).
const UPLOAD_MIN_BYTES_PER_S: u64 = 64 * 1024;

/// Longest a whole upload of `size` bytes may take.
fn upload_deadline(size: u64) -> Duration {
    UPLOAD_IDLE + Duration::from_secs(size / UPLOAD_MIN_BYTES_PER_S)
}
/// A started run may take timeout + this long before the daemon gives up
/// on the helper (kills its unit and frees the slot).
const RUN_GRACE: Duration = Duration::from_secs(300);
/// Live decoy updates at most this often.
const LIVE_EVERY: Duration = Duration::from_millis(300);

/// What a helper thread tells the core.
#[derive(Debug)]
pub enum GhEvent {
    /// One parsed helper line.
    Line {
        /// Run it belongs to.
        run_id: String,
        /// The message.
        out: HelperOut,
    },
    /// The helper ended (stdout closed).
    Exited {
        /// Run it belongs to.
        run_id: String,
        /// Last lines of its stderr (escaped later).
        stderr: String,
    },
}

/// What the core must do after a Glasshouse step.
#[derive(Debug, Default)]
pub struct Effects {
    /// Replies for clients (id, message).
    pub replies: Vec<(u64, DaemonMsg)>,
    /// Commands for the poller.
    pub poller: Vec<crate::collector::PollerCmd>,
    /// New decoy set for the engine (Some = replace).
    pub decoys: Option<Vec<(u64, u64)>>,
    /// A report to build (the core has the findings and loss).
    pub finish: bool,
}

struct Upload {
    file: std::fs::File,
    began: Instant,
    size: u64,
    got: u64,
    next_seq: u32,
}

enum Stage {
    Uploading(Upload),
    Uploaded,
    Started { to_helper: Sender<HelperIn> },
}

/// One run.
pub struct Run {
    owner: u64,
    /// Run id ([0-9-]).
    pub run_id: String,
    stage: Stage,
    name: String,
    args: Vec<BStr>,
    timeout_s: u32,
    started_ts: u64,
    root: Option<ProcKey>,
    box_procs: BTreeSet<ProcKey>,
    cgroup: u64,
    majmin: (u32, u32),
    decoys: Vec<DecoyStatus>,
    by_inode: BTreeMap<(u64, u64), usize>,
    read_seen: BTreeSet<(u64, u64)>,
    timeline: Vec<Event>,
    timeline_dropped: u64,
    loss_start: Loss,
    live_dirty: bool,
    last_live: Instant,
    diff: Option<HelperOut>,
    failed: Option<String>,
    /// Last client progress (upload) or the start of the run.
    last_activity: Instant,
    /// Between Go and the helper's Ended: events of the sandbox user are
    /// the box's even if their Fork event was lost.
    sample_running: bool,
    /// Box processes adopted that way.
    adopted: u64,
    /// Box processes not tracked because of MAX_BOX_PROCS.
    procs_overflow: u64,
    /// Events of box processes dropped by the kernel budget.
    box_drops: u64,
}

/// The daemon's Glasshouse state (owned by the core thread).
pub struct Glasshouse {
    /// The current run, if any.
    pub run: Option<Run>,
    tx: Sender<GhEvent>,
    counter: u64,
    helper: PathBuf,
    box_uid: Option<u32>,
}

/// Adds a process to the box set unless the cap is reached.
fn track(run: &mut Run, k: ProcKey) -> bool {
    if run.box_procs.len() >= MAX_BOX_PROCS && !run.box_procs.contains(&k) {
        run.procs_overflow += 1;
        return false;
    }
    run.box_procs.insert(k);
    true
}

/// True unless /proc says the process is in another cgroup (a process
/// that is already gone cannot be checked and is accepted on its uid).
fn in_unit(pid: u32, unit: &str) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(t) => t.lines().any(|l| l.ends_with(&format!("/{unit}"))),
        Err(_) => true,
    }
}

/// uid of a user from /etc/passwd.
fn user_id(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(name)).then(|| f.nth(1).and_then(|u| u.parse().ok()))?
    })
}

/// Turns a client-supplied name into a safe file name inside the box.
pub fn sanitize_name(name: &[u8]) -> String {
    let base = name.rsplit(|&b| b == b'/').next().unwrap_or(&[]);
    let mut s: String = base
        .iter()
        .take(64)
        .map(|&c| {
            if c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-') {
                char::from(c)
            } else {
                '_'
            }
        })
        .collect();
    while s.starts_with('.') {
        s.remove(0);
    }
    if s.is_empty() { "sample".into() } else { s }
}

fn err(code: &str, message: impl Into<String>) -> DaemonMsg {
    DaemonMsg::Error {
        code: code.into(),
        message: message.into(),
    }
}

fn status(state: GhState, run_id: &str, message: impl Into<String>) -> DaemonMsg {
    DaemonMsg::GhStatus {
        state,
        run_id: run_id.into(),
        message: message.into(),
        decoys: Vec::new(),
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn upload_path(run_id: &str) -> PathBuf {
    PathBuf::from(RUNS).join(format!("{run_id}.sample"))
}

fn job_path(run_id: &str) -> PathBuf {
    PathBuf::from(RUNS).join(format!("{run_id}.job.json"))
}

/// Starts the helper unit and its reader/writer threads.
fn spawn_helper(
    helper: &std::path::Path,
    run_id: &str,
    timeout_s: u32,
    tx: Sender<GhEvent>,
) -> std::io::Result<Sender<HelperIn>> {
    let mut child = Command::new("/usr/bin/systemd-run")
        .args([
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
            "--service-type=exec",
            // The helper (and the differ it starts) is bounded too.
            "-p",
            "MemoryMax=1G",
        ])
        .arg("-p")
        .arg(format!(
            "RuntimeMaxSec={}",
            u64::from(timeout_s) + RUN_GRACE.as_secs()
        ))
        .arg(format!("--unit=candor-ghh-{run_id}"))
        .arg(helper)
        .arg("run")
        .arg(run_id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (in_tx, in_rx) = bounded::<HelperIn>(16);
    if let Some(mut stdin) = child.stdin.take() {
        std::thread::spawn(move || {
            for m in in_rx {
                let Ok(line) = serde_json::to_string(&m) else {
                    continue;
                };
                if writeln!(stdin, "{line}")
                    .and_then(|()| stdin.flush())
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    let stderr_tail = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    if let Some(mut se) = child.stderr.take() {
        let tail = std::sync::Arc::clone(&stderr_tail);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = std::io::Read::read(&mut se, &mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut t) = tail.lock() {
                    t.extend_from_slice(buf.get(..n).unwrap_or(&[]));
                    let excess = t.len().saturating_sub(4096);
                    t.drain(..excess);
                }
            }
        });
    }
    let stdout = child.stdout.take();
    let id = run_id.to_string();
    std::thread::spawn(move || {
        if let Some(so) = stdout {
            let mut r = std::io::BufReader::new(so);
            loop {
                match candor_proto::read_line_bounded(&mut r, MAX_HELPER_LINE) {
                    Ok(Some(candor_proto::Line::Text(l))) => {
                        match serde_json::from_slice::<HelperOut>(&l) {
                            Ok(out) => {
                                if tx
                                    .send(GhEvent::Line {
                                        run_id: id.clone(),
                                        out,
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(e) => eprintln!(
                                "candord: ignoring a malformed Glasshouse helper line: {}",
                                candor_core::display::safe_str(&e.to_string())
                            ),
                        }
                    }
                    Ok(Some(candor_proto::Line::TooLong)) => {
                        eprintln!("candord: ignoring an over-long Glasshouse helper line");
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
        let _ = child.wait();
        // The stderr reader may still be draining; give it a moment.
        std::thread::sleep(Duration::from_millis(100));
        let stderr = stderr_tail
            .lock()
            .map(|t| String::from_utf8_lossy(&t).into_owned())
            .unwrap_or_default();
        let _ = tx.send(GhEvent::Exited { run_id: id, stderr });
    });
    Ok(in_tx)
}

impl Glasshouse {
    /// Creates the manager; helper events arrive on the returned receiver.
    pub fn new() -> (Glasshouse, Receiver<GhEvent>) {
        let (tx, rx) = bounded(256);
        let helper = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("candor-glasshouse")))
            .unwrap_or_else(|| PathBuf::from("/usr/libexec/candor/candor-glasshouse"));
        (
            Glasshouse {
                run: None,
                tx,
                counter: 0,
                helper,
                box_uid: user_id("candor-box"),
            },
            rx,
        )
    }

    fn owned_by(&self, id: u64) -> Option<&Run> {
        self.run.as_ref().filter(|r| r.owner == id)
    }

    /// GhUploadBegin.
    pub fn begin(&mut self, id: u64, name: &BStr, size: u64) -> Vec<DaemonMsg> {
        if let Some(r) = &self.run {
            return vec![err(
                "busy",
                format!("a Glasshouse run ({}) is already in progress", r.run_id),
            )];
        }
        if size == 0 || size > MAX_SAMPLE {
            return vec![err("bad_request", "the sample must be 1 byte to 256 MiB")];
        }
        self.counter += 1;
        let run_id = format!("{}-{}", unix_secs(), self.counter);
        if let Err(e) = runs_dir() {
            return vec![err("glasshouse_failed", format!("creating {RUNS}: {e}"))];
        }
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(upload_path(&run_id))
        {
            Ok(f) => f,
            Err(e) => return vec![err("glasshouse_failed", format!("storing the sample: {e}"))],
        };
        self.run = Some(Run {
            owner: id,
            run_id: run_id.clone(),
            stage: Stage::Uploading(Upload {
                file,
                began: Instant::now(),
                size,
                got: 0,
                next_seq: 0,
            }),
            name: sanitize_name(name.as_bytes()),
            args: Vec::new(),
            timeout_s: 60,
            started_ts: 0,
            root: None,
            box_procs: BTreeSet::new(),
            cgroup: 0,
            majmin: (0, 0),
            decoys: Vec::new(),
            by_inode: BTreeMap::new(),
            read_seen: BTreeSet::new(),
            timeline: Vec::new(),
            timeline_dropped: 0,
            loss_start: Loss::default(),
            live_dirty: false,
            last_live: Instant::now(),
            diff: None,
            failed: None,
            last_activity: Instant::now(),
            sample_running: false,
            adopted: 0,
            procs_overflow: 0,
            box_drops: 0,
        });
        vec![status(
            GhState::Uploading,
            &run_id,
            format!("receiving {size} bytes"),
        )]
    }

    /// GhUploadChunk.
    pub fn chunk(&mut self, id: u64, seq: u32, b64: &str) -> Vec<DaemonMsg> {
        let Some(run) = self.run.as_mut().filter(|r| r.owner == id) else {
            return vec![err("bad_request", "no upload in progress for this client")];
        };
        let Stage::Uploading(up) = &mut run.stage else {
            return vec![err("bad_request", "the upload is already complete")];
        };
        if seq != up.next_seq {
            let msg = format!("chunk {seq} out of order (expected {})", up.next_seq);
            self.abort_upload();
            return vec![err("bad_request", msg)];
        }
        let Some(data) = candor_proto::b64::decode(b64).filter(|d| d.len() <= MAX_CHUNK) else {
            self.abort_upload();
            return vec![err(
                "bad_request",
                "a chunk is not valid base64 of at most 64 KiB",
            )];
        };
        if up.got + data.len() as u64 > up.size {
            self.abort_upload();
            return vec![err("bad_request", "more bytes than announced")];
        }
        if let Err(e) = up.file.write_all(&data) {
            self.abort_upload();
            return vec![err("glasshouse_failed", format!("storing the sample: {e}"))];
        }
        up.got += data.len() as u64;
        up.next_seq += 1;
        run.last_activity = Instant::now();
        if up.got == up.size {
            run.stage = Stage::Uploaded;
            return vec![status(GhState::Uploading, &run.run_id, "sample received")];
        }
        Vec::new()
    }

    fn abort_upload(&mut self) {
        if let Some(r) = self.run.take() {
            let _ = std::fs::remove_file(upload_path(&r.run_id));
            let _ = std::fs::remove_file(job_path(&r.run_id));
        }
    }

    /// GhRun: writes the job file and starts the helper.
    pub fn start(&mut self, id: u64, args: &[BStr], timeout_s: u32, loss: Loss) -> Vec<DaemonMsg> {
        let helper = self.helper.clone();
        let tx = self.tx.clone();
        let Some(run) = self.run.as_mut().filter(|r| r.owner == id) else {
            return vec![err("bad_request", "upload a sample first")];
        };
        if !matches!(run.stage, Stage::Uploaded) {
            return vec![err(
                "bad_request",
                "the sample is not completely uploaded, or the run already started",
            )];
        }
        if !(1..=600).contains(&timeout_s) {
            return vec![err("bad_request", "timeout must be 1 to 600 seconds")];
        }
        if args.len() > 256 || args.iter().any(|a| a.as_bytes().len() > 4096) {
            return vec![err(
                "bad_request",
                "at most 256 arguments of at most 4096 bytes",
            )];
        }
        run.args = args.to_vec();
        run.timeout_s = timeout_s;
        run.loss_start = loss;
        let job = GhJob {
            name: run.name.clone(),
            args: run.args.clone(),
            timeout_s,
            calibrate: false,
        };
        let written = serde_json::to_vec(&job)
            .map_err(std::io::Error::other)
            .and_then(|body| {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(job_path(&run.run_id))?;
                f.write_all(&body)
            });
        let run_id = run.run_id.clone();
        if let Err(e) = written {
            self.abort_upload();
            return vec![err("glasshouse_failed", format!("writing the job: {e}"))];
        }
        match spawn_helper(&helper, &run_id, timeout_s, tx) {
            Ok(to_helper) => {
                run.stage = Stage::Started { to_helper };
                run.last_activity = Instant::now();
                vec![status(GhState::Starting, &run_id, "starting the sandbox")]
            }
            Err(e) => {
                self.abort_upload();
                vec![err(
                    "glasshouse_failed",
                    format!("starting the helper: {e}"),
                )]
            }
        }
    }

    /// GhCancel, or the owner disconnected.
    pub fn cancel(&mut self, id: u64) -> Vec<DaemonMsg> {
        let Some(run) = self.owned_by(id) else {
            return vec![err("bad_request", "no Glasshouse run for this client")];
        };
        match &run.stage {
            Stage::Started { to_helper } => {
                let _ = to_helper.try_send(HelperIn::Cancel {});
                vec![status(GhState::Running, &run.run_id.clone(), "cancelling")]
            }
            _ => {
                let rid = run.run_id.clone();
                self.abort_upload();
                vec![status(
                    GhState::Failed,
                    &rid,
                    "cancelled before the run started",
                )]
            }
        }
    }

    /// The owner went away: a run nobody watches is stopped.
    pub fn client_gone(&mut self, id: u64) {
        if self.owned_by(id).is_some() {
            let _ = self.cancel(id);
        }
    }

    /// Is this process part of the current box?
    pub fn in_box(&self, key: &ProcKey) -> bool {
        self.run.as_ref().is_some_and(|r| r.box_procs.contains(key))
    }

    /// Looks at one event before the engine does: attribution, timeline,
    /// live decoy states.
    pub fn observe(&mut self, ev: &Event) {
        let box_uid = self.box_uid;
        let Some(run) = self.run.as_mut() else { return };
        if run.root.is_none() {
            return;
        }
        if !run.box_procs.contains(&ev.proc) {
            // A box process whose Fork event the kernel dropped (budget or
            // full ring buffer): while the sample runs, only box processes
            // run as the sandbox user; the cgroup confirms it when the
            // process still exists.
            let adopt = run.sample_running
                && box_uid == Some(ev.uid)
                && in_unit(ev.proc.tgid, &format!("candor-gh-{}.service", run.run_id));
            if !adopt || !track(run, ev.proc) {
                return;
            }
            run.adopted += 1;
        }
        if let EventKind::Fork { child } = &ev.kind {
            track(run, *child);
        }
        let touched = match &ev.kind {
            EventKind::Open {
                dev,
                ino,
                read,
                write,
                ..
            } => {
                let _ = read;
                Some((
                    (*dev, *ino),
                    if *write {
                        DecoyState::Modified
                    } else {
                        DecoyState::Read
                    },
                ))
            }
            EventKind::Rename { dev, ino, .. } => Some(((*dev, *ino), DecoyState::Renamed)),
            EventKind::Unlink { dev, ino, .. } => Some(((*dev, *ino), DecoyState::Deleted)),
            _ => None,
        };
        if let Some((k, state)) = touched
            && let Some(&i) = run.by_inode.get(&k)
        {
            if state == DecoyState::Read {
                run.read_seen.insert(k);
            }
            if let Some(d) = run.decoys.get_mut(i)
                && !d.states.contains(&state)
            {
                d.states.retain(|s| *s != DecoyState::Untouched);
                d.states.push(state);
                run.live_dirty = true;
            }
        }
        if run.timeline.len() < TIMELINE_CAP {
            run.timeline.push(ev.clone());
        } else {
            run.timeline_dropped += 1;
        }
    }

    /// Periodic live update for the owner (decoy tiles).
    pub fn live(&mut self) -> Option<(u64, DaemonMsg)> {
        let run = self.run.as_mut()?;
        if !run.live_dirty || run.last_live.elapsed() < LIVE_EVERY {
            return None;
        }
        run.live_dirty = false;
        run.last_live = Instant::now();
        Some((
            run.owner,
            DaemonMsg::GhStatus {
                state: GhState::Running,
                run_id: run.run_id.clone(),
                message: String::new(),
                decoys: run.decoys.clone(),
            },
        ))
    }

    /// One message from a helper thread.
    pub fn on_helper(&mut self, ev: GhEvent, now_ts: u64) -> Effects {
        let mut fx = Effects::default();
        let (rid, out) = match ev {
            GhEvent::Line { run_id, out } => (run_id, Some(out)),
            GhEvent::Exited { run_id, stderr } => {
                let Some(run) = self.run.as_mut().filter(|r| r.run_id == run_id) else {
                    return fx;
                };
                if run.diff.is_none() && run.failed.is_none() {
                    let tail: String = stderr.lines().rev().take(3).collect::<Vec<_>>().join(" / ");
                    run.failed = Some(format!(
                        "the Glasshouse helper ended unexpectedly: {}",
                        candor_core::display::safe_str(&tail)
                    ));
                }
                return self.close(fx);
            }
        };
        let Some(run) = self.run.as_mut().filter(|r| r.run_id == rid) else {
            return fx;
        };
        let to_helper = match &run.stage {
            Stage::Started { to_helper } => to_helper.clone(),
            _ => return fx,
        };
        match out {
            Some(HelperOut::Status { state, message }) => {
                fx.replies
                    .push((run.owner, status(state, &run.run_id, message)));
            }
            Some(HelperOut::Need {
                cgroup_id,
                pid,
                run_dev,
                run_dir,
                decoys,
            }) => {
                // The root must be a live process right now (start time read
                // from /proc, so a recycled pid cannot be adopted later).
                match crate::follow::start_of(pid) {
                    Some(start_ticks) => {
                        let root = ProcKey {
                            tgid: pid,
                            start_ticks,
                        };
                        run.root = Some(root);
                        run.box_procs.insert(root);
                        run.cgroup = cgroup_id;
                        run.majmin = crate::mounts::user_dev_majmin(run_dev);
                        run.by_inode = decoys
                            .iter()
                            .enumerate()
                            .map(|(i, d)| ((d.dev, d.ino), i))
                            .collect();
                        fx.decoys = Some(run.by_inode.keys().copied().collect());
                        run.decoys = decoys;
                        run.started_ts = now_ts;
                        run.live_dirty = true;
                        fx.poller.push(crate::collector::PollerCmd::GhBox {
                            cgroup: cgroup_id,
                            majmin: run.majmin,
                            run_dir: run_dir.into_bytes(),
                        });
                        // Go is sent when the poller confirms (GhReady).
                    }
                    None => {
                        let _ = to_helper.try_send(HelperIn::Refuse {
                            message: format!("box process {pid} is not running"),
                        });
                    }
                }
            }
            Some(HelperOut::Ended {}) => run.sample_running = false,
            Some(HelperOut::Diff { .. }) => {
                run.diff = out;
                fx.finish = true;
            }
            Some(HelperOut::Failed { message }) => {
                run.failed = Some(message);
            }
            None => {}
        }
        fx
    }

    /// The poller has the box cgroup and path rewrites: release the box.
    pub fn ready(&mut self) {
        if let Some(run) = self.run.as_mut()
            && let Stage::Started { to_helper } = &run.stage
        {
            run.sample_running = true;
            let _ = to_helper.try_send(HelperIn::Go {});
        }
    }

    /// Kernel budget drops per process: counted for the report when they
    /// hit box processes.
    pub fn drops(&mut self, per_proc: &[(ProcKey, u64)]) {
        if let Some(run) = self.run.as_mut() {
            for (k, n) in per_proc {
                if run.box_procs.contains(k) {
                    run.box_drops = run.box_drops.saturating_add(*n);
                }
            }
        }
    }

    /// Once a second: frees the slot from an abandoned upload or a helper
    /// that never finishes (its unit is killed).
    pub fn watchdog(&mut self) -> Effects {
        let mut fx = Effects::default();
        let Some(run) = self.run.as_mut() else {
            return fx;
        };
        let started = matches!(run.stage, Stage::Started { .. });
        let limit = if started {
            Duration::from_secs(u64::from(run.timeout_s)) + RUN_GRACE
        } else {
            UPLOAD_IDLE
        };
        let too_slow = match &run.stage {
            Stage::Uploading(u) => u.began.elapsed() > upload_deadline(u.size),
            _ => false,
        };
        if run.last_activity.elapsed() < limit && !too_slow {
            return fx;
        }
        if started {
            let _ = Command::new("/usr/bin/systemctl")
                .args(["kill", "--signal=SIGKILL"])
                .arg(format!("candor-ghh-{}.service", run.run_id))
                .arg(format!("candor-gh-{}.service", run.run_id))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            run.diff = None;
            run.failed = Some("the run did not finish in time; it was stopped".into());
        } else {
            run.failed = Some("the upload stalled; the sample was discarded".into());
        }
        let owner = run.owner;
        let rid = run.run_id.clone();
        let msg = run.failed.clone().unwrap_or_default();
        fx.replies.push((owner, status(GhState::Failed, &rid, msg)));
        self.cleanup(&mut fx);
        fx
    }

    /// Ends the run after the helper exited: report or failure.
    fn close(&mut self, mut fx: Effects) -> Effects {
        let Some(run) = self.run.as_ref() else {
            return fx;
        };
        if run.diff.is_some() {
            // The report was already produced from the Diff line.
            self.cleanup(&mut fx);
            return fx;
        }
        let msg = run
            .failed
            .clone()
            .unwrap_or_else(|| "the run ended without a result".into());
        fx.replies.push((
            run.owner,
            status(
                GhState::Failed,
                &run.run_id,
                candor_core::display::safe_str(&msg),
            ),
        ));
        self.cleanup(&mut fx);
        fx
    }

    fn cleanup(&mut self, fx: &mut Effects) {
        if let Some(run) = self.run.take() {
            if run.root.is_some() {
                fx.poller.push(crate::collector::PollerCmd::GhBoxEnd {
                    cgroup: run.cgroup,
                    majmin: run.majmin,
                });
                fx.decoys = Some(Vec::new());
            }
            let _ = std::fs::remove_file(upload_path(&run.run_id));
            let _ = std::fs::remove_file(job_path(&run.run_id));
        }
    }

    /// Frees the run slot once its report is out. The box is already empty
    /// (the helper diffs only after the cgroup is gone); the helper's own
    /// unmount and exit no longer concern the next run.
    pub fn finished(&mut self) -> Effects {
        let mut fx = Effects::default();
        self.cleanup(&mut fx);
        fx
    }

    /// Builds the report from the helper's Diff and the trace.
    pub fn report(
        &mut self,
        findings: Vec<Finding>,
        loss_now: Loss,
        now_ts: u64,
    ) -> Option<(u64, GhReport)> {
        let run = self.run.as_mut()?;
        let Some(HelperOut::Diff {
            exit_code,
            timed_out,
            cancelled,
            decoys,
            created,
            notes,
        }) = run.diff.clone()
        else {
            return None;
        };
        let mut decoys = decoys;
        for d in &mut decoys {
            if run.read_seen.contains(&(d.dev, d.ino)) {
                d.states.retain(|s| *s != DecoyState::Untouched);
                d.states.insert(0, DecoyState::Read);
            }
        }
        let mut conns: BTreeMap<(String, u16, String, String), ConnStat> = BTreeMap::new();
        for e in &run.timeline {
            if let EventKind::Connect {
                family,
                addr,
                port,
                sock,
            } = &e.kind
            {
                let k = (
                    addr.clone(),
                    *port,
                    format!("{family:?}"),
                    format!("{sock:?}"),
                );
                let c = conns.entry(k).or_insert(ConnStat {
                    family: *family,
                    addr: addr.clone(),
                    port: *port,
                    sock: *sock,
                    count: 0,
                    last_ts: 0,
                });
                c.count += 1;
                c.last_ts = c.last_ts.max(e.ts_ns);
            }
        }
        let mut notes = notes;
        if cancelled {
            notes.push("the run was cancelled".into());
        }
        if run.box_drops > 0 {
            notes.push(format!(
                "{} events of box processes were dropped by the per-process budget; their activity is incomplete",
                run.box_drops
            ));
        }
        if run.adopted > 0 {
            notes.push(format!(
                "{} box process(es) were recognised by their user and cgroup because their start was not recorded",
                run.adopted
            ));
        }
        if run.procs_overflow > 0 {
            notes.push(format!(
                "more than {MAX_BOX_PROCS} processes ran in the box; {} later ones were not followed",
                run.procs_overflow
            ));
        }
        if run.box_procs.len() > MAX_CHILDREN_LISTED {
            notes.push(format!(
                "{} processes ran in the box; the first {MAX_CHILDREN_LISTED} are listed",
                run.box_procs.len()
            ));
        }
        if run.timeline_dropped > 0 {
            notes.push(format!(
                "the timeline keeps the first {TIMELINE_CAP} events; {} later events are counted but not listed",
                run.timeline_dropped
            ));
        }
        let s = &run.loss_start;
        let loss = Loss {
            ringbuf: loss_now.ringbuf.saturating_sub(s.ringbuf),
            budget: loss_now.budget.saturating_sub(s.budget),
            scratch: loss_now.scratch.saturating_sub(s.scratch),
            decode: loss_now.decode.saturating_sub(s.decode),
            untracked: loss_now.untracked.saturating_sub(s.untracked),
            missed: loss_now.missed.saturating_sub(s.missed),
            since_ts_ns: run.started_ts,
        };
        let report = GhReport {
            run_id: run.run_id.clone(),
            sample: BStr::from(run.name.as_str()),
            args: run.args.clone(),
            timeout_s: run.timeout_s,
            started_ts: run.started_ts,
            ended_ts: now_ts,
            exit_code,
            timed_out,
            decoys,
            created,
            timeline: std::mem::take(&mut run.timeline),
            connections: conns.into_values().collect(),
            children: run
                .box_procs
                .iter()
                .take(MAX_CHILDREN_LISTED)
                .copied()
                .collect(),
            findings: findings
                .into_iter()
                .filter(|f| run.box_procs.contains(&f.proc))
                .collect(),
            loss,
            limitation: candor_core::explain::GLASSHOUSE_LIMITATION.into(),
            notes,
        };
        Some((run.owner, report))
    }

    /// The set of box processes (for finding selection by the core).
    pub fn box_procs(&self) -> BTreeSet<ProcKey> {
        self.run
            .as_ref()
            .map(|r| r.box_procs.clone())
            .unwrap_or_default()
    }
}

/// Creates RUNS (and /var/lib/candor) as 0711: the sandbox stage runs as
/// candor-box and must pass through them to its own run directory; others
/// may not list them. The unit's UMask (0027) and StateDirectoryMode would
/// otherwise make them 0750 root:root, and every Glasshouse run of an
/// installed package failed (found by the README test in a clean VM, WP34).
fn runs_dir() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(RUNS)?;
    for d in [
        std::path::Path::new(RUNS),
        std::path::Path::new(RUNS)
            .parent()
            .unwrap_or(std::path::Path::new(RUNS)),
    ] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o711))?;
    }
    Ok(())
}

/// The helper runs as root through systemd: it must be a root-owned file
/// that only root can change, in such a directory (a `--dev` daemon finds it
/// next to itself, which may be a user's build directory; review 2
/// finding 11).
pub fn helper_trusted(helper: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let ok = |p: &std::path::Path| {
        std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
    };
    let dir_ok = helper.parent().is_some_and(ok);
    if ok(helper) && dir_ok {
        Ok(())
    } else {
        Err(format!(
            "the helper {} (or its directory) is not root-owned or is writable by others",
            helper.display()
        ))
    }
}

/// True if `candor-glasshouse availability` says this system can run it.
/// The check runs as its own transient unit, exactly like a real helper:
/// the hardened daemon itself may not switch users or create namespaces
/// (no CAP_SETUID, RestrictNamespaces), so checking from inside it would
/// always say "unavailable" (found in WP29).
pub fn available() -> Result<(), String> {
    let (g, _rx) = Glasshouse::new();
    helper_trusted(&g.helper)?;
    let out = Command::new("/usr/bin/systemd-run")
        .args([
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
            "--service-type=exec",
            "-p",
            "MemoryMax=256M",
            "-p",
            "RuntimeMaxSec=60",
            "--",
        ])
        .arg(&g.helper)
        .arg("availability")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot start the availability check: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    // The helper prints "unavailable: <why>" (already escaped); bounded.
    let text = String::from_utf8_lossy(&out.stdout);
    let why = text
        .lines()
        .find_map(|l| l.strip_prefix("unavailable: "))
        .unwrap_or("the sandbox check failed");
    Err(why.chars().take(1000).collect())
}

/// Saves a report as `REPORTS/<run_id>.json`, 0640 root:candor.
pub fn save_report(r: &GhReport) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(REPORTS)?;
    // The directory too is root:candor 0750 (the unit's UMask would leave it
    // root-only, and group members could not open saved reports, WP34).
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(REPORTS, std::fs::Permissions::from_mode(0o750))?;
        if let Some(gid) = group_id("candor") {
            let _ = rustix::fs::chown(REPORTS, None, Some(rustix::fs::Gid::from_raw(gid)));
        }
    }
    let path = PathBuf::from(REPORTS).join(format!("{}.json", r.run_id));
    // Sample-chosen names may hold bidi or C1 characters: escaped (I10).
    let body = candor_core::display::json_safe(
        &serde_json::to_string_pretty(r).map_err(std::io::Error::other)?,
    )
    .into_bytes();
    rotate_reports(MAX_REPORTS.saturating_sub(1));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&path)?;
    f.write_all(&body)?;
    if let Some(gid) = group_id("candor") {
        let _ = rustix::fs::fchown(&f, None, Some(rustix::fs::Gid::from_raw(gid)));
    }
    Ok(path)
}

/// Keeps at most `keep` reports (names start with the run's unix time).
fn rotate_reports(keep: usize) {
    let Ok(rd) = std::fs::read_dir(REPORTS) else {
        return;
    };
    let mut names: Vec<std::ffi::OsString> = rd
        .flatten()
        .map(|e| e.file_name())
        .filter(|n| n.to_string_lossy().ends_with(".json"))
        .collect();
    names.sort();
    let excess = names.len().saturating_sub(keep);
    for n in names.into_iter().take(excess) {
        let _ = std::fs::remove_file(PathBuf::from(REPORTS).join(n));
    }
}

/// Removes what an earlier daemon or helper left behind (daemon start):
/// run tmpfs mounts, run directories, uploads, job files, units.
pub fn sweep() {
    let _ = Command::new("/usr/bin/systemctl")
        .args(["kill", "--signal=SIGKILL", "candor-gh-*", "candor-ghh-*"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let Ok(rd) = std::fs::read_dir(RUNS) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            // The run tmpfs was mounted by the helper unit in the host's
            // mount namespace. The hardened daemon has no CAP_SYS_ADMIN and
            // its own (slave) mount namespace, so systemd unmounts it; the
            // unmount propagates here. Plain umount as a fallback (dev runs
            // outside the unit).
            let ok = Command::new("/usr/bin/systemd-run")
                .args([
                    "--wait",
                    "--quiet",
                    "--collect",
                    "--",
                    "/usr/bin/umount",
                    "--lazy",
                ])
                .arg(&p)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                let _ = Command::new("/usr/bin/umount")
                    .arg("--lazy")
                    .arg(&p)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            if std::fs::remove_dir(&p).is_err() {
                eprintln!(
                    "candord: could not remove a stale Glasshouse run directory {}",
                    p.display()
                );
            }
        } else {
            let _ = std::fs::remove_file(&p);
        }
    }
}

fn group_id(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(name)).then(|| f.nth(1).and_then(|g| g.parse().ok()))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_deadline_grows_with_size_and_is_bounded() {
        assert_eq!(upload_deadline(1), UPLOAD_IDLE);
        // The largest sample may take its size at 64 KiB/s plus a minute:
        // about 69 minutes, not the 4096 idle minutes of one chunk a minute.
        let max = upload_deadline(MAX_SAMPLE);
        assert_eq!(max, UPLOAD_IDLE + Duration::from_secs(4096));
        assert!(max < UPLOAD_IDLE * 70);
    }

    #[test]
    fn helper_must_be_root_owned_in_a_root_owned_directory() {
        assert!(helper_trusted(std::path::Path::new("/usr/bin/true")).is_ok());
        // A build directory the test user owns (unit tests run unprivileged).
        let dir = std::env::temp_dir().join(format!("candor-helper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let h = dir.join("candor-glasshouse");
        std::fs::write(&h, "x").unwrap();
        let mine = rustix::process::geteuid().is_root();
        assert_eq!(helper_trusted(&h).is_ok(), mine);
        assert!(helper_trusted(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_are_sanitised() {
        assert_eq!(sanitize_name(b"fake_malware.py"), "fake_malware.py");
        assert_eq!(sanitize_name(b"../../etc/passwd"), "passwd");
        assert_eq!(sanitize_name(b"..hidden"), "hidden");
        assert_eq!(sanitize_name(b"a b\x1b[31m"), "a_b__31m");
        assert_eq!(sanitize_name(b""), "sample");
        assert_eq!(sanitize_name(b"x/"), "sample");
        assert_eq!(sanitize_name(&[b'a'; 200]).len(), 64);
    }

    fn ev(id: u64, proc: ProcKey, kind: EventKind) -> Event {
        Event {
            id,
            ts_ns: id,
            proc,
            tid: proc.tgid,
            uid: 994,
            kind,
        }
    }

    #[test]
    fn box_attribution_follows_forks_only() {
        let (mut g, _rx) = Glasshouse::new();
        let root = ProcKey {
            tgid: 10,
            start_ticks: 5,
        };
        let child = ProcKey {
            tgid: 11,
            start_ticks: 6,
        };
        let other = ProcKey {
            tgid: 12,
            start_ticks: 6,
        };
        let (tx, _hrx) = bounded(4);
        g.run = Some(Run {
            owner: 1,
            run_id: "t".into(),
            stage: Stage::Started { to_helper: tx },
            name: "s".into(),
            args: vec![],
            timeout_s: 60,
            started_ts: 0,
            root: Some(root),
            box_procs: BTreeSet::from([root]),
            cgroup: 1,
            majmin: (0, 1),
            decoys: vec![DecoyStatus {
                path: BStr::from("/home/victim/.ssh/id_ed25519"),
                dev: 47,
                ino: 6,
                states: vec![DecoyState::Untouched],
                new_path: None,
                size_before: 1,
                size_after: None,
                entropy_before: 1.0,
                entropy_after: None,
            }],
            by_inode: BTreeMap::from([((47, 6), 0)]),
            read_seen: BTreeSet::new(),
            timeline: vec![],
            timeline_dropped: 0,
            loss_start: Loss::default(),
            live_dirty: false,
            last_live: Instant::now() - Duration::from_secs(1),
            diff: None,
            failed: None,
            last_activity: Instant::now(),
            sample_running: false,
            adopted: 0,
            procs_overflow: 0,
            box_drops: 0,
        });
        let open = |p: ProcKey, id| {
            ev(
                id,
                p,
                EventKind::Open {
                    path: BStr::from("/home/victim/.ssh/id_ed25519"),
                    dev: 47,
                    ino: 6,
                    read: true,
                    write: false,
                    create: false,
                    trunc: false,
                    path_trunc: false,
                },
            )
        };
        g.observe(&open(other, 1)); // not in the box
        g.observe(&ev(2, root, EventKind::Fork { child }));
        g.observe(&open(child, 3));
        assert!(g.in_box(&child) && !g.in_box(&other));
        let run = g.run.as_ref().unwrap();
        assert_eq!(
            run.timeline.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(run.read_seen.contains(&(47, 6)));
        let (owner, live) = g.live().unwrap();
        assert_eq!(owner, 1);
        match live {
            DaemonMsg::GhStatus { decoys, .. } => {
                assert_eq!(decoys[0].states, vec![DecoyState::Read]);
            }
            other => panic!("{other:?}"),
        }
        assert!(g.live().is_none(), "rate limited and not dirty");
    }

    #[test]
    fn upload_checks_order_size_and_ownership() {
        let (mut g, _rx) = Glasshouse::new();
        // Uploads need /var/lib/candor; outside the VM/host install only
        // the refusals that happen before any file is created are testable.
        assert!(matches!(
            g.begin(1, &BStr::from("x"), 0).first(),
            Some(DaemonMsg::Error { code, .. }) if code == "bad_request"
        ));
        assert!(matches!(
            g.begin(1, &BStr::from("x"), MAX_SAMPLE + 1).first(),
            Some(DaemonMsg::Error { code, .. }) if code == "bad_request"
        ));
        assert!(matches!(
            g.chunk(1, 0, "AAAA").first(),
            Some(DaemonMsg::Error { code, .. }) if code == "bad_request"
        ));
        assert!(matches!(
            g.start(2, &[], 60, Loss::default()).first(),
            Some(DaemonMsg::Error { code, .. }) if code == "bad_request"
        ));
    }
}
