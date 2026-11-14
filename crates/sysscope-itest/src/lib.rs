//! Root integration tests for SysScope.
//!
//! The tests in this crate start the real daemon, run the ground-truth
//! workload `wl` (testkit/wl) and compare what the tracer saw with what the
//! workload says it did. They need root and run only through `make test-root`
//! or inside a test VM (`make vm-test`), always single-threaded.
//!
//! Binaries are found through environment variables so the same test binary
//! works on the host and in a VM: `SYSSCOPE_BIN_DIR` (default
//! `target/release`) holds `sysscoped` and `sysscope-wl`.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use sysscope_proto::{Event, EventKind, ProcKey};

/// What `wl` printed about itself and its actions.
pub type Manifest = serde_json::Value;

/// Directory holding `sysscoped` and `sysscope-wl`.
pub fn bin_dir() -> PathBuf {
    match std::env::var_os("SYSSCOPE_BIN_DIR") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release"),
    }
}

/// Fails with a clear message unless running as root.
pub fn require_root() -> Result<(), String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    let euid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().nth(1))
        .unwrap_or("?");
    if euid != "0" {
        return Err(format!(
            "integration tests need root (euid {euid}); run them with `make test-root` or `make vm-test`"
        ));
    }
    Ok(())
}

/// A running `sysscoped --dev --dump` whose stdout is collected in a file.
pub struct Dump {
    child: Child,
    out: PathBuf,
    /// Lines the daemon wrote to stderr (filled by a reader thread).
    stderr: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Dump {
    /// Starts the daemon in dump mode and waits until it is tracing.
    pub fn start(extra_args: &[&str]) -> Result<Dump, String> {
        require_root()?;
        let out = std::env::temp_dir().join(format!("sysscope-dump-{}.jsonl", std::process::id()));
        let file = std::fs::File::create(&out).map_err(|e| e.to_string())?;
        let mut child = daemon_command()
            .args(["--dev", "--dump"])
            .args(extra_args)
            .stdout(Stdio::from(file))
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("starting sysscoped: {e}"))?;
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipe = child.stderr.take().ok_or("no stderr pipe")?;
        let sink = std::sync::Arc::clone(&stderr);
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if let Ok(mut v) = sink.lock() {
                    v.push(line);
                }
            }
        });
        let dump = Dump { child, out, stderr };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if dump.stderr_text().contains("tracing") {
                return Ok(dump);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(format!("sysscoped did not start: {}", dump.stderr_text()))
    }

    /// Everything the daemon wrote to stderr so far.
    pub fn stderr_text(&self) -> String {
        self.stderr.lock().map(|v| v.join("\n")).unwrap_or_default()
    }

    /// Stops the daemon (SIGINT) and returns every event it printed.
    pub fn stop(self) -> Result<Vec<Event>, String> {
        self.stop_full().map(|(events, _)| events)
    }

    /// Stops the daemon and returns its events and its final `sysstat` lines.
    pub fn stop_full(mut self) -> Result<(Vec<Event>, Vec<serde_json::Value>), String> {
        std::thread::sleep(Duration::from_millis(500));
        let pid = self.child.id().to_string();
        Command::new("kill")
            .args(["-INT", &pid])
            .status()
            .map_err(|e| e.to_string())?;
        self.child.wait().map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(100));
        let text = std::fs::read_to_string(&self.out).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&self.out);
        let mut events = Vec::new();
        let mut stats = Vec::new();
        for line in text.lines() {
            if line.starts_with("{\"sysstat\"")
                || line.starts_with("{\"budget\"")
                || line.starts_with("{\"loss\"")
                || line.starts_with("{\"t\":\"Samples\"")
            {
                // Kept whole: {"sysstat": {...}}, {"budget": {...}} or a
                // {"t":"Samples",...} core input.
                let v: serde_json::Value =
                    serde_json::from_str(line).map_err(|e| format!("{e}: {line}"))?;
                stats.push(v);
                continue;
            }
            let ev: Event = serde_json::from_str(line).map_err(|e| format!("{e}: {line}"))?;
            events.push(ev);
        }
        Ok((events, stats))
    }
}

/// A number no other call in this process gets (work directory names).
/// `Instant::now().elapsed()` was used before: about 0 for every call, so
/// two workloads started together shared one directory and one deleted the
/// other's files (intermittent loss-identity failure, WP31 matrix).
fn unique() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Runs `wl` with the given actions in a fresh directory and returns its manifest.
pub fn wl(actions: &[&str]) -> Result<Manifest, String> {
    let dir = std::env::temp_dir().join(format!("sysscope-wl-{}-{}", std::process::id(), unique()));
    let _ = std::fs::remove_dir_all(&dir);
    let out = Command::new(bin_dir().join("sysscope-wl"))
        .arg("--dir")
        .arg(&dir)
        .args(actions)
        .output()
        .map_err(|e| format!("running wl: {e}"))?;
    // Give a leader-exits-first run time to finish its other thread.
    std::thread::sleep(Duration::from_millis(600));
    let _ = std::fs::remove_dir_all(&dir);
    serde_json::from_slice(&out.stdout).map_err(|e| {
        format!(
            "wl manifest: {e}; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// The ProcKey of the wl process from its manifest.
pub fn wl_key(m: &Manifest) -> ProcKey {
    ProcKey {
        tgid: m["tgid"].as_u64().unwrap_or(0) as u32,
        start_ticks: m["start_ticks"].as_u64().unwrap_or(0),
    }
}

/// Keys of `root` and every process it created (transitively), from FORK events.
pub fn subtree(root: ProcKey, events: &[Event]) -> HashSet<ProcKey> {
    let mut keys = HashSet::from([root]);
    for e in events {
        if let EventKind::Fork { child } = &e.kind
            && keys.contains(&e.proc)
        {
            keys.insert(*child);
        }
    }
    keys
}

/// Starts the daemon, runs wl, stops the daemon; returns the manifest and
/// the events that belong to wl's process subtree.
pub fn run_wl(actions: &[&str]) -> Result<(Manifest, Vec<Event>), String> {
    let dump = Dump::start(&[])?;
    let manifest = wl(actions)?;
    let all = dump.stop()?;
    let keys = subtree(wl_key(&manifest), &all);
    let mine = all.into_iter().filter(|e| keys.contains(&e.proc)).collect();
    Ok((manifest, mine))
}

/// Like `run_wl`, but also returns the daemon's final syscall statistics
/// for wl's own tgid.
pub fn run_wl_sys(actions: &[&str]) -> Result<(Manifest, Vec<serde_json::Value>), String> {
    let dump = Dump::start(&[])?;
    let manifest = wl(actions)?;
    let (_, stats) = dump.stop_full()?;
    let tgid = wl_key(&manifest).tgid;
    Ok((manifest, sysstats_of(&stats, tgid)))
}

/// The `sysstat` objects for one tgid from `Dump::stop_full` output.
pub fn sysstats_of(stats: &[serde_json::Value], tgid: u32) -> Vec<serde_json::Value> {
    stats
        .iter()
        .filter_map(|v| v.get("sysstat"))
        .filter(|s| s["tgid"].as_u64() == Some(u64::from(tgid)))
        .cloned()
        .collect()
}

/// (budget dropped, ring-buffer dropped) for one tgid (0, 0 if absent).
pub fn drops_of(stats: &[serde_json::Value], tgid: u32) -> (u64, u64) {
    stats
        .iter()
        .filter_map(|v| v.get("budget"))
        .find(|b| b["tgid"].as_u64() == Some(u64::from(tgid)))
        .map(|b| {
            (
                b["dropped"].as_u64().unwrap_or(0),
                b["rb_dropped"].as_u64().unwrap_or(0),
            )
        })
        .unwrap_or((0, 0))
}

/// A wl started with --wait-stdin: it does nothing until `release`.
pub struct PausedWl {
    child: Child,
    dir: PathBuf,
}

impl PausedWl {
    /// Starts wl paused; its pid is known before it does anything.
    pub fn start(actions: &[&str]) -> Result<PausedWl, String> {
        let dir =
            std::env::temp_dir().join(format!("sysscope-wlp-{}-{}", std::process::id(), unique()));
        let _ = std::fs::remove_dir_all(&dir);
        let child = Command::new(bin_dir().join("sysscope-wl"))
            .arg("--dir")
            .arg(&dir)
            .arg("--wait-stdin")
            .args(actions)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("running wl: {e}"))?;
        Ok(PausedWl { child, dir })
    }

    /// Process id of the paused wl.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Lets it run and waits for its manifest.
    pub fn release(mut self) -> Result<Manifest, String> {
        use std::io::Write;
        if let Some(mut stdin) = self.child.stdin.take() {
            stdin.write_all(b"x").map_err(|e| e.to_string())?;
        }
        let out = self.child.wait_with_output().map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(300));
        let _ = std::fs::remove_dir_all(&self.dir);
        serde_json::from_slice(&out.stdout).map_err(|e| format!("wl manifest: {e}"))
    }
}

/// Short name of an event kind, for counting.
pub fn kind_name(e: &Event) -> &'static str {
    match e.kind {
        EventKind::Exec { .. } => "Exec",
        EventKind::Fork { .. } => "Fork",
        EventKind::Exit { .. } => "Exit",
        EventKind::Open { .. } => "Open",
        EventKind::Rename { .. } => "Rename",
        EventKind::Unlink { .. } => "Unlink",
        EventKind::Connect { .. } => "Connect",
        EventKind::Listen { .. } => "Listen",
        EventKind::Ptrace { .. } => "Ptrace",
    }
}

/// Number of events of one kind.
pub fn count(events: &[Event], kind: &str) -> usize {
    events.iter().filter(|e| kind_name(e) == kind).count()
}

/// Path bytes from a wl manifest string (wl writes each non-ASCII byte as
/// \u00XX, so every char is one byte).
pub fn manifest_bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_str()
        .unwrap_or("")
        .chars()
        .map(|c| u32::from(c).min(255) as u8)
        .collect()
}

/// (dev, ino) of a wl manifest file object.
pub fn manifest_id(v: &serde_json::Value) -> (u64, u64) {
    (
        v["dev"].as_u64().unwrap_or(0),
        v["ino"].as_u64().unwrap_or(0),
    )
}

/// The manifest object of the first action with this name.
pub fn action<'a>(m: &'a Manifest, name: &str) -> &'a serde_json::Value {
    m["actions"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["action"] == name))
        .unwrap_or(&serde_json::Value::Null)
}

/// Socket of a daemon started with --dev.
pub const DEV_SOCKET: &str = "/run/sysscope-dev/sysscope.sock";

/// `sysscoped`, or `$SYSSCOPE_ITEST_WRAP sysscoped` when that is set: WP29
/// runs every root itest with the daemon inside the hardened systemd unit
/// (scripts/unit-wrap.sh).
fn daemon_command() -> Command {
    let daemon = bin_dir().join("sysscoped");
    match std::env::var_os("SYSSCOPE_ITEST_WRAP") {
        Some(w) if !w.is_empty() => {
            let mut c = Command::new(w);
            c.arg(daemon);
            c
        }
        _ => Command::new(daemon),
    }
}

/// A running `sysscoped --dev` serving the socket.
pub struct Daemon {
    child: Child,
    stderr: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Daemon {
    /// Starts the daemon and waits until it serves the socket.
    pub fn start(extra_args: &[&str]) -> Result<Daemon, String> {
        Daemon::start_under(&[], extra_args)
    }

    /// Like `start`, but runs `wrapper... sysscoped` (e.g. strace).
    pub fn start_under(wrapper: &[&str], extra_args: &[&str]) -> Result<Daemon, String> {
        require_root()?;
        let daemon = bin_dir().join("sysscoped");
        let mut cmd = match wrapper.split_first() {
            Some((prog, rest)) => {
                let mut c = Command::new(prog);
                c.args(rest).arg(&daemon);
                c
            }
            None => daemon_command(),
        };
        let mut child = cmd
            .arg("--dev")
            .args(extra_args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("starting sysscoped: {e}"))?;
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipe = child.stderr.take().ok_or("no stderr pipe")?;
        let sink = std::sync::Arc::clone(&stderr);
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if let Ok(mut v) = sink.lock() {
                    v.push(line);
                }
            }
        });
        let d = Daemon { child, stderr };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if d.stderr_text().contains("serving") {
                return Ok(d);
            }
            if let Ok(Some(status)) = d.child_status() {
                return Err(format!("sysscoped exited {status}: {}", d.stderr_text()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(format!("sysscoped did not start: {}", d.stderr_text()))
    }

    fn child_status(&self) -> std::io::Result<Option<std::process::ExitStatus>> {
        // try_wait needs &mut; peek via /proc instead.
        let alive = std::path::Path::new(&format!("/proc/{}", self.child.id())).exists();
        Ok(if alive {
            None
        } else {
            Some(std::process::ExitStatus::default())
        })
    }

    /// The daemon's pid (from its "serving ... pid N" line).
    pub fn pid(&self) -> u32 {
        self.stderr_text()
            .split("pid ")
            .nth(1)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| self.child.id())
    }

    /// Everything the daemon wrote to stderr so far.
    pub fn stderr_text(&self) -> String {
        self.stderr.lock().map(|v| v.join("\n")).unwrap_or_default()
    }

    /// Sends SIGTERM to the daemon and waits; returns the exit status, or
    /// the daemon's stderr if it did not exit cleanly.
    pub fn stop(mut self) -> Result<std::process::ExitStatus, String> {
        Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .map_err(|e| e.to_string())?;
        let status = self.child.wait().map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(100));
        if status.success() {
            Ok(status)
        } else {
            Err(format!("sysscoped exited {status}: {}", self.stderr_text()))
        }
    }
}

impl Drop for Daemon {
    /// A test that panics must not leave its daemon running (the next test
    /// would find the socket busy).
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = Command::new("kill")
                .args(["-KILL", &self.pid().to_string()])
                .status();
            let _ = self.child.wait();
            let _ = std::fs::remove_file(DEV_SOCKET);
        }
    }
}

/// A protocol client over the dev socket.
pub struct Client {
    /// The connection.
    pub stream: std::os::unix::net::UnixStream,
}

impl Client {
    /// Connects (no Hello yet).
    pub fn connect() -> Result<Client, String> {
        let stream =
            std::os::unix::net::UnixStream::connect(DEV_SOCKET).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        Ok(Client { stream })
    }

    /// Connects and says Hello; returns the client and the first reply.
    pub fn hello() -> Result<(Client, sysscope_proto::DaemonMsg), String> {
        let mut c = Client::connect()?;
        c.send(&sysscope_proto::ClientMsg::Hello {
            proto: sysscope_proto::PROTO_VERSION,
            client: sysscope_proto::ClientKind::Cli,
            version: "itest".into(),
        })?;
        let reply = c.recv()?;
        Ok((c, reply))
    }

    /// Sends one message.
    pub fn send(&mut self, m: &sysscope_proto::ClientMsg) -> Result<(), String> {
        let body = sysscope_proto::encode(m).map_err(|e| e.to_string())?;
        sysscope_proto::write_frame(&mut self.stream, &body, sysscope_proto::MAX_CLIENT_FRAME)
            .map_err(|e| e.to_string())
    }

    /// Receives one message (error on EOF or timeout).
    pub fn recv(&mut self) -> Result<sysscope_proto::DaemonMsg, String> {
        match sysscope_proto::read_frame(&mut self.stream, sysscope_proto::MAX_DAEMON_FRAME) {
            Ok(Some(body)) => sysscope_proto::decode_daemon(&body).map_err(|e| e.to_string()),
            Ok(None) => Err("eof".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Receives until a message matches `f` (or an error).
    pub fn recv_until(
        &mut self,
        f: impl Fn(&sysscope_proto::DaemonMsg) -> bool,
    ) -> Result<sysscope_proto::DaemonMsg, String> {
        loop {
            let m = self.recv()?;
            if f(&m) {
                return Ok(m);
            }
        }
    }
}
