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
        let mut child = Command::new(bin_dir().join("sysscoped"))
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
    pub fn stop(mut self) -> Result<Vec<Event>, String> {
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
        for line in text.lines() {
            let ev: Event = serde_json::from_str(line).map_err(|e| format!("{e}: {line}"))?;
            events.push(ev);
        }
        Ok(events)
    }
}

/// Runs `wl` with the given actions in a fresh directory and returns its manifest.
pub fn wl(actions: &[&str]) -> Result<Manifest, String> {
    let dir = std::env::temp_dir().join(format!(
        "sysscope-wl-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
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
    }
}

/// Number of events of one kind.
pub fn count(events: &[Event], kind: &str) -> usize {
    events.iter().filter(|e| kind_name(e) == kind).count()
}
