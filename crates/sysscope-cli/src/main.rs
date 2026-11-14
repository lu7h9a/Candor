//! `sysscope`: the command-line client.
//!
//! An unprivileged program that talks to the daemon over its Unix socket
//! and prints process lists, events and findings. It is also the headless
//! surface the integration tests drive. `replay` works offline on a
//! recording, without a daemon.
//!
//! Exit codes: 0 ok, 1 error, 2 bad usage, 3 daemon not running,
//! 4 permission denied on the socket, 5 daemon or protocol error.
#![forbid(unsafe_code)]

mod conn;
mod export;
mod glasshouse;
mod out;

use conn::{CliError, Conn};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sysscope_core::Engine;
use sysscope_core::redact::Redactor;
use sysscope_proto::{ClientMsg, DaemonMsg, EventSub, EventSubMode, Finding, ProcKey, ProcRow};

const USAGE: &str = "usage: sysscope [--socket PATH] [--json] COMMAND
commands:
  status                      daemon, mode, process count, losses
  top [--sort cpu|mem|score] [-n N]   process table
  tree                        process tree with tree scores
  tail [--proc PID] [--count N]       stream events (Ctrl-C to stop)
  follow PID                  trace only PID and its descendants
  unfollow                    back to system-wide tracing
  act pause|resume|kill PID   EXPERIMENTAL: signal one process (daemon started with
                              --enable-act; root or group sysscope-act; protected list applies)
  detail PID                  files, connections, syscalls, findings of PID
  findings                    explanations of all flagged processes
  export --format json|csv [--raw] [--redact-ips]   redacted by default
  replay FILE [--frames OUT]  run a *.events.jsonl recording through the detector offline;
                              --frames also writes a *.frames.jsonl for `sysscope-gui --replay`
  glasshouse run [--timeout S] FILE [ARGS]   run FILE in the Glasshouse sandbox (uploaded
                              as bytes) and print what it touched; see the warning it prints
  glasshouse report FILE.json print a saved Glasshouse report
exit codes: 0 ok, 1 error, 2 usage, 3 daemon not running, 4 permission denied, 5 daemon error";

struct Args {
    socket: Option<PathBuf>,
    json: bool,
    rest: Vec<String>,
}

fn parse() -> Result<Args, CliError> {
    let mut a = Args {
        socket: None,
        json: false,
        rest: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(s) = it.next() {
        match s.as_str() {
            "--socket" => {
                a.socket = Some(
                    it.next()
                        .ok_or(CliError::Usage("--socket needs a path".into()))?
                        .into(),
                )
            }
            "--json" => a.json = true,
            "--version" | "-V" => {
                println!(
                    "sysscope {} (protocol {})",
                    env!("CARGO_PKG_VERSION"),
                    sysscope_proto::PROTO_VERSION
                );
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => a.rest.push(s),
        }
    }
    Ok(a)
}

/// Value of `--name V` in the remaining arguments.
fn opt(rest: &[String], name: &str) -> Option<String> {
    rest.iter()
        .position(|a| a == name)
        .and_then(|i| rest.get(i + 1).cloned())
}

fn flag(rest: &[String], name: &str) -> bool {
    rest.iter().any(|a| a == name)
}

fn pid_arg(rest: &[String], i: usize) -> Result<u32, CliError> {
    rest.get(i)
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| CliError::Usage(format!("expected a pid\n{USAGE}")))
}

fn welcome_wall(c: &Conn) -> u64 {
    match &c.welcome {
        DaemonMsg::Welcome {
            boot_to_wall_ns, ..
        } => *boot_to_wall_ns,
        _ => 0,
    }
}

/// Subscribes to snapshots and returns the first one.
fn snapshot(c: &mut Conn) -> Result<DaemonMsg, CliError> {
    c.send(&ClientMsg::Subscribe {
        snapshots: true,
        alerts: false,
        events: EventSub::Simple(EventSubMode::None),
    })?;
    c.recv_until(|m| matches!(m, DaemonMsg::Snapshot { .. }))
}

fn rows_of(m: &DaemonMsg) -> Vec<ProcRow> {
    match m {
        DaemonMsg::Snapshot { procs, .. } => procs.clone(),
        _ => Vec::new(),
    }
}

fn key_of(rows: &[ProcRow], pid: u32) -> Result<ProcKey, CliError> {
    rows.iter()
        .filter(|r| r.key.tgid == pid)
        .max_by_key(|r| r.key.start_ticks)
        .map(|r| r.key)
        .ok_or_else(|| CliError::Other(format!("process {pid} is not known to the daemon")))
}

fn detail(c: &mut Conn, key: ProcKey, maps: bool) -> Result<DaemonMsg, CliError> {
    c.send(&ClientMsg::GetDetail { proc: key, maps })?;
    c.recv_until(|m| matches!(m, DaemonMsg::Detail { .. }))
}

/// Findings of every process with a score, via Detail.
fn all_findings(c: &mut Conn, rows: &[ProcRow]) -> Result<Vec<Finding>, CliError> {
    let mut out = Vec::new();
    for r in rows.iter().filter(|r| r.score > 0) {
        // One process that cannot be described must not hide all findings.
        match detail(c, r.key, false) {
            Ok(DaemonMsg::Detail { findings, .. }) => out.extend(findings),
            Ok(_) => {}
            Err(CliError::Daemon(e)) => eprintln!("sysscope: skipping pid {}: {e}", r.key.tgid),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

fn print_findings(findings: &[Finding], rows: &[ProcRow], wall: u64) {
    if findings.is_empty() {
        println!("no findings");
    }
    for f in findings {
        let row = rows.iter().find(|r| r.key == f.proc);
        let parent = row
            .and_then(|r| r.parent)
            .and_then(|p| rows.iter().find(|x| x.key == p));
        println!("{}", out::finding(f, row, parent, wall));
    }
}

fn run(a: Args) -> Result<(), CliError> {
    let cmd = a.rest.first().cloned().unwrap_or_default();
    let rest: Vec<String> = a.rest.iter().skip(1).cloned().collect();
    if cmd == "replay" {
        return replay(&rest, a.json);
    }
    if cmd == "glasshouse" && rest.first().map(String::as_str) == Some("report") {
        return glasshouse::show(&rest);
    }
    if cmd == "glasshouse" {
        let mut c = Conn::open(a.socket.as_ref())?;
        return glasshouse::run(&mut c, &rest, a.json);
    }
    if cmd.is_empty() {
        return Err(CliError::Usage(USAGE.into()));
    }
    let known = [
        "status", "top", "tree", "tail", "follow", "unfollow", "detail", "findings", "export",
        "act",
    ];
    if !known.contains(&cmd.as_str()) {
        return Err(CliError::Usage(format!("unknown command {cmd:?}\n{USAGE}")));
    }
    let mut c = Conn::open(a.socket.as_ref())?;
    let wall = welcome_wall(&c);
    match cmd.as_str() {
        "status" => {
            let snap = snapshot(&mut c)?;
            if a.json {
                println!(
                    "{}",
                    out::json(&serde_json::json!({"welcome": c.welcome, "snapshot": snap}))
                );
            } else {
                print!("{}", out::status(&c.welcome, &snap));
            }
        }
        "top" => {
            let mut rows = rows_of(&snapshot(&mut c)?);
            match opt(&rest, "--sort").as_deref().unwrap_or("cpu") {
                "mem" => rows.sort_by_key(|r| std::cmp::Reverse(r.rss)),
                "score" => rows.sort_by_key(|r| std::cmp::Reverse((r.score, r.tree_score))),
                "cpu" => rows.sort_by(|x, y| y.cpu_pct.total_cmp(&x.cpu_pct)),
                other => return Err(CliError::Usage(format!("unknown sort {other:?}"))),
            }
            let n = opt(&rest, "-n").and_then(|n| n.parse().ok()).unwrap_or(25);
            if a.json {
                let shown: Vec<&ProcRow> = rows.iter().take(n).collect();
                println!("{}", out::json(&shown));
            } else {
                print!("{}", out::table(&rows, n));
            }
        }
        "tree" => {
            let rows = rows_of(&snapshot(&mut c)?);
            if a.json {
                println!("{}", out::json(&rows));
            } else {
                print!("{}", out::tree(&rows));
            }
        }
        "tail" => {
            let events = match opt(&rest, "--proc") {
                Some(p) => {
                    let pid = p
                        .parse()
                        .map_err(|_| CliError::Usage("--proc needs a pid".into()))?;
                    let rows = rows_of(&snapshot(&mut c)?);
                    EventSub::Proc {
                        proc: key_of(&rows, pid)?,
                    }
                }
                None => EventSub::Simple(EventSubMode::All),
            };
            c.send(&ClientMsg::Subscribe {
                snapshots: false,
                alerts: false,
                events,
            })?;
            let limit: Option<usize> = opt(&rest, "--count").and_then(|n| n.parse().ok());
            let seconds: Option<u64> = opt(&rest, "--seconds").and_then(|n| n.parse().ok());
            let started = Instant::now();
            let mut printed = 0usize;
            loop {
                if limit.is_some_and(|l| printed >= l)
                    || seconds.is_some_and(|s| started.elapsed() >= Duration::from_secs(s))
                {
                    break;
                }
                if let Some(DaemonMsg::Events {
                    events,
                    client_dropped,
                }) = c.recv_timeout(Duration::from_millis(500))?
                {
                    for e in events {
                        if limit.is_some_and(|l| printed >= l) {
                            break;
                        }
                        if a.json {
                            println!(
                                "{}",
                                out::json_safe(&serde_json::to_string(&e).unwrap_or_default())
                            );
                        } else {
                            println!("{}", out::event_line(&e, wall));
                        }
                        printed += 1;
                    }
                    if client_dropped > 0 && a.json {
                        println!("{}", serde_json::json!({"client_dropped": client_dropped}));
                    } else if client_dropped > 0 {
                        eprintln!(
                            "({client_dropped} events dropped because this client was too slow)"
                        );
                    }
                }
            }
        }
        "follow" => {
            let pid = pid_arg(&rest, 0)?;
            let rows = rows_of(&snapshot(&mut c)?);
            c.send(&ClientMsg::Follow {
                root: key_of(&rows, pid)?,
            })?;
            if let DaemonMsg::ActResult { message, .. } =
                c.recv_until(|m| matches!(m, DaemonMsg::ActResult { .. }))?
            {
                println!("{}", sysscope_core::display::safe_str(&message));
            }
            println!("other processes are not traced while following");
        }
        "act" => {
            // Experimental (D19): only with sysscoped --enable-act, and only
            // for root or members of sysscope-act. Never automatic.
            let action = match rest.first().map(String::as_str) {
                Some("pause") => sysscope_proto::ActAction::Pause,
                Some("resume") => sysscope_proto::ActAction::Resume,
                Some("kill") => sysscope_proto::ActAction::Kill,
                _ => return Err(CliError::Usage("act pause|resume|kill PID".into())),
            };
            let pid = pid_arg(&rest, 1)?;
            let rows = rows_of(&snapshot(&mut c)?);
            c.send(&ClientMsg::Act {
                proc: key_of(&rows, pid)?,
                action,
                nonce: format!("cli-{}", std::process::id()),
            })?;
            if let DaemonMsg::ActResult { ok, message } =
                c.recv_until(|m| matches!(m, DaemonMsg::ActResult { .. }))?
            {
                let text = sysscope_core::display::safe_str(&message);
                if !ok {
                    return Err(CliError::Daemon(text));
                }
                println!("{text}");
            }
        }
        "unfollow" => {
            c.send(&ClientMsg::Unfollow {})?;
            if let DaemonMsg::ActResult { message, .. } =
                c.recv_until(|m| matches!(m, DaemonMsg::ActResult { .. }))?
            {
                println!("{}", sysscope_core::display::safe_str(&message));
            }
        }
        "detail" => {
            let pid = pid_arg(&rest, 0)?;
            let snap = snapshot(&mut c)?;
            if matches!(
                &snap,
                DaemonMsg::Snapshot {
                    mode: sysscope_proto::Mode::Follow { .. },
                    ..
                }
            ) {
                // In follow mode syscall hooks run only while someone looks
                // (owner's Q5 B): ask for them and give them a moment.
                c.send(&ClientMsg::WatchSyscalls { on: true })?;
                std::thread::sleep(Duration::from_secs(6));
            }
            let rows = rows_of(&snap);
            let d = detail(&mut c, key_of(&rows, pid)?, flag(&rest, "--maps"))?;
            if a.json {
                println!("{}", out::json(&d));
            } else if let DaemonMsg::Detail {
                files,
                conns,
                syscalls,
                children,
                findings,
                ..
            } = &d
            {
                println!("files ({}):", files.len());
                for f in files.iter().take(50) {
                    println!(
                        "  {} opens={} {}{}",
                        sysscope_core::display::safe(&f.path),
                        f.opens,
                        if f.read { "r" } else { "" },
                        if f.write { "w" } else { "" }
                    );
                }
                println!("connections ({}):", conns.len());
                for cs in conns {
                    println!(
                        "  {}:{} x{}",
                        sysscope_core::display::safe_str(&cs.addr),
                        cs.port,
                        cs.count
                    );
                }
                println!("syscalls ({}):", syscalls.len());
                let mut sc = syscalls.clone();
                sc.sort_by_key(|s| std::cmp::Reverse(s.count));
                for s in sc.iter().take(15) {
                    println!("  {:<20} {}", s.name, s.count);
                }
                println!(
                    "children: {}",
                    children
                        .iter()
                        .map(|k| k.tgid.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                print_findings(findings, &rows, wall);
            }
        }
        "findings" => {
            let rows = rows_of(&snapshot(&mut c)?);
            let findings = all_findings(&mut c, &rows)?;
            if a.json {
                println!("{}", out::json(&findings));
            } else {
                print_findings(&findings, &rows, wall);
            }
        }
        "export" => {
            let format = opt(&rest, "--format").unwrap_or_else(|| "json".into());
            let raw = flag(&rest, "--raw");
            let mut redactor = if raw {
                eprintln!(
                    "warning: --raw export contains user names, home paths, host name and command lines; review before sharing"
                );
                None
            } else {
                let (home, user, host) = export::local_names();
                Some(Redactor::new(
                    &home,
                    &user,
                    &host,
                    flag(&rest, "--redact-ips"),
                ))
            };
            let rows = rows_of(&snapshot(&mut c)?);
            match format.as_str() {
                "csv" => print!("{}", export::csv(&rows, &mut redactor)),
                "json" => {
                    let findings = all_findings(&mut c, &rows)?;
                    println!("{}", export::json(&rows, &findings, &mut redactor));
                }
                other => {
                    return Err(CliError::Usage(format!(
                        "unknown format {other:?} (json or csv)"
                    )));
                }
            }
        }
        _ => return Err(CliError::Usage(USAGE.into())),
    }
    Ok(())
}

/// Offline: replay a recording through the detector and print the result.
fn replay(rest: &[String], json: bool) -> Result<(), CliError> {
    let path = rest
        .first()
        .ok_or_else(|| CliError::Usage("replay needs a file".into()))?;
    let file = std::fs::File::open(path).map_err(|e| CliError::Other(format!("{path}: {e}")))?;
    let mut engine = Engine::with_defaults().map_err(|e| CliError::Other(e.to_string()))?;
    let mut read_error = None;
    let mut skipped = 0u64;
    let mut reader = std::io::BufReader::new(file);
    // Lines are read with a cap, so a hostile file cannot make us hold an
    // endless line; too-long or non-UTF-8 lines are skipped and counted.
    let lines = std::iter::from_fn(|| {
        loop {
            match sysscope_proto::read_line_bounded(
                &mut reader,
                sysscope_proto::MAX_DAEMON_FRAME as usize,
            ) {
                Ok(Some(sysscope_proto::Line::Text(b))) => match String::from_utf8(b) {
                    Ok(l) => return Some(l),
                    Err(_) => skipped += 1,
                },
                Ok(Some(sysscope_proto::Line::TooLong)) => skipped += 1,
                Ok(None) => return None,
                Err(e) => {
                    read_error = Some(e);
                    return None;
                }
            }
        }
    });
    let frames_out = opt(rest, "--frames");
    // Each alert with its process's score at that moment: scores decay and
    // exited processes leave the state, so the final snapshot understates
    // what a user saw during a long recording (review F7).
    let mut alert_scores = Vec::new();
    let alerts = match &frames_out {
        Some(out) => write_frames(&mut engine, lines, out)?,
        None => {
            let mut alerts = Vec::new();
            sysscope_core::replay::for_each_input(lines, |input| {
                for a in engine.apply(&input) {
                    let now = engine.state.now().max(a.ts_ns);
                    let score = engine.detector.score(&a.proc, now);
                    alert_scores.push(serde_json::json!({
                        "proc": a.proc, "rule": a.rule, "ts_ns": a.ts_ns, "score": score
                    }));
                    alerts.push(a);
                }
            })
            .map_err(|e| CliError::Other(format!("{path}: {e}")))?;
            alerts
        }
    };
    if let Some(e) = read_error {
        return Err(CliError::Other(format!("{path}: {e}")));
    }
    if skipped > 0 {
        eprintln!("sysscope: skipped {skipped} unreadable line(s) in {path}");
    }
    let snap = engine.snapshot(0);
    let rows = rows_of(&snap);
    let findings: Vec<Finding> = engine.detector.findings().cloned().collect();
    if json {
        println!(
            "{}",
            out::json(
                &serde_json::json!({"snapshot": snap, "findings": findings, "alerts": alerts.len(),
                    "alert_scores": alert_scores})
            )
        );
    } else {
        println!(
            "replayed {path}: {} processes, {} findings, {} alerts",
            rows.len(),
            findings.len(),
            alerts.len()
        );
        print_findings(&findings, &rows, 0);
    }
    Ok(())
}

/// Replays inputs and writes what a daemon would have sent to a GUI: a
/// Welcome, a Snapshot at every Tick, Alerts as they happen, and at the end
/// a Detail for every flagged process and the 20 busiest ones.
fn write_frames<S: AsRef<str>>(
    engine: &mut Engine,
    lines: impl Iterator<Item = S>,
    out: &str,
) -> Result<Vec<Finding>, CliError> {
    use std::io::Write;
    let file = std::fs::File::create(out).map_err(|e| CliError::Other(format!("{out}: {e}")))?;
    let mut w = std::io::BufWriter::new(file);
    let put = |w: &mut std::io::BufWriter<std::fs::File>, m: &DaemonMsg| {
        if let Ok(line) = serde_json::to_string(m) {
            let _ = writeln!(w, "{line}");
        }
    };
    let mut lines = lines.peekable();
    let header: serde_json::Value = lines
        .peek()
        .and_then(|l| serde_json::from_str(l.as_ref()).ok())
        .unwrap_or_default();
    let welcome = DaemonMsg::Welcome {
        proto: sysscope_proto::PROTO_VERSION,
        daemon_version: header
            .get("daemon_version")
            .and_then(|v| v.as_str())
            .unwrap_or("replay")
            .into(),
        kernel: header
            .get("kernel")
            .and_then(|v| v.as_str())
            .unwrap_or("replay")
            .into(),
        boot_to_wall_ns: header
            .get("boot_to_wall_ns")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        features: Vec::new(),
        act_enabled: false,
    };
    put(&mut w, &welcome);
    let mut alerts = Vec::new();
    let mut seq = 0u64;
    sysscope_core::replay::for_each_input(lines, |input| {
        let tick = matches!(input, sysscope_core::Input::Tick { .. });
        for a in engine.apply(&input) {
            put(&mut w, &DaemonMsg::Alert { finding: a.clone() });
            alerts.push(a);
        }
        if tick {
            seq += 1;
            put(&mut w, &engine.snapshot(seq));
        }
    })
    .map_err(|e| CliError::Other(e.to_string()))?;
    let snap = engine.snapshot(seq + 1);
    let mut rows = rows_of(&snap);
    rows.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct));
    let mut keys: Vec<ProcKey> = rows.iter().take(20).map(|r| r.key).collect();
    keys.extend(
        rows.iter()
            .filter(|r| r.score > 0 || r.tree_score > 0)
            .map(|r| r.key),
    );
    keys.sort();
    keys.dedup();
    for k in keys {
        if let Some(DaemonMsg::Detail {
            proc,
            series,
            recent,
            files,
            conns,
            syscalls,
            children,
            ..
        }) = engine.state.detail(&k)
        {
            let findings = engine.detector.findings_for(&proc);
            put(
                &mut w,
                &DaemonMsg::Detail {
                    proc,
                    series,
                    recent,
                    files,
                    conns,
                    syscalls,
                    children,
                    maps: None,
                    findings,
                },
            );
        }
    }
    put(&mut w, &snap);
    w.flush()
        .map_err(|e| CliError::Other(format!("{out}: {e}")))?;
    Ok(alerts)
}

fn main() {
    // `sysscope findings | head`: stdout closes early; exit quietly like
    // other command-line tools instead of printing a panic.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.to_string().contains("Broken pipe") {
            std::process::exit(0);
        }
        default_hook(info);
    }));
    let result = parse().and_then(run);
    if let Err(e) = result {
        eprintln!("sysscope: {e}");
        std::process::exit(e.exit_code());
    }
}
