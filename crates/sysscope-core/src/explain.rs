//! The explanation text for a finding (plan 5.6), shared by CLI, GUI and
//! export so all three say exactly the same thing.
//!
//! All bytes that came from a traced process (paths, argv) are shown in
//! their escaped form, so the text is safe to print to a terminal (I10).

use crate::detect::{Band, Detector};
use sysscope_proto::{BStr, Event, EventKind, Finding};

/// Plan 6.4, verbatim: shown in the GUI Glasshouse tab, every Glasshouse
/// report footer, the README and the docs.
pub const GLASSHOUSE_LIMITATION: &str = "Glasshouse is a behaviour-demonstration sandbox, not a malware containment system. The program you run shares this computer's kernel. A kernel or sandbox vulnerability, a CPU side-channel, or a mistake in configuration could let it read your data or take over your account or the machine. Glasshouse does not hide that it is a sandbox, so a program may behave differently inside it. Run only programs you would accept losing this machine to, such as your own test scripts. For real or suspected malware use a dedicated virtual machine or a separate computer with no network, following docs/REAL_SAMPLES.md.";

/// Facts about the flagged process that the finding itself does not carry.
#[derive(Clone, Debug, PartialEq)]
pub struct ExplainCtx {
    /// Current score of the process.
    pub score: u8,
    /// Band of that score.
    pub band: Band,
    /// Process start time (boot ns).
    pub start_ns: u64,
    /// Parent executable and pid, if known.
    pub parent: Option<(BStr, u32)>,
    /// uid.
    pub uid: u32,
    /// Add to boot ns to get Unix-epoch ns (from Welcome).
    pub boot_to_wall_ns: u64,
    /// Offset of the viewer's time zone from UTC, seconds.
    pub tz_offset_s: i64,
}

/// "HH:MM:SS" for a boot-time timestamp.
pub fn clock(boot_ns: u64, boot_to_wall_ns: u64, tz_offset_s: i64) -> String {
    let wall_s = (boot_ns.saturating_add(boot_to_wall_ns) / 1_000_000_000) as i64 + tz_offset_s;
    let day = wall_s.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", day / 3600, (day / 60) % 60, day % 60)
}

/// One-line description of an event, e.g. "Open /etc/passwd (read)".
pub fn describe(e: &Event) -> String {
    match &e.kind {
        EventKind::Exec { exe, fileless, .. } => {
            format!("Exec {exe}{}", if *fileless { " (fileless)" } else { "" })
        }
        EventKind::Fork { child } => format!("Fork child pid {}", child.tgid),
        EventKind::Exit {} => "Exit".to_string(),
        EventKind::Open {
            path,
            read,
            write,
            create,
            trunc,
            ..
        } => {
            let mut modes = Vec::new();
            if *read {
                modes.push("read");
            }
            if *write {
                modes.push("write");
            }
            if *create {
                modes.push("create");
            }
            if *trunc {
                modes.push("truncate");
            }
            format!("Open {path} ({})", modes.join(","))
        }
        EventKind::Rename { old, new, .. } => format!("Rename {old} -> {new}"),
        EventKind::Unlink { path, .. } => format!("Unlink {path}"),
        EventKind::Connect { addr, port, .. } => format!("Connect {addr}:{port}"),
        EventKind::Listen { addr, port } => format!("Listen {addr}:{port}"),
        EventKind::Ptrace { target, .. } => {
            format!("Ptrace attach check on pid {}", target.tgid)
        }
    }
}

/// A daemon-supplied text field as one line: CR and LF become visible
/// escapes, so only the renderer's own newlines separate lines.
fn one_line(s: &str) -> String {
    s.replace('\r', "\\u{000D}").replace('\n', "\\u{000A}")
}

/// Renders the full explanation text (plan 5.6).
pub fn render(f: &Finding, ctx: &ExplainCtx) -> String {
    let mut f = f.clone();
    f.rule = one_line(&f.rule);
    f.title = one_line(&f.title);
    f.subject = one_line(&f.subject);
    f.summary = one_line(&f.summary);
    f.attack = f.attack.as_deref().map(one_line);
    f.why = f.why.iter().map(|w| one_line(w)).collect();
    f.benign = f.benign.iter().map(|b| one_line(b)).collect();
    let f = &f;
    let t = |ns| clock(ns, ctx.boot_to_wall_ns, ctx.tz_offset_s);
    let mut out = String::new();
    let parent = match &ctx.parent {
        Some((exe, pid)) => format!(", parent {exe} pid {pid}"),
        None => String::new(),
    };
    out.push_str(&format!(
        "[{} {}] {} (pid {}, started {}{parent}, uid {})\n",
        ctx.band.label(),
        ctx.score,
        f.exe,
        f.proc.tgid,
        t(ctx.start_ns),
        ctx.uid
    ));
    let attack = match &f.attack {
        Some(a) => format!(" - ATT&CK {a}"),
        None => String::new(),
    };
    out.push_str(&format!(
        "{} {}{attack} - weight {}, confidence {}\n",
        f.rule,
        f.title,
        trim_float(f.weight),
        trim_float(f.confidence)
    ));
    out.push_str(&format!(
        "What happened: {} at {}.\n",
        f.summary,
        t(f.ts_ns)
    ));
    out.push_str("Why it is flagged:\n");
    for w in &f.why {
        out.push_str(&format!("  - {w}\n"));
    }
    if !f.benign.is_empty() {
        out.push_str(&format!(
            "Could be harmless if: {}.\n",
            f.benign.join("; or ")
        ));
    }
    let shown: Vec<String> = f
        .evidence_events
        .iter()
        .map(|e| format!("#{} {}", e.id, describe(e)))
        .collect();
    let more = f.evidence.len().saturating_sub(shown.len());
    let tail = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    out.push_str(&format!(
        "Evidence ({} events): {}{tail}\n",
        f.evidence.len(),
        shown.join(", ")
    ));
    out.push_str(&format!(
        "To silence: add to /etc/sysscope/allow.toml -> {}\n",
        Detector::silence_entry(&f.rule, &f.exe.escaped(), &f.subject)
    ));
    out
}

/// The explanation as terminal-safe text: each line is passed through
/// `display::safe_str` separately, so the only newlines are the ones the
/// renderer put there (a traced path can never inject a line).
pub fn render_safe(f: &Finding, ctx: &ExplainCtx) -> String {
    render(f, ctx)
        .lines()
        .map(crate::display::safe_str)
        .collect::<Vec<_>>()
        .join("\n")
}

/// 0.6 -> "0.6", 1.0 -> "1", 0.9000001 -> "0.9".
fn trim_float(v: f32) -> String {
    let s = format!("{:.2}", v);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}
