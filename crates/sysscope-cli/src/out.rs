//! Text output: tables, the process tree, event lines, finding explanations.
//!
//! Every byte string from a traced process goes through
//! `sysscope_core::display::safe` before it is printed (I10), and JSON
//! output has C1 controls and bidi overrides turned into \u escapes, so no
//! output can drive the terminal.

use sysscope_core::detect::Band;
use sysscope_core::display::{safe, safe_str};
use sysscope_core::explain::{self, ExplainCtx};
use sysscope_proto::{DaemonMsg, Event, Finding, ProcKey, ProcRow};

pub use sysscope_core::display::json_safe;

/// Pretty JSON of any message, terminal-safe.
pub fn json<T: serde::Serialize>(v: &T) -> String {
    json_safe(&serde_json::to_string_pretty(v).unwrap_or_default())
}

/// "1.2 GiB" style size.
pub fn size(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < U.len() {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U.get(i).copied().unwrap_or("B"))
}

/// Band label for a score, with words (never colour alone).
pub fn band(score: u8) -> &'static str {
    match score {
        0 => "",
        1..=29 => "low",
        30..=59 => "SUSPICIOUS",
        _ => "HIGH",
    }
}

/// The process table.
pub fn table(rows: &[ProcRow], limit: usize) -> String {
    let mut s = format!(
        "{:>7} {:>6} {:>6} {:>10} {:>5} {:>6} {:>5} {:>5} {:>4} {:<10} {}\n",
        "PID", "USER", "CPU%", "MEM", "THR", "OPENS", "CONN", "CHILD", "SCR", "", "EXE"
    );
    for r in rows.iter().take(limit) {
        s.push_str(&format!(
            "{:>7} {:>6} {:>6.1} {:>10} {:>5} {:>6} {:>5} {:>5} {:>4} {:<10} {}{}\n",
            r.key.tgid,
            r.uid,
            r.cpu_pct,
            size(r.rss),
            r.threads,
            r.n_open,
            r.n_conn,
            r.n_child,
            r.score,
            band(r.score),
            if r.exe.as_bytes().is_empty() {
                format!("[{}]", safe(&r.comm))
            } else {
                safe(&r.exe)
            },
            if r.exited_ts.is_some() {
                " (exited)"
            } else {
                ""
            },
        ));
    }
    s
}

/// The process tree, children indented under parents.
pub fn tree(rows: &[ProcRow]) -> String {
    let mut out = String::new();
    let keys: std::collections::BTreeSet<_> = rows.iter().map(|r| r.key).collect();
    let roots: Vec<&ProcRow> = rows
        .iter()
        .filter(|r| r.parent.is_none_or(|p| !keys.contains(&p)))
        .collect();
    let mut stack: Vec<(&ProcRow, usize)> = roots.into_iter().rev().map(|r| (r, 0)).collect();
    // Children by parent, built once: the walk stays linear in the rows.
    let mut children: std::collections::BTreeMap<ProcKey, Vec<&ProcRow>> = Default::default();
    for c in rows {
        if let Some(p) = c.parent {
            children.entry(p).or_default().push(c);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    while let Some((r, depth)) = stack.pop() {
        if !seen.insert(r.key) {
            continue;
        }
        let name = if r.exe.as_bytes().is_empty() {
            format!("[{}]", safe(&r.comm))
        } else {
            safe(&r.exe)
        };
        let score = if r.tree_score > 0 {
            format!("  [tree score {} {}]", r.tree_score, band(r.tree_score))
        } else {
            String::new()
        };
        out.push_str(&format!(
            "{}{} {}{}\n",
            "  ".repeat(depth.min(40)),
            r.key.tgid,
            name,
            score
        ));
        let mut kids: Vec<&ProcRow> = children.get(&r.key).cloned().unwrap_or_default();
        kids.sort_by_key(|c| std::cmp::Reverse(c.key));
        for k in kids {
            stack.push((k, depth + 1));
        }
    }
    out
}

/// One line for an event.
pub fn event_line(e: &Event, boot_to_wall: u64) -> String {
    format!(
        "{} #{} pid {} {}",
        explain::clock(e.ts_ns, boot_to_wall, 0),
        e.id,
        e.proc.tgid,
        safe_str(&explain::describe(e))
    )
}

/// The full explanation of a finding (plan 5.6), terminal-safe.
pub fn finding(
    f: &Finding,
    row: Option<&ProcRow>,
    parent: Option<&ProcRow>,
    boot_to_wall: u64,
) -> String {
    let score = row.map(|r| r.score).unwrap_or(0);
    let band = match score {
        0 => Band::None,
        1..=29 => Band::Low,
        30..=59 => Band::Suspicious,
        _ => Band::High,
    };
    let ctx = ExplainCtx {
        score,
        band,
        start_ns: f.proc.start_ticks.saturating_mul(10_000_000),
        parent: parent.map(|p| (p.exe.clone(), p.key.tgid)),
        uid: row.map(|r| r.uid).unwrap_or(0),
        boot_to_wall_ns: boot_to_wall,
        tz_offset_s: 0,
    };
    explain::render_safe(f, &ctx)
}

/// Status summary from Welcome + Snapshot.
pub fn status(welcome: &DaemonMsg, snap: &DaemonMsg) -> String {
    let mut s = String::new();
    if let DaemonMsg::Welcome {
        daemon_version,
        kernel,
        features,
        act_enabled,
        ..
    } = welcome
    {
        s.push_str(&format!(
            "daemon {} on kernel {}\nfeatures: {}\nact mode: {}\n",
            safe_str(daemon_version),
            safe_str(kernel),
            safe_str(&features.join(", ")),
            if *act_enabled { "enabled" } else { "off" }
        ));
    }
    if let DaemonMsg::Snapshot {
        procs, loss, mode, ..
    } = snap
    {
        let live = procs.iter().filter(|p| p.exited_ts.is_none()).count();
        let flagged = procs.iter().filter(|p| p.score >= 30).count();
        let mode = match mode {
            sysscope_proto::Mode::System(_) => "system-wide".to_string(),
            sysscope_proto::Mode::Follow { follow } => format!("following pid {}", follow.tgid),
        };
        s.push_str(&format!("mode: {mode}\nprocesses: {live} live, {} tracked\nflagged (score >= 30): {flagged}\nlost events: ring buffer {}, budget {}, scratch {}, undecodable {}, untracked (process table full) {}\n",
            procs.len(), loss.ringbuf, loss.budget, loss.scratch, loss.decode, loss.untracked));
    }
    s
}
