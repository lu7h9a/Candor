//! The Glasshouse report as text (plan 6.3) and the limitation statement
//! (plan 6.4), shared by the CLI, the helper and the GUI export.
//!
//! Everything that came from the sandbox (names, previews, arguments) is
//! untrusted and goes through `safe`/`safe_str` before it is printed (I10).

use crate::display::{safe, safe_str};
use sysscope_proto::{DecoyState, DecoyStatus, EventKind, GhReport};

/// Plan 6.4, verbatim.
pub use crate::explain::GLASSHOUSE_LIMITATION as LIMITATION;

/// Lower-case name of a decoy state.
pub fn state_name(s: DecoyState) -> &'static str {
    match s {
        DecoyState::Untouched => "untouched",
        DecoyState::Read => "read",
        DecoyState::Modified => "modified",
        DecoyState::Renamed => "renamed",
        DecoyState::Deleted => "deleted",
    }
}

/// "read, modified" or "unknown" for an empty list.
pub fn states_text(d: &DecoyStatus) -> String {
    if d.states.is_empty() {
        return "unknown".into();
    }
    d.states
        .iter()
        .map(|s| state_name(*s))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The entropy sentence of plan 6.3, or None if entropy did not rise much.
pub fn entropy_sentence(before: f32, after: f32) -> Option<String> {
    (after - before >= 1.0 && after >= 7.0).then(|| {
        format!(
            "entropy rose from {before:.1} to {after:.1} bits/byte, consistent with encryption or compression"
        )
    })
}

/// Counts used by the summary line and by tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Decoys read.
    pub read: usize,
    /// Decoys modified.
    pub modified: usize,
    /// Decoys renamed.
    pub renamed: usize,
    /// Decoys deleted.
    pub deleted: usize,
    /// New files.
    pub created: usize,
    /// Connection attempts.
    pub connects: u64,
}

/// Summary counts of a report.
pub fn counts(r: &GhReport) -> Counts {
    let has = |d: &DecoyStatus, s: DecoyState| d.states.contains(&s);
    Counts {
        read: r.decoys.iter().filter(|d| has(d, DecoyState::Read)).count(),
        modified: r
            .decoys
            .iter()
            .filter(|d| has(d, DecoyState::Modified))
            .count(),
        renamed: r
            .decoys
            .iter()
            .filter(|d| has(d, DecoyState::Renamed))
            .count(),
        deleted: r
            .decoys
            .iter()
            .filter(|d| has(d, DecoyState::Deleted))
            .count(),
        created: r.created.len(),
        connects: r.connections.iter().map(|c| c.count).sum(),
    }
}

/// The whole report as plain text, safe to print to a terminal.
pub fn render_text(r: &GhReport) -> String {
    let mut o = String::new();
    let c = counts(r);
    let args: Vec<String> = r.args.iter().map(safe).collect();
    o.push_str(&format!(
        "Glasshouse report {}\nsample: {}{}\n",
        safe_str(&r.run_id),
        safe(&r.sample),
        args.iter().map(|a| format!(" {a}")).collect::<String>()
    ));
    let secs = r.ended_ts.saturating_sub(r.started_ts) as f64 / 1e9;
    let end = if r.timed_out {
        format!("killed at the {} s timeout", r.timeout_s)
    } else {
        match r.exit_code {
            Some(code) => format!("exited with code {code}"),
            None => "ended by a signal".into(),
        }
    };
    o.push_str(&format!("ran {secs:.1} s, {end}\n"));
    o.push_str(&format!(
        "decoys: {} read, {} modified, {} renamed, {} deleted (of {}); {} new file(s); {} connection attempt(s)\n",
        c.read,
        c.modified,
        c.renamed,
        c.deleted,
        r.decoys.len(),
        c.created,
        c.connects
    ));
    o.push_str("\nDecoys touched (before -> after):\n");
    let touched: Vec<&DecoyStatus> = r
        .decoys
        .iter()
        .filter(|d| d.states != vec![DecoyState::Untouched])
        .collect();
    if touched.is_empty() {
        o.push_str("  none\n");
    }
    for d in touched {
        o.push_str(&format!("  {}  [{}]\n", safe(&d.path), states_text(d)));
        if let Some(n) = &d.new_path {
            o.push_str(&format!("      now named {}\n", safe(n)));
        }
        match (d.size_after, d.entropy_after) {
            (Some(size), Some(e)) => {
                o.push_str(&format!(
                    "      size {} -> {} bytes, entropy {:.1} -> {:.1} bits/byte\n",
                    d.size_before, size, d.entropy_before, e
                ));
                if let Some(s) = entropy_sentence(d.entropy_before, e) {
                    o.push_str(&format!("      {s}\n"));
                }
            }
            _ => o.push_str(&format!(
                "      size {} bytes before; gone after\n",
                d.size_before
            )),
        }
    }
    o.push_str("\nNew files:\n");
    if r.created.is_empty() {
        o.push_str("  none\n");
    }
    for f in &r.created {
        o.push_str(&format!(
            "  {} ({}, {} bytes, entropy {:.1})\n",
            safe(&f.path),
            safe_str(&f.kind),
            f.size,
            f.entropy
        ));
        if let Some(p) = &f.preview {
            for line in safe(p).split("\\x0A").filter(|l| !l.is_empty()).take(8) {
                o.push_str(&format!("      | {line}\n"));
            }
        }
    }
    o.push_str("\nConnection attempts:\n");
    if r.connections.is_empty() {
        o.push_str("  none\n");
    }
    for c in &r.connections {
        o.push_str(&format!(
            "  {}:{} x{} (the box has no network; attempts are observed, not delivered)\n",
            safe_str(&c.addr),
            c.port,
            c.count
        ));
    }
    o.push_str("\nFindings:\n");
    if r.findings.is_empty() {
        o.push_str("  none\n");
    }
    for f in &r.findings {
        o.push_str(&format!(
            "  {} {} - {}\n",
            safe_str(&f.rule),
            safe_str(&f.title),
            safe_str(&f.summary)
        ));
    }
    let execs = r
        .timeline
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Exec { .. }))
        .count();
    o.push_str(&format!(
        "\nTimeline: {} events, {} processes, {} programs started\n",
        r.timeline.len(),
        r.children.len(),
        execs
    ));
    let l = &r.loss;
    o.push_str(&format!(
        "Lost events during the run: ring buffer {}, budget {}, scratch {}, undecodable {}\n",
        l.ringbuf, l.budget, l.scratch, l.decode
    ));
    for n in &r.notes {
        o.push_str(&format!("Note: {}\n", safe_str(n)));
    }
    o.push_str(&format!("\n{LIMITATION}\n"));
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysscope_proto::{BStr, CreatedFile, Loss};

    fn report() -> GhReport {
        GhReport {
            run_id: "r1".into(),
            sample: BStr::from("x\u{1b}[31m.py"),
            args: vec![],
            timeout_s: 60,
            started_ts: 0,
            ended_ts: 2_000_000_000,
            exit_code: Some(0),
            timed_out: false,
            decoys: vec![DecoyStatus {
                path: BStr::from("/home/victim/Documents/a.docx"),
                dev: 1,
                ino: 2,
                states: vec![DecoyState::Modified, DecoyState::Renamed],
                new_path: Some(BStr::from("/home/victim/Documents/a.docx.locked")),
                size_before: 100,
                size_after: Some(100),
                entropy_before: 4.2,
                entropy_after: Some(7.9),
            }],
            created: vec![CreatedFile {
                path: BStr(b"/home/victim/R\nEADME".to_vec()),
                size: 5,
                entropy: 2.0,
                preview: Some(BStr::from("pay\n\u{1b}]0;x\u{7}")),
                kind: "file".into(),
            }],
            timeline: vec![],
            connections: vec![],
            children: vec![],
            findings: vec![],
            loss: Loss::default(),
            limitation: LIMITATION.into(),
            notes: vec![],
        }
    }

    #[test]
    fn limitation_is_the_plan_text_verbatim() {
        let plan = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/MASTER_PLAN.md"),
        )
        .unwrap();
        assert!(plan.contains(&format!("\"{LIMITATION}\"")));
    }

    #[test]
    fn report_text_is_escaped_and_complete() {
        let t = render_text(&report());
        assert!(!t.contains('\u{1b}') && !t.contains('\u{7}'), "{t}");
        assert!(t.contains(
            "entropy rose from 4.2 to 7.9 bits/byte, consistent with encryption or compression"
        ));
        assert!(t.contains("1 modified, 1 renamed"));
        assert!(t.ends_with(&format!("{LIMITATION}\n")));
        // The created file's newline does not start a new report line.
        assert!(!t.lines().any(|l| l.starts_with("EADME")));
    }
}
