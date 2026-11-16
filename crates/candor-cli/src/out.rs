//! Text output: tables, the process tree, event lines, finding explanations.
//!
//! Every byte string from a traced process goes through
//! `candor_core::display::safe` before it is printed (I10), and JSON
//! output has C1 controls and bidi overrides turned into \u escapes, so no
//! output can drive the terminal.

use crate::style::Style;
use candor_core::detect::Band;
use candor_core::display::{safe, safe_str};
use candor_core::explain::{self, ExplainCtx};
use candor_proto::{DaemonMsg, Event, Finding, ProcKey, ProcRow};

pub use candor_core::display::json_safe;

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

/// The process table: the same columns as before, with a leading marker
/// (`●` red for a finding, amber for worth a look), a dim header, names in
/// bright white, the followed process in teal and scores in band colours.
pub fn table(rows: &[ProcRow], limit: usize, st: Style) -> String {
    let mut s = st.dim(&format!(
        "  {:>7} {:>6} {:>6} {:>10} {:>5} {:>6} {:>5} {:>5} {:>4} {:<10} {}",
        "PID", "USER", "CPU%", "MEM", "THR", "OPENS", "CONN", "CHILD", "SCR", "", "EXE"
    ));
    s.push('\n');
    for r in rows.iter().take(limit) {
        let exe = if r.exe.as_bytes().is_empty() {
            format!("[{}]", safe(&r.comm))
        } else {
            candor_core::display::exe_shown(r)
        };
        let name = if r.followed {
            st.accent(&exe)
        } else {
            st.bright(&exe)
        };
        s.push_str(&format!(
            "{}{:>7} {:>6} {:>6.1} {:>10} {:>5} {:>6} {:>5} {:>5} {} {} {}{}\n",
            st.marker(r.score),
            r.key.tgid,
            r.uid,
            r.cpu_pct,
            size(r.rss),
            r.threads,
            r.n_open,
            r.n_conn,
            r.n_child,
            st.score(r.score, &format!("{:>4}", r.score)),
            st.score(r.score, &format!("{:<10}", band(r.score))),
            name,
            if r.exited_ts.is_some() {
                " (exited)"
            } else {
                ""
            },
        ));
    }
    s
}

/// The dim footer under `top`: "142 processes · 2 flagged · 0 events not
/// recorded".
pub fn footer(rows: &[ProcRow], lost: u64, st: Style) -> String {
    let flagged = rows.iter().filter(|r| r.score >= 30).count();
    st.dim(&format!(
        "{} processes · {flagged} flagged · {lost} events not recorded",
        rows.len()
    ))
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
            candor_core::display::exe_shown(r)
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

/// A finding for `candor findings` (spec 9): a title line, then three
/// indented labelled lines, then the evidence and how to silence it, dim.
pub fn finding_short(f: &Finding, row: Option<&ProcRow>, st: Style) -> String {
    let score = row.map(|r| r.score).unwrap_or(0);
    let one = |s: &str| safe_str(&s.replace(['\n', '\r'], " "));
    let exe = safe(&f.exe);
    // A finding always has its dot (red unless the process is only worth
    // a look), then the rule and title, the program and the score.
    let marker = if (30..60).contains(&score) {
        st.marker(score)
    } else {
        format!("{} ", st.alert("●"))
    };
    let score_text = if score > 0 {
        format!(
            " · {}",
            st.score(score, &format!("{} {score}", band(score)))
        )
    } else {
        String::new()
    };
    let mut o = format!(
        "{marker}{} · {} (pid {}){score_text}\n",
        st.bright(&format!("{} {}", one(&f.rule), one(&f.title))),
        exe,
        f.proc.tgid,
    );
    let why: Vec<String> = f.why.iter().map(|w| one(w)).collect();
    let benign: Vec<String> = f.benign.iter().map(|b| one(b)).collect();
    o.push_str(&format!(
        "    {} {}\n",
        st.dim("What happened:"),
        one(&f.summary)
    ));
    o.push_str(&format!(
        "    {} {}\n",
        st.dim("Why it is flagged:"),
        why.join("; ")
    ));
    o.push_str(&format!(
        "    {} {}\n",
        st.dim("Harmless explanation:"),
        if benign.is_empty() {
            "none known".to_string()
        } else {
            benign.join("; or ")
        }
    ));
    let ev: Vec<String> = f
        .evidence_events
        .iter()
        .map(|e| format!("#{} {}", e.id, safe_str(&explain::describe(e))))
        .collect();
    o.push_str(&st.dim(&format!(
        "    Evidence ({} events): {}",
        f.evidence.len(),
        ev.join(", ")
    )));
    o.push('\n');
    o.push_str(&st.dim(&format!(
        "    To silence: add to /etc/candor/allow.toml -> {}",
        safe_str(&candor_core::detect::Detector::silence_entry(
            &f.rule,
            &f.exe.escaped(),
            &f.subject
        ))
    )));
    o.push('\n');
    o
}

/// Status summary from Welcome + Snapshot.
pub fn status(welcome: &DaemonMsg, snap: &DaemonMsg) -> String {
    let mut s = String::new();
    if let DaemonMsg::Welcome {
        daemon_version,
        kernel,
        features,
        unavailable,
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
        for n in unavailable {
            s.push_str(&candor_core::display::feature_note(n));
            s.push('\n');
        }
    }
    if let DaemonMsg::Snapshot {
        procs, loss, mode, ..
    } = snap
    {
        let live = procs.iter().filter(|p| p.exited_ts.is_none()).count();
        let flagged = procs.iter().filter(|p| p.score >= 30).count();
        let mode = match mode {
            candor_proto::Mode::System(_) => "system-wide".to_string(),
            candor_proto::Mode::Follow { follow } => format!("following pid {}", follow.tgid),
        };
        s.push_str(&format!("mode: {mode}\nprocesses: {live} live, {} tracked\nflagged (score >= 30): {flagged}\nlost events: ring buffer {}, budget {}, scratch {}, undecodable {}, untracked (process table full) {}, skipped by the kernel {}\n",
            procs.len(), loss.ringbuf, loss.budget, loss.scratch, loss.decode, loss.untracked, loss.missed));
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use candor_proto::BStr;

    fn row(pid: u32, exe: &str, score: u8) -> ProcRow {
        ProcRow {
            key: ProcKey {
                tgid: pid,
                start_ticks: 1,
            },
            exe: BStr::from(exe),
            score,
            ..ProcRow::default()
        }
    }

    #[test]
    fn plain_table_has_markers_and_no_escape_codes() {
        let rows = vec![
            row(1, "/tmp/x", 82),
            row(2, "/usr/bin/curl", 41),
            row(3, "/bin/sh", 0),
        ];
        let t = table(&rows, 10, Style { color: false });
        assert!(!t.contains('\x1b'), "{t:?}");
        let lines: Vec<&str> = t.lines().collect();
        assert!(lines[0].contains("PID") && lines[0].contains("EXE"));
        assert!(lines[1].starts_with("● ") && lines[1].contains("HIGH"));
        assert!(lines[2].starts_with("● ") && lines[2].contains("SUSPICIOUS"));
        assert!(lines[3].starts_with("  "));
        // Columns line up: each PID ends under the D of the PID header.
        let end = lines[0].chars().position(|c| c == 'D').unwrap();
        for (l, pid) in lines[1..].iter().zip(['1', '2', '3']) {
            assert_eq!(l.chars().position(|c| c == pid), Some(end), "{l:?}");
        }
        let f = footer(&rows, 0, Style { color: false });
        assert_eq!(f, "3 processes · 2 flagged · 0 events not recorded");
    }

    #[test]
    fn coloured_table_colours_findings_red_and_names_bright() {
        let mut rows = vec![row(1, "/tmp/x", 82), row(2, "/bin/sh", 0)];
        rows[1].followed = true;
        let t = table(&rows, 10, Style { color: true });
        assert!(t.contains("\x1b[38;2;244;124;124m●"));
        assert!(t.contains("\x1b[1;97m/tmp/x"));
        assert!(t.contains("\x1b[38;2;45;212;191m/bin/sh"));
    }

    #[test]
    fn short_finding_has_a_title_and_three_labelled_lines() {
        let f = Finding {
            id: 1,
            rule: "R001".into(),
            title: "Credential file read".into(),
            subject: "ssh_keys".into(),
            attack: None,
            proc: ProcKey {
                tgid: 7,
                start_ticks: 1,
            },
            exe: BStr::from("/tmp/x"),
            ts_ns: 0,
            weight: 0.6,
            confidence: 0.9,
            summary: "opened ~/.ssh/id_ed25519".into(),
            why: vec!["this file holds a private SSH key".into()],
            benign: vec!["a backup tool".into()],
            evidence: vec![],
            evidence_events: vec![],
        };
        let r = row(7, "/tmp/x", 89);
        let s = finding_short(&f, Some(&r), Style { color: false });
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines[0].starts_with("● R001 Credential file read · /tmp/x (pid 7) · HIGH 89"));
        assert!(lines[1].starts_with("    What happened: "));
        assert!(lines[2].starts_with("    Why it is flagged: this file holds"));
        assert!(lines[3].starts_with("    Harmless explanation: a backup tool"));
        assert!(s.contains("To silence:"));
        assert!(!s.contains('\x1b'));
    }
}
