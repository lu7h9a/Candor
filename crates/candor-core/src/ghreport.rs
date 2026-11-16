//! The Glasshouse report as text (plan 6.3) and the limitation statement
//! (plan 6.4), shared by the CLI, the helper and the GUI export.
//!
//! Everything that came from the sandbox (names, previews, arguments) is
//! untrusted and goes through `safe`/`safe_str` before it is printed (I10).

use crate::display::{safe, safe_str};
use candor_proto::{DecoyState, DecoyStatus, EventKind, GhReport};

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
/// Files changed by the run: decoys modified or renamed (each counted
/// once, even if both), plus new files.
pub fn changed_count(r: &GhReport) -> usize {
    r.decoys
        .iter()
        .filter(|d| {
            d.states.contains(&DecoyState::Modified) || d.states.contains(&DecoyState::Renamed)
        })
        .count()
        + r.created.len()
}

/// True for a decoy that stands for a secret (keys, tokens, passwords):
/// a read of one is shown in the alert colour.
pub fn is_secret(path: &str) -> bool {
    const MARKS: [&str; 9] = [
        "/.ssh/",
        "/.gnupg/",
        "/.aws/",
        "/.kube/",
        "/.docker/config",
        "password",
        "credential",
        "/.netrc",
        "id_",
    ];
    let p = path.to_lowercase();
    MARKS.iter().any(|m| p.contains(m))
}

fn join_words(parts: &[String], last: &str) -> String {
    match parts {
        [] => String::new(),
        [a] => a.clone(),
        [rest @ .., z] => format!("{} {last} {z}", rest.join(", ")),
    }
}

fn n_things(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("one {one}"),
        n => format!("{n} {many}"),
    }
}

/// The report in one or two plain sentences, from its counts (spec 7.3):
/// "It read a decoy SSH key and created one file. It did not delete
/// anything or try to reach the network."
pub fn summary_sentence(r: &GhReport) -> String {
    let c = counts(r);
    let read_secret = r
        .decoys
        .iter()
        .any(|d| d.states.contains(&DecoyState::Read) && is_secret(&safe(&d.path)));
    let ssh = r
        .decoys
        .iter()
        .any(|d| d.states.contains(&DecoyState::Read) && safe(&d.path).contains("/.ssh/"));
    let mut did = Vec::new();
    let mut didnt = Vec::new();
    if c.read > 0 {
        let what = if c.read == 1 && ssh {
            "a decoy SSH key".to_string()
        } else if c.read == 1 && read_secret {
            "a decoy secret".to_string()
        } else if read_secret {
            format!("{} decoy files including secrets", c.read)
        } else {
            n_things(c.read, "decoy file", "decoy files")
        };
        did.push(format!("read {what}"));
    } else {
        didnt.push("read any decoy".to_string());
    }
    let changed = changed_count(r) - c.created;
    if changed > 0 {
        did.push(format!(
            "changed {}",
            n_things(changed, "decoy file", "decoy files")
        ));
    } else {
        didnt.push("change any decoy".to_string());
    }
    if c.created > 0 {
        did.push(format!("created {}", n_things(c.created, "file", "files")));
    }
    if c.deleted > 0 {
        did.push(format!("deleted {}", n_things(c.deleted, "file", "files")));
    } else {
        didnt.push("delete anything".to_string());
    }
    if c.connects > 0 {
        let n = c.connects as usize;
        did.push(format!(
            "tried to reach the network {}",
            if n == 1 {
                "once".to_string()
            } else {
                format!("{n} times")
            }
        ));
    } else {
        didnt.push("try to reach the network".to_string());
    }
    let mut out = String::new();
    if !did.is_empty() {
        out.push_str(&format!("It {}.", join_words(&did, "and")));
    }
    if !didnt.is_empty() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("It did not {}.", join_words(&didnt, "or")));
    }
    out
}

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
    use candor_proto::{BStr, CreatedFile, Loss};

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
        // The plan's section 6.4 text is kept as a tracked fixture (the plan
        // itself is a local file, owner 2026-11-14); where the plan exists
        // it is compared too, so the fixture cannot drift from it (I13).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let fixture =
            std::fs::read_to_string(root.join("fixtures/core/glasshouse_limitation.txt")).unwrap();
        assert_eq!(fixture.trim_end_matches('\n'), LIMITATION);
        if let Ok(plan) = std::fs::read_to_string(root.join("docs/MASTER_PLAN.md")) {
            assert!(plan.contains(&format!("\"{LIMITATION}\"")));
        }
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

#[cfg(test)]
mod summary_tests {
    use super::*;
    use candor_proto::{BStr, ConnStat, CreatedFile, Family, Loss, SockType};

    fn decoy(path: &str, states: &[DecoyState]) -> DecoyStatus {
        DecoyStatus {
            path: BStr::from(path),
            dev: 1,
            ino: 1,
            states: states.to_vec(),
            new_path: None,
            size_before: 10,
            size_after: Some(10),
            entropy_before: 4.0,
            entropy_after: Some(4.0),
        }
    }

    fn report(decoys: Vec<DecoyStatus>, created: usize, connects: u64) -> GhReport {
        GhReport {
            run_id: "r".into(),
            sample: BStr::from("try.sh"),
            args: vec![],
            timeout_s: 30,
            started_ts: 0,
            ended_ts: 1,
            exit_code: Some(0),
            timed_out: false,
            decoys,
            created: (0..created)
                .map(|i| CreatedFile {
                    path: BStr::from(format!("/home/u/n{i}").as_str()),
                    size: 1,
                    entropy: 1.0,
                    preview: None,
                    kind: "text".into(),
                })
                .collect(),
            timeline: vec![],
            connections: if connects > 0 {
                vec![ConnStat {
                    family: Family::Inet,
                    addr: "10.0.0.1".into(),
                    port: 443,
                    sock: SockType::Stream,
                    count: connects,
                    last_ts: 1,
                }]
            } else {
                vec![]
            },
            children: vec![],
            findings: vec![],
            loss: Loss::default(),
            limitation: String::new(),
            notes: vec![],
        }
    }

    #[test]
    fn the_spec_example() {
        let r = report(
            vec![
                decoy("/home/u/.ssh/id_ed25519", &[DecoyState::Read]),
                decoy("/home/u/Documents/a.txt", &[DecoyState::Untouched]),
            ],
            1,
            0,
        );
        assert_eq!(
            summary_sentence(&r),
            "It read a decoy SSH key and created one file. It did not change any decoy, delete anything or try to reach the network."
        );
    }

    #[test]
    fn nothing_touched() {
        let r = report(vec![decoy("/home/u/a", &[DecoyState::Untouched])], 0, 0);
        assert_eq!(
            summary_sentence(&r),
            "It did not read any decoy, change any decoy, delete anything or try to reach the network."
        );
    }

    #[test]
    fn everything_with_plurals() {
        let r = report(
            vec![
                decoy(
                    "/home/u/Documents/a",
                    &[DecoyState::Read, DecoyState::Modified],
                ),
                decoy(
                    "/home/u/Documents/b",
                    &[DecoyState::Read, DecoyState::Deleted],
                ),
                decoy("/home/u/Photos/c", &[DecoyState::Renamed]),
                // Modified and renamed: one changed file, not two.
                decoy(
                    "/home/u/Photos/d",
                    &[DecoyState::Modified, DecoyState::Renamed],
                ),
            ],
            2,
            3,
        );
        assert_eq!(
            summary_sentence(&r),
            "It read 2 decoy files, changed 3 decoy files, created 2 files, deleted one file and tried to reach the network 3 times."
        );
    }

    #[test]
    fn secrets_are_named() {
        assert!(is_secret("/home/u/.ssh/id_rsa") && is_secret("/home/u/.aws/credentials"));
        assert!(!is_secret("/home/u/Documents/report.txt"));
        let r = report(
            vec![
                decoy("/home/u/.aws/credentials", &[DecoyState::Read]),
                decoy("/home/u/Photos/p.jpg", &[DecoyState::Read]),
            ],
            0,
            1,
        );
        assert!(summary_sentence(&r).starts_with(
            "It read 2 decoy files including secrets and tried to reach the network once."
        ));
    }
}
