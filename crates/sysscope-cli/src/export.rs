//! `sysscope export`: the process table and findings as JSON or CSV.
//!
//! Redaction (plan 9.2) is on by default; `--raw` turns it off and prints a
//! warning to stderr. Redaction is best effort, as the docs say.

use sysscope_core::display::safe;
use sysscope_core::redact::Redactor;
use sysscope_proto::{Finding, ProcRow};

/// The local names redaction hides: (home, user, host).
pub fn local_names() -> (String, String, String) {
    let home = std::env::var("HOME").unwrap_or_default();
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    (home, user, host)
}

/// One CSV cell: terminal-safe text, protected against spreadsheet formula
/// injection (a leading = + - @ gets a ' prefix), quoted when needed.
fn csv_field(s: &str) -> String {
    let mut s = sysscope_core::display::safe_str(s);
    if s.starts_with(['=', '+', '-', '@']) {
        s.insert(0, '\'');
    }
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// CSV of the process table.
pub fn csv(rows: &[ProcRow], r: &mut Option<Redactor>) -> String {
    let mut out = String::from(
        "pid,start_ticks,parent_pid,uid,exe,cpu_pct,rss,threads,opens,connects,execs,children,score,tree_score,top_rule,exited\n",
    );
    for p in rows {
        let exe = safe(&p.exe);
        let exe = match r {
            Some(r) => r.text(&exe),
            None => exe,
        };
        out.push_str(&format!(
            "{},{},{},{},{},{:.1},{},{},{},{},{},{},{},{},{},{}\n",
            p.key.tgid,
            p.key.start_ticks,
            p.parent.map(|k| k.tgid.to_string()).unwrap_or_default(),
            p.uid,
            csv_field(&exe),
            p.cpu_pct,
            p.rss,
            p.threads,
            p.n_open,
            p.n_conn,
            p.n_exec,
            p.n_child,
            p.score,
            p.tree_score,
            csv_field(p.top_rule.as_deref().unwrap_or("")),
            p.exited_ts.is_some()
        ));
    }
    out
}

/// JSON of the process table and findings (redacted unless `r` is None).
pub fn json(rows: &[ProcRow], findings: &[Finding], r: &mut Option<Redactor>) -> String {
    let procs: Vec<serde_json::Value> = rows
        .iter()
        .map(|p| {
            let exe = safe(&p.exe);
            serde_json::json!({
                "pid": p.key.tgid, "start_ticks": p.key.start_ticks, "private_view": p.private_view,
                "parent_pid": p.parent.map(|k| k.tgid), "uid": p.uid,
                "exe": match r { Some(r) => r.text(&exe), None => exe },
                "cpu_pct": p.cpu_pct, "rss": p.rss, "threads": p.threads,
                "opens": p.n_open, "connects": p.n_conn, "score": p.score,
                "tree_score": p.tree_score, "top_rule": p.top_rule.as_deref().map(sysscope_core::display::safe_str),
            })
        })
        .collect();
    let findings: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let mut text = |s: &str| match r {
                Some(r) => r.text(s),
                None => s.to_string(),
            };
            let summary = text(&f.summary);
            let title = text(&f.title);
            let subject = text(&f.subject);
            let why: Vec<String> = f.why.iter().map(|w| text(w)).collect();
            let exe = text(&safe(&f.exe));
            let events: Vec<serde_json::Value> = f
                .evidence_events
                .iter()
                .map(|e| {
                    let d = sysscope_core::explain::describe(e);
                    let argv = match &e.kind {
                        sysscope_proto::EventKind::Exec { argv, .. } => Some(safe(argv)),
                        _ => None,
                    };
                    let (d, argv) = match r {
                        Some(r) => (r.text(&d), argv.map(|a| r.argv(&a.replace("\\x00", "\0")))),
                        None => (d, argv),
                    };
                    serde_json::json!({"id": e.id, "what": d, "argv": argv})
                })
                .collect();
            serde_json::json!({
                "rule": sysscope_core::display::safe_str(&f.rule), "title": title, "subject": subject, "pid": f.proc.tgid,
                "exe": exe, "summary": summary, "why": why, "evidence": f.evidence,
                "evidence_events": events, "confidence": f.confidence, "weight": f.weight,
            })
        })
        .collect();
    crate::out::json(&serde_json::json!({"processes": procs, "findings": findings}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysscope_proto::{BStr, ProcKey};

    #[test]
    fn csv_cells_are_safe_and_formula_proof() {
        assert_eq!(csv_field("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(csv_field("@SUM"), "'@SUM");
        assert_eq!(
            csv_field("a\x1b[31m"),
            sysscope_core::display::safe_str("a\x1b[31m")
        );
        assert!(!csv_field("x\u{202e}y").contains('\u{202e}'));
        assert_eq!(csv_field("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_quotes_and_redacts() {
        let row = ProcRow {
            key: ProcKey {
                tgid: 7,
                start_ticks: 1,
            },
            exe: BStr::from("/home/anshul/bin/a,b"),
            ..ProcRow::default()
        };
        let mut r = Some(Redactor::new("/home/anshul", "anshul", "box", false));
        let text = csv(std::slice::from_ref(&row), &mut r);
        assert!(text.contains("\"~/bin/a,b\""), "{text}");
        let raw = csv(&[row], &mut None);
        assert!(raw.contains("/home/anshul/bin/a,b"));
    }
}
