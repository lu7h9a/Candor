//! Event-driven rules about processes (WP28):
//! R009 shell spawned by an unusual parent, R011 process injection attempt.

use super::{class_matches, vars};
use crate::config::Rules;
use crate::detect::Hit;
use crate::state::State;
use candor_proto::{BStr, Event, EventKind, ProcKey};

fn leaf(b: &BStr) -> String {
    let bytes = b.as_bytes();
    let name = bytes.rsplit(|&c| c == b'/').next().unwrap_or(bytes);
    BStr(name.to_vec()).to_string()
}

/// R009: a shell or script interpreter started by a document viewer,
/// browser, mail client or web server.
pub fn r009(rules: &Rules, st: &State, ev: &Event) -> Option<Hit> {
    let cfg = rules.rule("R009")?;
    let EventKind::Exec { exe, .. } = &ev.kind else {
        return None;
    };
    if !class_matches(&cfg.programs, &[], exe, None) {
        return None;
    }
    let parent = st.get(&st.get(&ev.proc)?.parent?)?;
    if !class_matches(&cfg.parents, &[], &parent.exe, None) {
        return None;
    }
    let (pname, prog) = (leaf(&parent.exe), leaf(exe));
    Some(Hit {
        rule: "R009".into(),
        proc: ev.proc,
        subject: pname.clone(),
        confidence: cfg.confidence? as f32,
        ts_ns: ev.ts_ns,
        evidence: vec![ev.clone()],
        summary: format!("{pname} (pid {}) started {exe}", parent.key.tgid),
        vars: vars(&[("parent", pname), ("program", prog)]),
        extra_why: Vec::new(),
    })
}

/// True if `k` is `ancestor` or below it in the process tree.
fn in_tree(st: &State, mut k: ProcKey, ancestor: ProcKey) -> bool {
    for _ in 0..4096 {
        if k == ancestor {
            return true;
        }
        match st.get(&k).and_then(|p| p.parent) {
            Some(p) => k = p,
            None => return false,
        }
    }
    false
}

/// R011: ptrace-level access (attach, /proc/<pid>/mem, process_vm_*)
/// to a process outside the caller's own tree, by a non-debugger.
pub fn r011(rules: &Rules, st: &State, ev: &Event) -> Option<Hit> {
    let cfg = rules.rule("R011")?;
    let EventKind::Ptrace {
        target,
        attach: true,
    } = &ev.kind
    else {
        return None;
    };
    if in_tree(st, *target, ev.proc) {
        return None; // a parent looking at its own child: normal
    }
    // The debugger exemption needs the verified, root-owned system
    // executable: a name alone is chosen by whoever wrote the program.
    let me = st.get(&ev.proc);
    if let Some(p) = me
        && p.exe_trusted
        && p.exe_system
        && class_matches(&cfg.debuggers, &[], &p.exe, None)
    {
        return None;
    }
    let texe = st
        .get(target)
        .map(|p| p.exe.to_string())
        .unwrap_or_else(|| "an unknown program".into());
    Some(Hit {
        rule: "R011".into(),
        proc: ev.proc,
        subject: format!("pid {}", target.tgid),
        confidence: cfg.confidence? as f32,
        ts_ns: ev.ts_ns,
        evidence: vec![ev.clone()],
        summary: format!(
            "asked for debugger-level access to pid {} ({texe})",
            target.tgid
        ),
        vars: vars(&[("target", format!("pid {} ({texe})", target.tgid))]),
        extra_why: Vec::new(),
    })
}
