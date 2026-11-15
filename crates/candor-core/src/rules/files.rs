//! Event-driven rules about files and executables:
//! R001 credential read, R002 temp-dir exec, R003 fileless exec,
//! R004 persistence write, R012 decoy touched.

use super::{class_matches, vars};
use crate::config::{PathClass, Rules};
use crate::detect::Hit;
use crate::state::State;
use candor_proto::{BStr, Event, EventKind};
use std::collections::BTreeSet;

fn hit(rule: &str, ev: &Event, subject: &str, confidence: f64, summary: String) -> Hit {
    Hit {
        rule: rule.into(),
        proc: ev.proc,
        subject: subject.into(),
        confidence: confidence as f32,
        ts_ns: ev.ts_ns,
        evidence: vec![ev.clone()],
        summary,
        vars: Default::default(),
        extra_why: Vec::new(),
    }
}

/// The first class matching `path`. "~/" means the process's own home;
/// with `any_home` it also means every /home/<user> and /root, because a
/// credential file is one whoever reads it (root or another user).
fn find_class<'a>(
    classes: &'a [PathClass],
    path: &BStr,
    st: &State,
    ev: &Event,
    any_home: bool,
) -> Option<&'a PathClass> {
    let p = st.get(&ev.proc);
    classes.iter().find(|c| {
        class_matches(&c.paths, &c.exclude_suffix, path, p)
            || (any_home && class_matches(&c.paths, &c.exclude_suffix, path, None))
    })
}

/// R001: a credential file opened for reading.
pub fn r001(rules: &Rules, st: &State, ev: &Event) -> Option<Hit> {
    let cfg = rules.rule("R001")?;
    let EventKind::Open {
        path, read: true, ..
    } = &ev.kind
    else {
        return None;
    };
    let class = find_class(&rules.credentials, path, st, ev, true)?;
    let system = st.get(&ev.proc).is_some_and(|p| p.exe_system);
    let c = if system {
        cfg.confidence_system_exe?
    } else {
        cfg.confidence_untrusted_exe?
    };
    let mut h = hit(
        "R001",
        ev,
        &class.subject,
        c,
        format!("opened {path} for reading"),
    );
    h.vars = vars(&[
        ("subject", class.subject.clone()),
        ("subject_desc", class.desc.clone()),
    ]);
    if !system {
        h.extra_why
            .push("the program does not run from a root-owned system directory".into());
    }
    Some(h)
}

/// R002: exec from a writable temp location. `world_writable_dir` comes from
/// the daemon's check of the executable's directory (ExeMeta).
pub fn r002(rules: &Rules, ev: &Event, world_writable_dir: bool) -> Option<Hit> {
    let cfg = rules.rule("R002")?;
    let EventKind::Exec { exe, .. } = &ev.kind else {
        return None;
    };
    let bytes = exe.as_bytes();
    let dir = cfg
        .dirs
        .iter()
        .find(|d| bytes.starts_with(d.as_bytes()))
        .cloned()
        .or_else(|| {
            world_writable_dir.then(|| {
                let cut = bytes.iter().rposition(|&b| b == b'/').unwrap_or(0);
                let parent = bytes.get(..cut).unwrap_or(b"");
                format!("{}/", BStr::new(parent.to_vec()))
            })
        })?;
    let mut h = hit("R002", ev, &dir, cfg.confidence?, format!("started {exe}"));
    h.vars = vars(&[("dir", dir.clone())]);
    Some(h)
}

/// R003: exec of a file with no link on disk.
pub fn r003(rules: &Rules, ev: &Event) -> Option<Hit> {
    let cfg = rules.rule("R003")?;
    let EventKind::Exec {
        exe,
        fileless: true,
        ..
    } = &ev.kind
    else {
        return None;
    };
    Some(hit(
        "R003",
        ev,
        "fileless",
        cfg.confidence?,
        format!("started {exe} from memory"),
    ))
}

/// R004: write/create/truncate of, or rename into, a persistence location.
pub fn r004(rules: &Rules, st: &State, ev: &Event) -> Option<Hit> {
    let cfg = rules.rule("R004")?;
    let (path, summary) = match &ev.kind {
        EventKind::Open {
            path,
            write,
            create,
            trunc,
            ..
        } if *write || *create || *trunc => (path, format!("opened {path} for writing")),
        EventKind::Rename { old, new, .. } => (new, format!("renamed {old} to {new}")),
        _ => return None,
    };
    let class = find_class(&rules.persistence, path, st, ev, false)?;
    let c = if cfg.strong_subjects.contains(&class.subject) {
        cfg.confidence_strong?
    } else {
        cfg.confidence?
    };
    let mut h = hit("R004", ev, &class.subject, c, summary);
    h.vars = vars(&[
        ("subject", class.subject.clone()),
        ("subject_desc", class.desc.clone()),
    ]);
    Some(h)
}

/// R012: any open, rename or unlink of a decoy inode.
pub fn r012(rules: &Rules, decoys: &BTreeSet<(u64, u64)>, ev: &Event) -> Option<Hit> {
    let cfg = rules.rule("R012")?;
    let (dev, ino, write, summary) = match &ev.kind {
        EventKind::Open {
            path,
            dev,
            ino,
            write,
            create,
            trunc,
            ..
        } => (
            *dev,
            *ino,
            *write || *create || *trunc,
            format!("opened decoy {path}"),
        ),
        EventKind::Rename {
            old, new, dev, ino, ..
        } => (*dev, *ino, true, format!("renamed decoy {old} to {new}")),
        EventKind::Unlink { path, dev, ino, .. } => {
            (*dev, *ino, true, format!("deleted decoy {path}"))
        }
        _ => return None,
    };
    if !decoys.contains(&(dev, ino)) {
        return None;
    }
    let c = if write {
        cfg.confidence_write?
    } else {
        cfg.confidence_read?
    };
    Some(hit("R012", ev, "decoy", c, summary))
}
