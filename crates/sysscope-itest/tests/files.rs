//! WP06 file events: exact counts, (dev, ino) equal to stat, resolved paths,
//! truncation and hostile names (plan WP06 Verify).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sysscope_itest::{action, manifest_bytes, manifest_id, run_wl};
use sysscope_proto::{Event, EventKind};

fn opens_of(ev: &[Event], id: (u64, u64)) -> Vec<&Event> {
    ev.iter()
        .filter(|e| matches!(&e.kind, EventKind::Open { dev, ino, .. } if (*dev, *ino) == id))
        .collect()
}

#[test]
fn open_rename_unlink_exact_counts_and_identity() {
    let (m, ev) = run_wl(&[
        "open-read",
        "1000",
        "open-write",
        "500",
        "rename",
        "200",
        "unlink",
        "200",
    ])
    .unwrap();

    // open-read: exactly 1000 read-only opens of the target.
    let target = &action(&m, "open-read")["file"];
    let reads = opens_of(&ev, manifest_id(target))
        .into_iter()
        .filter(|e| {
            matches!(
                e.kind,
                EventKind::Open {
                    read: true,
                    write: false,
                    ..
                }
            )
        })
        .count();
    assert_eq!(reads, 1000);

    // open-write: each file exactly once, (dev, ino) and path equal to lstat.
    for f in action(&m, "open-write")["files"].as_array().unwrap() {
        let o = opens_of(&ev, manifest_id(f));
        assert_eq!(o.len(), 1, "{f}");
        match &o[0].kind {
            EventKind::Open {
                path,
                write,
                create,
                trunc,
                path_trunc,
                ..
            } => {
                assert!(*write && *create && *trunc && !*path_trunc);
                assert_eq!(path.as_bytes(), manifest_bytes(&f["path"]).as_slice());
            }
            _ => unreachable!(),
        }
    }

    // rename: 200 events, identity and both paths.
    let renames: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Rename { .. }))
        .collect();
    assert_eq!(renames.len(), 200);
    for f in action(&m, "rename")["files"].as_array().unwrap() {
        let hit = renames.iter().find(|e| matches!(&e.kind, EventKind::Rename { dev, ino, .. } if (*dev, *ino) == manifest_id(f)));
        match hit.map(|e| &e.kind) {
            Some(EventKind::Rename { old, new, .. }) => {
                assert_eq!(old.as_bytes(), manifest_bytes(&f["old"]).as_slice());
                assert_eq!(new.as_bytes(), manifest_bytes(&f["new"]).as_slice());
            }
            _ => panic!("no rename for {f}"),
        }
    }

    // unlink: 200 events, identity and path.
    let unlinks: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Unlink { .. }))
        .collect();
    assert_eq!(unlinks.len(), 200);
    for f in action(&m, "unlink")["files"].as_array().unwrap() {
        let hit = unlinks.iter().find(|e| matches!(&e.kind, EventKind::Unlink { dev, ino, .. } if (*dev, *ino) == manifest_id(f)));
        match hit.map(|e| &e.kind) {
            Some(EventKind::Unlink { path, .. }) => {
                assert_eq!(path.as_bytes(), manifest_bytes(&f["path"]).as_slice())
            }
            _ => panic!("no unlink for {f}"),
        }
    }
}

#[test]
fn long_path_is_flagged_truncated_with_leaf_name() {
    let (m, ev) = run_wl(&["longpath"]).unwrap();
    let f = &action(&m, "longpath")["file"];
    assert!(action(&m, "longpath")["len"].as_u64().unwrap() > 512);
    let o = opens_of(&ev, manifest_id(f));
    assert_eq!(o.len(), 1);
    match &o[0].kind {
        EventKind::Open {
            path, path_trunc, ..
        } => {
            assert!(*path_trunc);
            assert_eq!(path.as_bytes(), b"leaf-file");
        }
        _ => unreachable!(),
    }
}

#[test]
fn hostile_name_round_trips_through_bstr() {
    let (m, ev) = run_wl(&["badname"]).unwrap();
    let f = &action(&m, "badname")["file"];
    let want = manifest_bytes(&f["path"]);
    assert!(want.contains(&0xff) && want.contains(&b'\n') && want.contains(&0x1b));
    let o = opens_of(&ev, manifest_id(f));
    assert_eq!(o.len(), 1);
    let EventKind::Open { path, .. } = &o[0].kind else {
        unreachable!()
    };
    assert_eq!(path.as_bytes(), want.as_slice());
    // Through JSON and back, still the same bytes; escaped form has no raw controls.
    let json = serde_json::to_string(&o[0]).unwrap();
    let back: Event = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, o[0]);
    assert!(!path.escaped().bytes().any(|b| b < 0x20 || b == 0x7f));
}

#[test]
fn relative_and_symlink_opens_report_the_resolved_path() {
    let (m, ev) = run_wl(&["open-relative", "open-symlink"]).unwrap();
    for name in ["open-relative", "open-symlink"] {
        let f = &action(&m, name)["file"];
        let reads: Vec<_> = opens_of(&ev, manifest_id(f))
            .into_iter()
            .filter(|e| matches!(e.kind, EventKind::Open { write: false, .. }))
            .collect();
        assert_eq!(reads.len(), 1, "{name}");
        let EventKind::Open { path, .. } = &reads[0].kind else {
            unreachable!()
        };
        assert_eq!(
            path.as_bytes(),
            manifest_bytes(&f["path"]).as_slice(),
            "{name}"
        );
    }
}

#[test]
fn io_uring_open_is_observed() {
    let (m, ev) = run_wl(&["uring-open"]).unwrap();
    let a = action(&m, "uring-open");
    assert!(
        a["res"].as_i64().unwrap() >= 0,
        "io_uring open failed in wl: {a}"
    );
    let reads = opens_of(&ev, manifest_id(&a["file"]))
        .into_iter()
        .filter(|e| matches!(e.kind, EventKind::Open { write: false, .. }))
        .count();
    assert_eq!(reads, 1);
}
