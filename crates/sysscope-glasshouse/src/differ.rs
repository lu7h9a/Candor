//! The run-directory differ (plan 6.3).
//!
//! Runs as `sysscope-box`, never root. Walks `<run>/home` one directory at
//! a time with `openat(O_NOFOLLOW | O_DIRECTORY)` relative to the parent's
//! descriptor, so a symlink planted by the sample is never followed (the
//! RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS property, built per component).
//! Only `lstat` is used for listing; only regular files are opened (with
//! O_NOFOLLOW | O_NONBLOCK, and the inode re-checked with fstat). Caps:
//! 20 000 entries, 64 MiB hashed per file, 30 s in total.
//!
//! Decoys are matched by inode: same inode under another name is
//! "renamed", a changed hash is "modified", a missing inode is "deleted".
//! Regular files whose inode is neither a decoy nor in the pre-run baseline
//! are "created". Other new entries are listed by type, never opened.

use crate::decoys::{DecoyEntry, Manifest, entropy, sha256_hex};
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::{Duration, Instant};
use sysscope_proto::{BStr, CreatedFile, DecoyState, DecoyStatus};

/// A non-decoy file present before the run (e.g. a plain `.bashrc`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Path relative to the run directory.
    pub path: String,
    /// Inode.
    pub ino: u64,
    /// SHA-256, lower-case hex.
    pub sha256: String,
}

/// What the root helper hands the differ on stdin.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DiffInput {
    /// The decoys.
    pub manifest: Manifest,
    /// Other files that existed before the run.
    pub baseline: Vec<BaselineEntry>,
}

/// The differ's caps.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Entries examined at most.
    pub max_entries: usize,
    /// Bytes hashed per file at most.
    pub max_hash: u64,
    /// Total time.
    pub max_time: Duration,
    /// Directory depth.
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_entries: 20_000,
            max_hash: 64 * 1024 * 1024,
            max_time: Duration::from_secs(30),
            max_depth: 64,
        }
    }
}

/// The differ's result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DiffOutput {
    /// One entry per decoy.
    pub decoys: Vec<DecoyStatus>,
    /// New entries.
    pub created: Vec<CreatedFile>,
    /// Caps reached, changed non-decoy files.
    pub notes: Vec<String>,
}

/// One entry found by the walk.
#[derive(Clone, Debug)]
struct Found {
    rel: Vec<u8>,
    kind: &'static str,
    size: u64,
    sha: Option<String>,
    entropy: f64,
    head: Vec<u8>,
}

/// Where the sample sees a run-relative path.
pub fn sandbox_path(rel: &[u8]) -> Vec<u8> {
    if let Some(rest) = rel.strip_prefix(b"home/") {
        let mut p = b"/home/victim/".to_vec();
        p.extend_from_slice(rest);
        p
    } else if rel == b"home" {
        b"/home/victim".to_vec()
    } else {
        let mut p = b"/".to_vec();
        p.extend_from_slice(rel);
        p
    }
}

fn kind_of(t: FileType) -> &'static str {
    match t {
        FileType::RegularFile => "file",
        FileType::Directory => "dir",
        FileType::Symlink => "symlink",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
        FileType::CharacterDevice | FileType::BlockDevice => "device",
        _ => "other",
    }
}

/// Hashes up to `max` bytes of a regular file opened beneath `dir`.
fn hash_file(
    dir: &OwnedFd,
    name: &std::ffi::CStr,
    ino: u64,
    max: u64,
) -> Option<(String, f64, Vec<u8>, bool)> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .ok()?;
    let st = rustix::fs::fstat(&fd).ok()?;
    if st.st_ino != ino || FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return None; // replaced between lstat and open
    }
    let mut data = Vec::new();
    let mut f = std::fs::File::from(fd).take(max);
    f.read_to_end(&mut data).ok()?;
    let partial = (st.st_size as u64) > max;
    let mut h = Sha256::new();
    h.update(&data);
    let sha: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let head = data.get(..256).unwrap_or(&data).to_vec();
    Some((sha, entropy(&data), head, partial))
}

/// Walks `<run>/home`. Returns found entries by inode and notes.
fn walk(
    run: &std::path::Path,
    lim: Limits,
    notes: &mut Vec<String>,
) -> (BTreeMap<u64, Found>, bool) {
    let started = Instant::now();
    let mut found = BTreeMap::new();
    let mut complete = true;
    let Ok(run_fd) = rustix::fs::open(
        run,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        notes.push("the run directory could not be opened".into());
        return (found, false);
    };
    let Ok(home) = rustix::fs::openat(
        &run_fd,
        c"home",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        notes.push("the sandbox home directory is missing or was replaced".into());
        return (found, false);
    };
    let mut stack: Vec<(OwnedFd, Vec<u8>, usize)> = vec![(home, b"home".to_vec(), 0)];
    let mut entries = 0usize;
    let mut partial_hashes = 0usize;
    'outer: while let Some((dir, rel, depth)) = stack.pop() {
        let Ok(mut it) = Dir::read_from(&dir) else {
            notes.push(format!(
                "a directory could not be listed: {}",
                BStr(sandbox_path(&rel))
            ));
            complete = false;
            continue;
        };
        while let Some(Ok(e)) = it.next() {
            let name = e.file_name();
            let nb = name.to_bytes();
            if nb == b"." || nb == b".." {
                continue;
            }
            entries += 1;
            if entries > lim.max_entries {
                notes.push(format!(
                    "differ stopped at {} entries; files beyond were not examined",
                    lim.max_entries
                ));
                complete = false;
                break 'outer;
            }
            if started.elapsed() > lim.max_time {
                notes.push(format!(
                    "differ stopped after {} s; files beyond were not examined",
                    lim.max_time.as_secs()
                ));
                complete = false;
                break 'outer;
            }
            let Ok(st) = rustix::fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) else {
                continue; // vanished
            };
            let t = FileType::from_raw_mode(st.st_mode);
            let mut child_rel = rel.clone();
            child_rel.push(b'/');
            child_rel.extend_from_slice(nb);
            match t {
                FileType::Directory => {
                    if depth + 1 > lim.max_depth {
                        notes.push(format!(
                            "directories deeper than {} levels were not examined",
                            lim.max_depth
                        ));
                        complete = false;
                        continue;
                    }
                    if let Ok(sub) = rustix::fs::openat(
                        &dir,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        stack.push((sub, child_rel, depth + 1));
                    }
                }
                FileType::RegularFile => {
                    let (sha, ent, head) = match hash_file(&dir, name, st.st_ino, lim.max_hash) {
                        Some((s, e, h, partial)) => {
                            if partial {
                                partial_hashes += 1;
                            }
                            (Some(s), e, h)
                        }
                        None => (None, 0.0, Vec::new()),
                    };
                    found.insert(
                        st.st_ino,
                        Found {
                            rel: child_rel,
                            kind: "file",
                            size: st.st_size as u64,
                            sha,
                            entropy: ent,
                            head,
                        },
                    );
                }
                other => {
                    found.insert(
                        st.st_ino,
                        Found {
                            rel: child_rel,
                            kind: kind_of(other),
                            size: st.st_size as u64,
                            sha: None,
                            entropy: 0.0,
                            head: Vec::new(),
                        },
                    );
                }
            }
        }
    }
    if partial_hashes > 0 {
        notes.push(format!(
            "{partial_hashes} file(s) larger than {} MiB were hashed only in part",
            lim.max_hash / (1024 * 1024)
        ));
    }
    (found, complete)
}

fn printable(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|&c| (0x20..0x7f).contains(&c) || c == b'\n' || c == b'\t')
}

fn f32_of(x: f64) -> f32 {
    // Two decimals are all the report shows.
    ((x * 100.0).round() / 100.0) as f32
}

fn status_of(d: &DecoyEntry, found: &BTreeMap<u64, Found>, complete: bool) -> DecoyStatus {
    let mut s = DecoyStatus {
        path: BStr(d.sandbox_path.as_bytes().to_vec()),
        dev: d.dev,
        ino: d.ino,
        states: Vec::new(),
        new_path: None,
        size_before: d.size,
        size_after: None,
        entropy_before: f32_of(d.entropy),
        entropy_after: None,
    };
    if !d.path.starts_with("home/") {
        // Outside the writable home (e.g. /etc/shadow, bound read-only):
        // only the trace can say it was read.
        s.states.push(DecoyState::Untouched);
        s.size_after = Some(d.size);
        s.entropy_after = Some(s.entropy_before);
        return s;
    }
    match found.get(&d.ino) {
        Some(f) if f.kind == "file" => {
            if f.rel != d.path.as_bytes() {
                s.states.push(DecoyState::Renamed);
                s.new_path = Some(BStr(sandbox_path(&f.rel)));
            }
            if f.sha.as_deref() != Some(d.sha256.as_str()) {
                s.states.insert(0, DecoyState::Modified);
            }
            s.size_after = Some(f.size);
            s.entropy_after = Some(f32_of(f.entropy));
            if s.states.is_empty() {
                s.states.push(DecoyState::Untouched);
            }
        }
        // Same inode number but no longer a regular file: the decoy is gone.
        Some(_) => s.states.push(DecoyState::Deleted),
        None if complete => s.states.push(DecoyState::Deleted),
        None => {} // unknown: the walk stopped early (states left empty)
    }
    s
}

/// Compares the run directory with the manifest and baseline.
pub fn diff(run: &std::path::Path, input: &DiffInput, lim: Limits) -> DiffOutput {
    let mut out = DiffOutput::default();
    let (found, complete) = walk(run, lim, &mut out.notes);
    let decoy_inos: std::collections::BTreeSet<u64> =
        input.manifest.decoys.iter().map(|d| d.ino).collect();
    out.decoys = input
        .manifest
        .decoys
        .iter()
        .map(|d| status_of(d, &found, complete))
        .collect();
    let unknown = out.decoys.iter().filter(|d| d.states.is_empty()).count();
    if unknown > 0 {
        out.notes.push(format!(
            "{unknown} decoy(s) were not found before the differ stopped; their state is unknown"
        ));
    }
    let baseline: BTreeMap<u64, &BaselineEntry> =
        input.baseline.iter().map(|b| (b.ino, b)).collect();
    for b in &input.baseline {
        match found.get(&b.ino) {
            Some(f)
                if f.sha.as_deref() != Some(b.sha256.as_str()) || f.rel != b.path.as_bytes() =>
            {
                out.notes.push(format!(
                    "pre-existing non-decoy file changed: {}",
                    BStr(sandbox_path(b.path.as_bytes()))
                ));
            }
            None if complete => out.notes.push(format!(
                "pre-existing non-decoy file deleted: {}",
                BStr(sandbox_path(b.path.as_bytes()))
            )),
            _ => {}
        }
    }
    for (ino, f) in &found {
        if decoy_inos.contains(ino) || baseline.contains_key(ino) {
            continue;
        }
        out.created.push(CreatedFile {
            path: BStr(sandbox_path(&f.rel)),
            size: f.size,
            entropy: f32_of(f.entropy),
            preview: (f.kind == "file" && printable(&f.head)).then(|| BStr(f.head.clone())),
            kind: f.kind.to_string(),
        });
    }
    out.created
        .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    out
}

/// Every decoy as "untouched" (the live view before anything happened).
pub fn initial_status(m: &Manifest) -> Vec<DecoyStatus> {
    m.decoys
        .iter()
        .map(|d| DecoyStatus {
            path: BStr(d.sandbox_path.as_bytes().to_vec()),
            dev: d.dev,
            ino: d.ino,
            states: vec![DecoyState::Untouched],
            new_path: None,
            size_before: d.size,
            size_after: None,
            entropy_before: f32_of(d.entropy),
            entropy_after: None,
        })
        .collect()
}

/// Records every regular file under `<run>/home` that is not a decoy (the
/// helper calls this, as root, right after preparing the run).
pub fn baseline(run: &std::path::Path, manifest: &Manifest) -> Vec<BaselineEntry> {
    let decoys: std::collections::BTreeSet<u64> = manifest.decoys.iter().map(|d| d.ino).collect();
    let mut notes = Vec::new();
    let (found, _) = walk(run, Limits::default(), &mut notes);
    found
        .into_iter()
        .filter(|(ino, f)| f.kind == "file" && !decoys.contains(ino))
        .map(|(ino, f)| BaselineEntry {
            path: String::from_utf8_lossy(&f.rel).into_owned(),
            ino,
            sha256: f.sha.unwrap_or_else(|| sha256_hex(b"")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoys;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sysscope-differ-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn by_path<'a>(o: &'a DiffOutput, p: &str) -> &'a DecoyStatus {
        o.decoys
            .iter()
            .find(|d| d.path.as_bytes() == p.as_bytes())
            .unwrap()
    }

    #[test]
    fn untouched_run_reports_nothing() {
        let d = tmp("clean");
        let m = decoys::generate(&d, Some(5)).unwrap();
        std::fs::write(d.join("home/.bashrc"), "# plain\n").unwrap();
        let input = DiffInput {
            baseline: baseline(&d, &m),
            manifest: m,
        };
        assert_eq!(input.baseline.len(), 1);
        let o = diff(&d, &input, Limits::default());
        assert!(o.created.is_empty(), "{:?}", o.created);
        assert!(o.notes.is_empty(), "{:?}", o.notes);
        assert!(
            o.decoys
                .iter()
                .all(|s| s.states == vec![DecoyState::Untouched])
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ransomware_like_changes_are_classified() {
        let d = tmp("ransom");
        let m = decoys::generate(&d, Some(6)).unwrap();
        std::fs::write(d.join("home/.bashrc"), "# plain\n").unwrap();
        let input = DiffInput {
            baseline: baseline(&d, &m),
            manifest: m,
        };
        let h = d.join("home");
        // Encrypt in place, then rename (same inode).
        let doc = h.join("Documents/file00.docx");
        let mut data = std::fs::read(&doc).unwrap();
        let mut rng = decoys::Rng::new(9);
        for b in data.iter_mut() {
            *b ^= (rng.next_u64() & 0xff) as u8;
        }
        std::fs::write(&doc, &data).unwrap();
        std::fs::rename(&doc, h.join("Documents/file00.docx.locked")).unwrap();
        std::fs::remove_file(h.join("Pictures/photo00.jpg")).unwrap();
        std::fs::write(h.join("README_RESTORE.txt"), "pay up (demo)\n").unwrap();
        std::fs::write(h.join(".bashrc"), "# plain\nevil\n").unwrap();
        // A symlink to a host file is listed, never followed.
        std::os::unix::fs::symlink("/etc/passwd", h.join("link")).unwrap();
        let o = diff(&d, &input, Limits::default());
        let doc_s = by_path(&o, "/home/victim/Documents/file00.docx");
        assert_eq!(
            doc_s.states,
            vec![DecoyState::Modified, DecoyState::Renamed]
        );
        assert_eq!(
            doc_s.new_path.as_ref().unwrap().as_bytes(),
            b"/home/victim/Documents/file00.docx.locked"
        );
        assert!(doc_s.entropy_after.unwrap() > doc_s.entropy_before + 1.0);
        assert_eq!(
            by_path(&o, "/home/victim/Pictures/photo00.jpg").states,
            vec![DecoyState::Deleted]
        );
        assert_eq!(
            by_path(&o, "/etc/shadow").states,
            vec![DecoyState::Untouched]
        );
        let names: Vec<(String, String)> = o
            .created
            .iter()
            .map(|c| (c.path.to_string(), c.kind.clone()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("/home/victim/README_RESTORE.txt".into(), "file".into()),
                ("/home/victim/link".into(), "symlink".into()),
            ]
        );
        assert_eq!(
            o.created[0].preview.as_ref().unwrap().as_bytes(),
            b"pay up (demo)\n"
        );
        assert!(o.created[1].preview.is_none());
        assert_eq!(
            o.notes,
            vec!["pre-existing non-decoy file changed: /home/victim/.bashrc".to_string()]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn caps_stop_the_walk_and_say_so() {
        let d = tmp("caps");
        let m = decoys::generate(&d, Some(7)).unwrap();
        let input = DiffInput {
            baseline: Vec::new(),
            manifest: m,
        };
        for i in 0..50 {
            std::fs::write(d.join(format!("home/junk{i}")), "x").unwrap();
        }
        let lim = Limits {
            max_entries: 20,
            ..Limits::default()
        };
        let o = diff(&d, &input, lim);
        assert!(
            o.notes.iter().any(|n| n.contains("stopped at 20 entries")),
            "{:?}",
            o.notes
        );
        // Nothing may be called deleted when the walk was incomplete.
        assert!(
            !o.decoys
                .iter()
                .any(|s| s.states.contains(&DecoyState::Deleted))
        );
        assert!(o.created.len() <= 20);
        // A FIFO is listed by type and never opened (opening would block).
        let d2 = tmp("fifo");
        let m2 = decoys::generate(&d2, Some(8)).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            d2.join("home/pipe"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let o2 = diff(
            &d2,
            &DiffInput {
                baseline: Vec::new(),
                manifest: m2,
            },
            Limits::default(),
        );
        assert_eq!(o2.created.len(), 1);
        assert_eq!(o2.created[0].kind, "fifo");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }
}
