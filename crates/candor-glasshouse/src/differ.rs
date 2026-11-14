//! The run-directory differ (plan 6.3).
//!
//! Runs as `candor-box`, never root. Walks `<run>/home` one directory at
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
use candor_proto::{BStr, CreatedFile, DecoyState, DecoyStatus};

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
    /// When decoys and baseline were recorded (wall-clock ns since the
    /// epoch). A file born later is new even if the filesystem reused the
    /// inode number of a deleted decoy or baseline file (WP31: inode reuse
    /// on ext4 made a deleted decoy look "modified, renamed").
    #[serde(default)]
    pub prepared_ns: Option<u64>,
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
    /// Birth time (statx btime, wall-clock ns) if the filesystem reports it.
    born_ns: Option<u64>,
    /// Other names of the same inode (hard links), at most a few.
    alt: Vec<Vec<u8>>,
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

/// Longest path kept per entry (deeper paths are cut and marked).
pub const MAX_PATH_KEPT: usize = 1024;
/// New entries listed in a report (the rest are counted in a note).
pub const MAX_CREATED: usize = 1000;

/// Opens `name` beneath `dir` without following links; if the sample made
/// it unreadable (it owns everything in the box home), restores owner
/// access once and says so in `repaired`.
fn open_beneath(
    dir: &OwnedFd,
    name: &std::ffi::CStr,
    flags: OFlags,
    owner_mode: u32,
    repaired: &mut usize,
) -> rustix::io::Result<OwnedFd> {
    let f = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY;
    match rustix::fs::openat(dir, name, f, Mode::empty()) {
        Err(rustix::io::Errno::ACCESS) => {
            // chmodat never follows a final symlink for us: the entry was
            // lstat'ed as a directory or regular file just before.
            let st = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
            let t = FileType::from_raw_mode(st.st_mode);
            if t != FileType::Directory && t != FileType::RegularFile {
                return Err(rustix::io::Errno::ACCESS);
            }
            let mode = (st.st_mode & 0o7777) | owner_mode;
            rustix::fs::chmodat(dir, name, Mode::from_raw_mode(mode), AtFlags::empty())?;
            *repaired += 1;
            rustix::fs::openat(dir, name, f, Mode::empty())
        }
        other => other,
    }
}

/// Birth time of `name` beneath `dir` (statx btime, not following a
/// symlink), or None if the filesystem does not report it.
fn born_ns(dir: &OwnedFd, name: &std::ffi::CStr) -> Option<u64> {
    use rustix::fs::{StatxFlags, statx};
    let x = statx(dir, name, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::BTIME).ok()?;
    if !StatxFlags::from_bits_retain(x.stx_mask).contains(StatxFlags::BTIME) {
        return None;
    }
    let secs = u64::try_from(x.stx_btime.tv_sec).ok()?;
    Some(
        secs.saturating_mul(1_000_000_000)
            .saturating_add(u64::from(x.stx_btime.tv_nsec)),
    )
}

/// Hashes up to `max` bytes of a regular file beneath `dir`. None if it
/// could not be read (it is then reported as unreadable, never "modified").
fn hash_file(
    dir: &OwnedFd,
    name: &std::ffi::CStr,
    ino: u64,
    max: u64,
    repaired: &mut usize,
) -> Option<(String, f64, Vec<u8>, bool)> {
    let fd = open_beneath(
        dir,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK,
        0o400,
        repaired,
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

/// One directory still to visit: its name and its parent (an index into
/// the node list). Directories are re-opened from the run root by this
/// chain, so the walk never holds more than a few descriptors at a time.
struct Node {
    parent: Option<usize>,
    name: Vec<u8>,
    depth: usize,
}

fn chain(nodes: &[Node], mut i: usize) -> Vec<&[u8]> {
    let mut v = Vec::new();
    while let Some(n) = nodes.get(i) {
        v.push(n.name.as_slice());
        match n.parent {
            Some(p) => i = p,
            None => break,
        }
    }
    v.reverse();
    v
}

/// "home/a/b/…" from a chain plus a leaf, cut at MAX_PATH_KEPT.
fn rel_of(comps: &[&[u8]], leaf: Option<&[u8]>) -> Vec<u8> {
    let mut r = Vec::new();
    for c in comps.iter().copied().chain(leaf) {
        if !r.is_empty() {
            r.push(b'/');
        }
        r.extend_from_slice(c);
        if r.len() > MAX_PATH_KEPT {
            r.truncate(MAX_PATH_KEPT);
            r.extend_from_slice("…".as_bytes());
            break;
        }
    }
    r
}

/// Opens the directory a node names, component by component from the run
/// root, never following a link.
fn open_node(run: &OwnedFd, comps: &[&[u8]], repaired: &mut usize) -> rustix::io::Result<OwnedFd> {
    let mut cur: Option<OwnedFd> = None;
    for c in comps {
        let name = std::ffi::CString::new(c.to_vec()).map_err(|_| rustix::io::Errno::INVAL)?;
        let base = cur.as_ref().unwrap_or(run);
        let next = open_beneath(
            base,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY,
            0o700,
            repaired,
        )?;
        cur = Some(next);
    }
    cur.ok_or(rustix::io::Errno::INVAL)
}

/// Walks `<run>/home`. Returns found entries by inode and whether the walk
/// saw everything (any error or cap makes it incomplete, with a note).
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
    let mut nodes = vec![Node {
        parent: None,
        name: b"home".to_vec(),
        depth: 0,
    }];
    let mut stack = vec![0usize];
    let mut entries = 0usize;
    let mut partial_hashes = 0usize;
    let mut repaired = 0usize;
    let mut problems = 0usize;
    let mut problem = |what: String, notes: &mut Vec<String>| {
        problems += 1;
        if problems <= 5 {
            notes.push(what);
        }
    };
    'outer: while let Some(ni) = stack.pop() {
        let owned: Vec<Vec<u8>> = chain(&nodes, ni).into_iter().map(<[u8]>::to_vec).collect();
        let comps: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let depth = nodes.get(ni).map(|n| n.depth).unwrap_or(0);
        let dir_rel = rel_of(&comps, None);
        let dir = match open_node(&run_fd, &comps, &mut repaired) {
            Ok(d) => d,
            Err(e) => {
                complete = false;
                problem(
                    format!(
                        "a directory could not be opened ({e}): {}",
                        BStr(sandbox_path(&dir_rel))
                    ),
                    notes,
                );
                continue;
            }
        };
        let Ok(mut it) = Dir::read_from(&dir) else {
            complete = false;
            problem(
                format!(
                    "a directory could not be listed: {}",
                    BStr(sandbox_path(&dir_rel))
                ),
                notes,
            );
            continue;
        };
        loop {
            let e = match it.next() {
                None => break,
                Some(Ok(e)) => e,
                Some(Err(e)) => {
                    complete = false;
                    problem(
                        format!(
                            "listing stopped early ({e}): {}",
                            BStr(sandbox_path(&dir_rel))
                        ),
                        notes,
                    );
                    break;
                }
            };
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
            let st = match rustix::fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => st,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(e) => {
                    complete = false;
                    problem(
                        format!(
                            "an entry could not be examined ({e}) in {}",
                            BStr(sandbox_path(&dir_rel))
                        ),
                        notes,
                    );
                    continue;
                }
            };
            let t = FileType::from_raw_mode(st.st_mode);
            match t {
                FileType::Directory => {
                    if depth + 1 > lim.max_depth {
                        problem(
                            format!(
                                "directories deeper than {} levels were not examined",
                                lim.max_depth
                            ),
                            notes,
                        );
                        complete = false;
                        continue;
                    }
                    nodes.push(Node {
                        parent: Some(ni),
                        name: nb.to_vec(),
                        depth: depth + 1,
                    });
                    stack.push(nodes.len() - 1);
                }
                FileType::RegularFile => {
                    if let Some(f) = found.get_mut(&st.st_ino) {
                        // A hard link to an inode already seen.
                        if f.alt.len() < 4 {
                            f.alt.push(rel_of(&comps, Some(nb)));
                        }
                        continue;
                    }
                    let (sha, ent, head) =
                        match hash_file(&dir, name, st.st_ino, lim.max_hash, &mut repaired) {
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
                            rel: rel_of(&comps, Some(nb)),
                            born_ns: born_ns(&dir, name),
                            alt: Vec::new(),
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
                            rel: rel_of(&comps, Some(nb)),
                            born_ns: born_ns(&dir, name),
                            alt: Vec::new(),
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
    if problems > 5 {
        notes.push(format!(
            "{} more problems while walking were not listed",
            problems - 5
        ));
    }
    if repaired > 0 {
        notes.push(format!(
            "{repaired} file(s) or directories had been made unreadable inside the box; the differ restored owner access to examine them"
        ));
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
            let same_name = std::iter::once(&f.rel)
                .chain(f.alt.iter())
                .any(|n| n.as_slice() == d.path.as_bytes());
            if !same_name {
                s.states.push(DecoyState::Renamed);
                s.new_path = Some(BStr(sandbox_path(&f.rel)));
            }
            match f.sha.as_deref() {
                // Unreadable: the content is unknown, so never "modified";
                // with no other state the decoy's state is unknown (empty).
                None => {}
                Some(h) => {
                    if h != d.sha256 {
                        s.states.insert(0, DecoyState::Modified);
                    }
                    s.size_after = Some(f.size);
                    s.entropy_after = Some(f32_of(f.entropy));
                    if s.states.is_empty() {
                        s.states.push(DecoyState::Untouched);
                    }
                }
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
    let (all, complete) = walk(run, lim, &mut out.notes);
    // Files born after the decoys and baseline were recorded are new, even
    // at an inode number a decoy or baseline file had (inode reuse).
    let fresh = |f: &Found| {
        input
            .prepared_ns
            .zip(f.born_ns)
            .is_some_and(|(prepared, born)| born > prepared)
    };
    let fresh_inos: std::collections::BTreeSet<u64> = all
        .iter()
        .filter(|(_, f)| fresh(f))
        .map(|(i, _)| *i)
        .collect();
    let found: BTreeMap<u64, Found> = all
        .iter()
        .filter(|(i, _)| !fresh_inos.contains(i))
        .map(|(i, f)| (*i, f.clone()))
        .collect();
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
            "{unknown} decoy(s) could not be fully examined (walk stopped early or file unreadable); their state is unknown"
        ));
    }
    for d in &input.manifest.decoys {
        if let Some(f) = found.get(&d.ino)
            && !f.alt.is_empty()
        {
            let other = std::iter::once(&f.rel)
                .chain(f.alt.iter())
                .find(|a| a.as_slice() != d.path.as_bytes())
                .unwrap_or(&f.rel);
            out.notes.push(format!(
                "decoy {} has {} extra name(s) (hard links), e.g. {}",
                BStr(d.sandbox_path.as_bytes().to_vec()),
                f.alt.len(),
                BStr(sandbox_path(other))
            ));
        }
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
    for (ino, f) in &all {
        if (decoy_inos.contains(ino) || baseline.contains_key(ino)) && !fresh_inos.contains(ino) {
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
    if out.created.len() > MAX_CREATED {
        out.notes.push(format!(
            "{} new entries; the first {MAX_CREATED} by name are listed",
            out.created.len()
        ));
        out.created.truncate(MAX_CREATED);
    }
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

    fn now_ns() -> Option<u64> {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        u64::try_from(d.as_nanos()).ok()
    }
    use crate::decoys;

    /// Scratch directory on a tmpfs when there is one (owner's choice E,
    /// WP32): real runs diff a fresh tmpfs, which does not reuse inode
    /// numbers within a run; a disk /tmp (CI's ext4) can give a new file the
    /// number of one just deleted, which made a deleted decoy look
    /// "modified, renamed" in ransomware_like_changes_are_classified.
    fn tmp(tag: &str) -> std::path::PathBuf {
        let shm = std::path::Path::new("/dev/shm");
        let base =
            if shm.is_dir() && std::fs::metadata(shm).is_ok_and(|m| !m.permissions().readonly()) {
                shm.to_path_buf()
            } else {
                std::env::temp_dir()
            };
        let d = base.join(format!("candor-differ-{tag}-{}", std::process::id()));
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
            prepared_ns: now_ns(),
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

    /// A file born after the decoys were recorded is new even at a decoy's
    /// inode number (simulated: prepared_ns before the decoys were made,
    /// so every decoy file looks newer than the record and none matches).
    #[test]
    fn files_born_after_the_record_never_match_a_decoy_inode() {
        let d = tmp("reuse");
        let before = now_ns().map(|n| n.saturating_sub(1_000_000_000));
        std::thread::sleep(std::time::Duration::from_millis(20));
        let m = decoys::generate(&d, Some(3)).unwrap();
        let born = std::fs::metadata(d.join(&m.decoys[0].path))
            .ok()
            .and_then(|x| x.created().ok());
        if born.is_none() {
            eprintln!("skipped: this filesystem reports no birth time");
            let _ = std::fs::remove_dir_all(&d);
            return;
        }
        let input = DiffInput {
            baseline: Vec::new(),
            manifest: m,
            prepared_ns: before,
        };
        let o = diff(&d, &input, Limits::default());
        // Every decoy in the writable home is "deleted" and its file is
        // reported as created: identity needs inode AND birth before the record.
        let home: Vec<_> = o
            .decoys
            .iter()
            .filter(|s| s.path.as_bytes().starts_with(b"/home/"))
            .collect();
        assert!(!home.is_empty());
        assert!(
            home.iter().all(|s| s.states == vec![DecoyState::Deleted]),
            "{home:?}"
        );
        assert!(o.created.len() >= home.len(), "{:?}", o.created);
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
            prepared_ns: now_ns(),
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
    fn hostile_trees_stay_bounded_and_honest() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("hostile");
        let m = decoys::generate(&d, Some(11)).unwrap();
        let input = DiffInput {
            baseline: Vec::new(),
            manifest: m,
            prepared_ns: now_ns(),
        };
        let h = d.join("home");
        // 3000 files with 255-byte non-UTF-8 names (5x larger when escaped).
        let many = h.join("many");
        std::fs::create_dir(&many).unwrap();
        for i in 0..3000u32 {
            let mut n = vec![0xffu8; 247];
            n.extend_from_slice(format!("{i:08}").as_bytes());
            std::fs::write(many.join(std::ffi::OsStr::from_bytes(&n)), "x").unwrap();
        }
        // A deep chain of 255-byte directory names (as deep as this test
        // process can create; the differ itself walks relative to parents).
        let mut deep = h.join("deep");
        std::fs::create_dir(&deep).unwrap();
        for _ in 0..40 {
            deep = deep.join("d".repeat(255));
            if std::fs::create_dir(&deep).is_err() {
                break;
            }
        }
        // A hard link to a decoy: a second name, not a rename.
        std::fs::hard_link(h.join("passwords.txt"), h.join("zz-link")).unwrap();
        // A directory and a decoy made unreadable by the sample.
        let docs = h.join("Documents");
        std::fs::set_permissions(
            h.join("Pictures/photo00.jpg"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o000)).unwrap();
        let o = diff(&d, &input, Limits::default());
        let json = serde_json::to_vec(&o).unwrap();
        assert!(json.len() < 4 << 20, "differ output {} bytes", json.len());
        assert_eq!(o.created.len(), MAX_CREATED);
        assert!(
            o.created
                .iter()
                .all(|c| c.path.as_bytes().len() <= MAX_PATH_KEPT + 32)
        );
        assert!(
            o.notes
                .iter()
                .any(|n| n.contains("the first 1000 by name are listed")),
            "{:?}",
            o.notes
        );
        assert!(
            o.notes.iter().any(|n| n.contains("restored owner access")),
            "{:?}",
            o.notes
        );
        assert!(
            o.notes
                .iter()
                .any(|n| n.contains("extra name(s) (hard links)")),
            "{:?}",
            o.notes
        );
        // Examined after the repair: nothing falsely "deleted" or "modified".
        assert!(
            !o.decoys
                .iter()
                .any(|s| s.states.contains(&DecoyState::Deleted)
                    || s.states.contains(&DecoyState::Modified)),
            "{:?}",
            o.decoys
                .iter()
                .map(|s| (&s.path, &s.states))
                .collect::<Vec<_>>()
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
            prepared_ns: now_ns(),
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
                prepared_ns: now_ns(),
            },
            Limits::default(),
        );
        assert_eq!(o2.created.len(), 1);
        assert_eq!(o2.created[0].kind, "fifo");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }
}
