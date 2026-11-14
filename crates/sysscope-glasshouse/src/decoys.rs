//! Decoy files for a Glasshouse run and their manifest (plan 6.2, 6.3, WP22).
//!
//! Every decoy is fake and generated fresh for each run: nothing is copied
//! from the host. The manifest records each decoy's path, (dev, ino), size,
//! SHA-256, Shannon entropy and mode, so the differ can later tell which
//! decoys were read, modified, renamed or deleted. With a seed the output is
//! byte-for-byte reproducible (tests); without one the SSH key comes from
//! `ssh-keygen` and other content from the seed derived from the clock.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Why decoy generation failed.
#[derive(Debug, thiserror::Error)]
pub enum DecoyError {
    /// File system error.
    #[error("{path}: {err}")]
    Io {
        /// The file.
        path: String,
        /// The error.
        err: String,
    },
    /// ssh-keygen failed.
    #[error("ssh-keygen failed: {0}")]
    Keygen(String),
}

/// One decoy in the manifest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecoyEntry {
    /// Path relative to the run directory, e.g. "home/.ssh/id_ed25519".
    pub path: String,
    /// Where the sample sees it, e.g. "/home/victim/.ssh/id_ed25519".
    pub sandbox_path: String,
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256, lower-case hex.
    pub sha256: String,
    /// Shannon entropy in bits per byte.
    pub entropy: f64,
    /// File mode bits.
    pub mode: u32,
}

/// All decoys of one run.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version (1).
    pub version: u32,
    /// The decoys.
    pub decoys: Vec<DecoyEntry>,
}

/// Small deterministic generator (SplitMix64): enough for fake content.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// A generator from a seed.
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `n` random bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n + 8);
        while v.len() < n {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(n);
        v
    }

    /// A number in 0..n.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// Shannon entropy of bytes, in bits per byte (0 for empty input).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        if let Some(c) = counts.get_mut(usize::from(b)) {
            *c += 1;
        }
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// SHA-256 of bytes as lower-case hex.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

const WORDS: &[&str] = &[
    "quarterly",
    "budget",
    "meeting",
    "notes",
    "project",
    "invoice",
    "travel",
    "plan",
    "report",
    "draft",
    "summary",
    "review",
    "client",
    "contract",
    "schedule",
    "team",
];

fn words(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        let w = WORDS
            .get(rng.below(WORDS.len() as u64) as usize)
            .copied()
            .unwrap_or("x");
        out.extend_from_slice(w.as_bytes());
        out.push(if i % 12 == 11 { b'\n' } else { b' ' });
    }
    out
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = ((n >> (18 - 6 * i)) & 63) as usize;
                s.push(char::from(A.get(idx).copied().unwrap_or(b'A')));
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// A fake key in OpenSSH PEM framing (seeded mode; never a usable key).
fn fake_ssh_key(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
    let body = b64(&rng.bytes(300));
    let mut private = b"-----BEGIN OPENSSH PRIVATE KEY-----\n".to_vec();
    for line in body.as_bytes().chunks(70) {
        private.extend_from_slice(line);
        private.push(b'\n');
    }
    private.extend_from_slice(b"-----END OPENSSH PRIVATE KEY-----\n");
    let public = format!("ssh-ed25519 {} victim@glasshouse\n", b64(&rng.bytes(51))).into_bytes();
    (private, public)
}

/// A fresh throwaway key from ssh-keygen (normal runs).
fn keygen(tmp: &Path) -> Result<(Vec<u8>, Vec<u8>), DecoyError> {
    let key = tmp.join("decoy-key");
    let _ = std::fs::remove_file(&key);
    let _ = std::fs::remove_file(tmp.join("decoy-key.pub"));
    let out = std::process::Command::new("/usr/bin/ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "victim@glasshouse",
            "-f",
        ])
        .arg(&key)
        .output()
        .map_err(|e| DecoyError::Keygen(e.to_string()))?;
    if !out.status.success() {
        return Err(DecoyError::Keygen(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    let read = |p: &Path| {
        std::fs::read(p).map_err(|e| DecoyError::Io {
            path: p.display().to_string(),
            err: e.to_string(),
        })
    };
    let pair = (read(&key)?, read(&tmp.join("decoy-key.pub"))?);
    let _ = std::fs::remove_file(&key);
    let _ = std::fs::remove_file(tmp.join("decoy-key.pub"));
    Ok(pair)
}

/// (path relative to the run dir, path inside the sandbox, content, mode).
type Planned = (String, String, Vec<u8>, u32);

fn plan(rng: &mut Rng, ssh: (Vec<u8>, Vec<u8>)) -> Vec<Planned> {
    let mut v: Vec<Planned> = Vec::new();
    let mut home = |rel: &str, content: Vec<u8>, mode: u32| {
        v.push((
            format!("home/{rel}"),
            format!("/home/victim/{rel}"),
            content,
            mode,
        ));
    };
    home(".ssh/id_ed25519", ssh.0, 0o600);
    home(".ssh/id_ed25519.pub", ssh.1, 0o644);
    let hosts: Vec<u8> = (0..3)
        .map(|i| {
            format!(
                "host{i}.example.internal ssh-ed25519 {}\n",
                b64(&rng.bytes(51))
            )
        })
        .collect::<String>()
        .into_bytes();
    home(".ssh/known_hosts", hosts, 0o644);
    // AWS's documented example credentials (never valid).
    home(
        ".aws/credentials",
        b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n".to_vec(),
        0o600,
    );
    home(
        ".config/google-chrome/Default/Login Data",
        rng.bytes(16384),
        0o600,
    );
    home(
        ".mozilla/firefox/x.default/logins.json",
        rng.bytes(4096),
        0o600,
    );
    home(".mozilla/firefox/x.default/key4.db", rng.bytes(8192), 0o600);
    let mut hist = Vec::new();
    for c in [
        "ls -la",
        "cd projects",
        "git status",
        "make",
        "ssh host1.example.internal",
        "vim notes.txt",
    ] {
        hist.extend_from_slice(c.as_bytes());
        hist.push(b'\n');
    }
    home(".bash_history", hist, 0o600);
    let pw: Vec<u8> = (0..8)
        .map(|i| format!("site{i}.example.com  user{i}  {}\n", b64(&rng.bytes(9))))
        .collect::<String>()
        .into_bytes();
    home("passwords.txt", pw, 0o600);
    home("wallet.dat", rng.bytes(32768), 0o600);
    home(".gnupg/private-keys-v1.d/x.key", rng.bytes(1200), 0o600);
    let exts = ["docx", "xlsx", "pdf", "txt"];
    for i in 0..20 {
        let ext = exts.get(i % 4).copied().unwrap_or("txt");
        let mut content = match ext {
            "docx" | "xlsx" => b"PK\x03\x04".to_vec(),
            "pdf" => b"%PDF-1.4\n".to_vec(),
            _ => Vec::new(),
        };
        let n = 200 + rng.below(400) as usize;
        content.extend(words(rng, n));
        home(&format!("Documents/file{i:02}.{ext}"), content, 0o644);
    }
    for i in 0..10 {
        let mut content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00".to_vec();
        let n = 4096 + rng.below(8192) as usize;
        content.extend(rng.bytes(n));
        home(&format!("Pictures/photo{i:02}.jpg"), content, 0o644);
    }
    let shadow = format!(
        "root:$6${}$fakehash:19000:0:99999:7:::\nvictim:$6${}$fakehash:19000:0:99999:7:::\n",
        b64(&rng.bytes(12)),
        b64(&rng.bytes(12))
    );
    v.push((
        "etc/shadow".into(),
        "/etc/shadow".into(),
        shadow.into_bytes(),
        0o640,
    ));
    v
}

fn io(path: &Path, e: std::io::Error) -> DecoyError {
    DecoyError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    }
}

/// Writes all decoys under `run_dir` and returns their manifest. `seed`
/// makes the output reproducible (the SSH key is then a fake one).
pub fn generate(run_dir: &Path, seed: Option<u64>) -> Result<Manifest, DecoyError> {
    let mut rng = Rng::new(seed.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1)
    }));
    let ssh = match seed {
        Some(_) => fake_ssh_key(&mut rng),
        None => keygen(run_dir)?,
    };
    let mut entries = Vec::new();
    for (rel, sandbox, content, mode) in plan(&mut rng, ssh) {
        let path: PathBuf = run_dir.join(&rel);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        }
        std::fs::write(&path, &content).map_err(|e| io(&path, e))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| io(&path, e))?;
        let meta = std::fs::metadata(&path).map_err(|e| io(&path, e))?;
        entries.push(DecoyEntry {
            path: rel,
            sandbox_path: sandbox,
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            sha256: sha256_hex(&content),
            entropy: entropy(&content),
            mode,
        });
    }
    Ok(Manifest {
        version: 1,
        decoys: entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sysscope-decoys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(b""), 0.0);
        assert_eq!(entropy(b"aaaa"), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn b64_matches_known_values() {
        assert_eq!(b64(b"hello"), "aGVsbG8=");
        assert_eq!(b64(b"hi"), "aGk=");
        assert_eq!(b64(b"abc"), "YWJj");
    }

    #[test]
    fn manifest_matches_files_on_disk() {
        let d = tmp("rehash");
        let m = generate(&d, Some(42)).unwrap();
        assert_eq!(
            m.decoys.len(),
            42,
            "plan 6.2: 11 named home files + 20 documents + 10 pictures + /etc/shadow"
        );
        for e in &m.decoys {
            let p = d.join(&e.path);
            let data = std::fs::read(&p).unwrap();
            let meta = std::fs::metadata(&p).unwrap();
            assert_eq!(sha256_hex(&data), e.sha256, "{}", e.path);
            assert_eq!((meta.dev(), meta.ino(), meta.len()), (e.dev, e.ino, e.size));
            assert!((entropy(&data) - e.entropy).abs() < 1e-12);
            assert_eq!(meta.permissions().mode() & 0o777, e.mode);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn same_seed_same_content_other_seed_differs() {
        let (a, b, c) = (tmp("a"), tmp("b"), tmp("c"));
        let ma = generate(&a, Some(7)).unwrap();
        let mb = generate(&b, Some(7)).unwrap();
        let mc = generate(&c, Some(8)).unwrap();
        let hashes = |m: &Manifest| {
            m.decoys
                .iter()
                .map(|e| (e.path.clone(), e.sha256.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(hashes(&ma), hashes(&mb));
        assert_ne!(hashes(&ma), hashes(&mc));
        for d in [a, b, c] {
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn no_decoy_contains_host_data() {
        let d = tmp("host");
        // A real run: key from ssh-keygen.
        generate(&d, None).unwrap();
        let user = std::env::var("USER").unwrap_or_default();
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();
        let home = std::env::var("HOME").unwrap_or_default();
        let mut needles: Vec<String> = vec![home];
        if user.len() > 2 {
            needles.push(user);
        }
        if host.len() > 2 {
            needles.push(host);
        }
        let mut stack = vec![d.clone()];
        let mut files = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                files += 1;
                let data = std::fs::read(&p).unwrap();
                for n in needles.iter().filter(|n| !n.is_empty()) {
                    assert!(
                        !data.windows(n.len()).any(|w| w == n.as_bytes()),
                        "{} contains host data {n:?}",
                        p.display()
                    );
                }
            }
        }
        assert_eq!(files, 42);
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Writes `<run>/manifest.json` (read only by the root helper and differ).
pub fn write_manifest(run_dir: &Path, m: &Manifest) -> Result<(), DecoyError> {
    let path = run_dir.join("manifest.json");
    let text = serde_json::to_string_pretty(m).map_err(|e| DecoyError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    })?;
    std::fs::write(&path, text).map_err(|e| io(&path, e))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| io(&path, e))
}

#[cfg(test)]
mod manifest_tests {
    use super::*;

    #[test]
    fn manifest_round_trips_through_json() {
        let d = std::env::temp_dir().join(format!("sysscope-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let m = generate(&d, Some(3)).unwrap();
        write_manifest(&d, &m).unwrap();
        let back: Manifest =
            serde_json::from_slice(&std::fs::read(d.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(back, m);
        let _ = std::fs::remove_dir_all(&d);
    }
}
