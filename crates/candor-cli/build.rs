//! Records the git commit for `candor --version` (plan WP32). Taken from
//! CANDOR_GIT_COMMIT when set (package builds from a source tarball have
//! no .git), else from `git rev-parse`, else "unknown".
fn main() {
    println!("cargo:rerun-if-env-changed=CANDOR_GIT_COMMIT");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
    let commit = std::env::var("CANDOR_GIT_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .filter(|c| c.chars().all(|ch| ch.is_ascii_hexdigit()) && !c.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=CANDOR_GIT_COMMIT={commit}");
}
