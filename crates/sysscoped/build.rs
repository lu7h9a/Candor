//! Build script: compiles bpf/sysscope.bpf.c with clang and generates the
//! Rust skeleton (`sysscope.skel.rs` in OUT_DIR) that `abi.rs` includes.
//! libbpf is linked statically (libbpf-sys default `vendored-libbpf`);
//! libelf and zlib are linked dynamically. When the libelf development
//! package is not installed system-wide, its headers and link symlink come
//! from target/sysroot (see scripts/sysroot.sh).

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out = PathBuf::from(env::var("OUT_DIR")?).join("sysscope.skel.rs");
    let bpf = manifest.join("bpf");

    SkeletonBuilder::new()
        .source(bpf.join("sysscope.bpf.c"))
        .clang_args([
            "-I".into(),
            bpf.as_os_str().to_owned(),
            "-I".into(),
            bpf.join("vmlinux/x86_64").into_os_string(),
            "-Wall".into(),
            "-Werror".into(),
            "-Wno-missing-declarations".into(),
        ])
        .build_and_generate(&out)?;

    let sysroot_lib = manifest.join("../../target/sysroot/usr/lib/x86_64-linux-gnu");
    if sysroot_lib.exists() {
        println!("cargo:rustc-link-search=native={}", sysroot_lib.display());
    }
    write_syscall_table()?;

    // __isoc23_* shims so the binary also runs on glibc 2.34-2.37.
    cc::Build::new()
        .file(manifest.join("compat/glibc_compat.c"))
        .flag("-std=c11")
        .compile("sysscope_glibc_compat");
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-changed=compat");
    Ok(())
}

/// Generates `syscall_names.rs` (number -> name) from the kernel headers'
/// unistd_64.h, so the daemon can show names without hard-coding a table.
fn write_syscall_table() -> Result<(), Box<dyn std::error::Error>> {
    let header = [
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
    ]
    .iter()
    .find(|p| std::path::Path::new(p).exists())
    .map(|p| std::fs::read_to_string(p).unwrap_or_default())
    .unwrap_or_default();
    let mut rows = String::new();
    for line in header.lines() {
        let mut it = line.split_whitespace();
        if let (Some("#define"), Some(name), Some(nr)) = (it.next(), it.next(), it.next())
            && let (Some(name), Ok(nr)) = (name.strip_prefix("__NR_"), nr.parse::<u32>())
        {
            rows.push_str(&format!("    ({nr}, \"{name}\"),\n"));
        }
    }
    let out = PathBuf::from(env::var("OUT_DIR")?).join("syscall_names.rs");
    std::fs::write(
        out,
        format!(
            "/// Syscall numbers and names from unistd_64.h.\npub const SYSCALL_NAMES: &[(u32, &str)] = &[\n{rows}];\n"
        ),
    )?;
    println!("cargo:rerun-if-changed=/usr/include/x86_64-linux-gnu/asm/unistd_64.h");
    Ok(())
}
