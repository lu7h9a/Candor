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
    // __isoc23_* shims so the binary also runs on glibc 2.34-2.37.
    cc::Build::new()
        .file(manifest.join("compat/glibc_compat.c"))
        .flag("-std=c11")
        .compile("sysscope_glibc_compat");
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-changed=compat");
    Ok(())
}
