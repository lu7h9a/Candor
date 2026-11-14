//! abi.rs includes the generated BPF skeleton from OUT_DIR. The decoder does
//! not use it, so the fuzz build provides an empty one (no BPF toolchain).
fn main() {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(format!("{out}/candor.skel.rs"), "").expect("write empty skeleton");
}
