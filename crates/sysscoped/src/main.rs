//! `sysscoped`: the root daemon.
//!
//! It loads the eBPF programs, samples /proc, owns all state, runs the
//! detection rules and serves clients over a Unix socket. It is the only
//! SysScope process that runs as root (invariant I1). The only `unsafe`
//! code in the whole project lives in `abi.rs` (invariant I14).
#![deny(unsafe_code)]

fn main() {
    println!(
        "sysscoped {}: not implemented yet",
        env!("CARGO_PKG_VERSION")
    );
}
