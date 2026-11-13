//! `sysscope`: the command-line client.
//!
//! An unprivileged program that talks to the daemon over its Unix socket
//! and prints process lists, events and findings. It is also the headless
//! surface the integration tests drive.
#![forbid(unsafe_code)]

fn main() {
    println!(
        "sysscope {}: not implemented yet",
        env!("CARGO_PKG_VERSION")
    );
}
