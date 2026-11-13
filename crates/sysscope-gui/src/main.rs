//! `sysscope-gui`: the desktop client.
//!
//! An unprivileged egui window that shows the daemon's snapshots. The UI is
//! a pure function of a view-model (`model.rs`); a reader thread
//! (`net.rs`) feeds that model from the socket or from a replay file.
#![forbid(unsafe_code)]

fn main() {
    println!(
        "sysscope-gui {}: not implemented yet",
        env!("CARGO_PKG_VERSION")
    );
}
