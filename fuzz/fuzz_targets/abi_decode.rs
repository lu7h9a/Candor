//! Kernel ring-buffer record decoder (crates/sysscoped/src/abi.rs, included
//! by path because sysscoped is a binary crate): any record bytes decode or
//! fail cleanly.
#![no_main]
use libfuzzer_sys::fuzz_target;

#[allow(dead_code, clippy::all)]
#[path = "../../crates/sysscoped/src/abi.rs"]
mod abi;

fuzz_target!(|data: &[u8]| {
    let _ = abi::decode(data);
});
