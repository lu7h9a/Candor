//! Record-file reader and replay: any recording parses or fails, and what
//! parses can be fed to the engine without a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use candor_core::Engine;
use candor_core::replay::{parse, replay_engine};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse(s);
    if let Ok(mut e) = Engine::with_defaults() {
        let _ = replay_engine(&mut e, s.lines());
        let _ = e.snapshot(1);
    }
});
