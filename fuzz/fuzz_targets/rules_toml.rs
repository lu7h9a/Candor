//! Rules and allowlist TOML loaders: any text is accepted or rejected with
//! an error, never a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use candor_core::config::{Rules, load_allow};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(r) = Rules::load(Some(s)) {
        let _ = load_allow(&r, None);
    }
    if let Ok(r) = Rules::load(None) {
        let _ = load_allow(&r, Some(s));
    }
});
