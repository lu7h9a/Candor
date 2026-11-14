//! Glasshouse report and helper-line parsers (the daemon reads helper lines
//! from a sandbox-adjacent process; the CLI reads saved reports).
#![no_main]
use libfuzzer_sys::fuzz_target;
use sysscope_proto::GhReport;
use sysscope_proto::helper::{HelperIn, HelperOut};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<GhReport>(data);
    let _ = serde_json::from_slice::<HelperOut>(data);
    let _ = serde_json::from_slice::<HelperIn>(data);
});
