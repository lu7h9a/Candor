//! BStr escaping (I10): unescape never panics; the wire escaping round-trips
//! any bytes exactly and leaves no C0 control; the display form adds no C1,
//! bidi, zero-width or tag character (the wire form may keep those as
//! valid UTF-8 by design, see bstr.rs; display::safe neutralises them).
#![no_main]
use libfuzzer_sys::fuzz_target;
use sysscope_core::display::{json_safe, safe};
use sysscope_proto::BStr;
use sysscope_proto::bstr::unescape;

fn dangerous(c: char) -> bool {
    matches!(c as u32,
        0x00..=0x1F | 0x7F..=0x9F | 0x200B..=0x200F | 0x2028 | 0x2029
        | 0x202A..=0x202E | 0x2066..=0x2069 | 0x061C | 0xFEFF | 0xE0000..=0xE007F)
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = unescape(s);
        let _ = BStr::from_escaped(s);
    }
    let b = BStr(data.to_vec());
    let wire = b.escaped();
    assert!(
        !wire.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7F),
        "C0 control in wire form: {wire:?}"
    );
    assert_eq!(unescape(&wire).ok().as_deref(), Some(data));
    let shown = safe(&b);
    assert!(
        !shown.chars().any(dangerous),
        "dangerous char shown: {shown:?}"
    );
    let json = json_safe(&serde_json::to_string(&b).unwrap_or_default());
    assert!(
        !json.chars().any(dangerous),
        "dangerous char in json: {json:?}"
    );
});
