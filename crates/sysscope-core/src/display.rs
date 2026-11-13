//! Terminal-safe text for anything that came from a traced process (I10).
//!
//! The wire escaping of `BStr` (plan 4.5) already turns control bytes and
//! invalid UTF-8 into `\xHH`. Valid UTF-8 can still carry characters a
//! terminal or GUI interprets: C1 controls (U+0080-U+009F, e.g. U+009B is an
//! 8-bit CSI) and bidirectional overrides that reorder what is shown
//! (U+202A-U+202E, U+2066-U+2069, U+200E/F, U+061C). `safe` replaces those
//! with `\u{XXXX}` so the displayed text is exactly what was there.

use sysscope_proto::BStr;

/// JSON text with every character a terminal could interpret (C1, bidi,
/// zero-width, tags; JSON already escapes C0) written as \uXXXX, so a JSON
/// file or stream can be printed safely (I10).
pub fn json_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if dangerous(c) && (c as u32) > 0x1F {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{:04x}", u));
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn dangerous(c: char) -> bool {
    matches!(c as u32,
        0x00..=0x1F | 0x7F..=0x9F       // C0 and C1 controls
        | 0x200B..=0x200F                // zero-width space/joiners, LRM, RLM
        | 0x2028 | 0x2029                // line and paragraph separators
        | 0x202A..=0x202E | 0x2066..=0x2069 | 0x061C  // bidi controls
        | 0xFEFF                         // byte-order mark / zero-width no-break space
        | 0xE0000..=0xE007F) // tag characters
}

/// Neutralises dangerous characters in already-escaped text.
pub fn safe_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if dangerous(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Display form of a byte string: wire escaping plus `safe_str`.
pub fn safe(b: &BStr) -> String {
    safe_str(&b.escaped())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_safe_escapes_c1_bidi_and_tags_but_stays_json() {
        let raw = serde_json::to_string(&"a\u{85}b\u{202e}c\u{e0041}d").unwrap();
        let safe = json_safe(&raw);
        assert!(safe.chars().all(|c| !dangerous(c)), "{safe}");
        let back: String = serde_json::from_str(&safe).unwrap();
        assert_eq!(back, "a\u{85}b\u{202e}c\u{e0041}d");
    }

    #[test]
    fn c1_and_bidi_are_neutralised() {
        let b = BStr::new("a\u{9b}31mb\u{202e}cba".as_bytes().to_vec());
        let s = safe(&b);
        assert_eq!(s, "a\\u{009B}31mb\\u{202E}cba");
        assert_eq!(safe(&BStr::from("/usr/bin/ls")), "/usr/bin/ls");
        assert_eq!(safe(&BStr::new(b"\x1b[2J".to_vec())), "\\x1B[2J");
        assert_eq!(safe_str("x\u{7}y"), "x\\u{0007}y");
        assert_eq!(
            safe_str("a\u{2028}b\u{200B}c\u{FEFF}d\u{E0041}"),
            "a\\u{2028}b\\u{200B}c\\u{FEFF}d\\u{E0041}"
        );
    }
}
