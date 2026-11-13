//! Terminal-safe text for anything that came from a traced process (I10).
//!
//! The wire escaping of `BStr` (plan 4.5) already turns control bytes and
//! invalid UTF-8 into `\xHH`. Valid UTF-8 can still carry characters a
//! terminal or GUI interprets: C1 controls (U+0080-U+009F, e.g. U+009B is an
//! 8-bit CSI) and bidirectional overrides that reorder what is shown
//! (U+202A-U+202E, U+2066-U+2069, U+200E/F, U+061C). `safe` replaces those
//! with `\u{XXXX}` so the displayed text is exactly what was there.

use sysscope_proto::BStr;

fn dangerous(c: char) -> bool {
    matches!(c as u32,
        0x00..=0x1F | 0x7F..=0x9F | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x061C)
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
    fn c1_and_bidi_are_neutralised() {
        let b = BStr::new("a\u{9b}31mb\u{202e}cba".as_bytes().to_vec());
        let s = safe(&b);
        assert_eq!(s, "a\\u{009B}31mb\\u{202E}cba");
        assert_eq!(safe(&BStr::from("/usr/bin/ls")), "/usr/bin/ls");
        assert_eq!(safe(&BStr::new(b"\x1b[2J".to_vec())), "\\x1B[2J");
        assert_eq!(safe_str("x\u{7}y"), "x\\u{0007}y");
    }
}
