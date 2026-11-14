//! `BStr`: a byte string that came from a traced process.
//!
//! Paths, argv and comm are arbitrary bytes: they may be invalid UTF-8 or
//! contain terminal escape sequences. On the wire they travel as JSON strings
//! using a reversible escaping (plan section 4.5): a backslash becomes `\\`,
//! and every control byte (< 0x20 or 0x7F) or byte that is not part of valid
//! UTF-8 becomes `\xHH` with uppercase hex. Valid UTF-8 can still carry C1
//! controls and bidi overrides, so display code must additionally use
//! `candor_core::display::safe` before printing (invariant I10).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Raw bytes from a traced process, escaped whenever they are shown or sent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BStr(pub Vec<u8>);

/// Why an escaped string could not be turned back into bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnescapeError {
    /// A backslash at the very end of the string.
    #[error("dangling backslash at end of string")]
    DanglingBackslash,
    /// A backslash followed by something other than `\` or `xHH`.
    #[error("unknown escape at byte offset {0}")]
    UnknownEscape(usize),
    /// `\x` not followed by two uppercase hex digits.
    #[error("bad \\x escape at byte offset {0}")]
    BadHex(usize),
    /// A raw control character that should have been escaped.
    #[error("unescaped control character at byte offset {0}")]
    RawControl(usize),
}

impl BStr {
    /// Wraps raw bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> BStr {
        BStr(bytes.into())
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the escaped, display-safe form (the wire form).
    pub fn escaped(&self) -> String {
        escape(&self.0)
    }

    /// Parses an escaped string back into bytes.
    pub fn from_escaped(s: &str) -> Result<BStr, UnescapeError> {
        unescape(s).map(BStr)
    }
}

impl From<&str> for BStr {
    fn from(s: &str) -> BStr {
        BStr(s.as_bytes().to_vec())
    }
}

impl From<&[u8]> for BStr {
    fn from(b: &[u8]) -> BStr {
        BStr(b.to_vec())
    }
}

impl fmt::Display for BStr {
    /// Prints the escaped form, never the raw bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.escaped())
    }
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        _ => char::from(b'A' + (nibble & 0x0F) - 10),
    }
}

fn push_hex(out: &mut String, b: u8) {
    out.push('\\');
    out.push('x');
    out.push(hex_digit(b >> 4));
    out.push(hex_digit(b & 0x0F));
}

/// Escapes arbitrary bytes into a display-safe string (plan 4.5).
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    // `utf8_chunks` splits the input into valid UTF-8 runs and the invalid
    // bytes between them, so we never guess at encodings ourselves.
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 || c as u32 == 0x7F => push_hex(&mut out, c as u8),
                c => out.push(c),
            }
        }
        for &b in chunk.invalid() {
            push_hex(&mut out, b);
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Reverses [`escape`]. Rejects anything `escape` could not have produced.
pub fn unescape(s: &str) -> Result<Vec<u8>, UnescapeError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            match bytes.get(i + 1) {
                None => return Err(UnescapeError::DanglingBackslash),
                Some(b'\\') => {
                    out.push(b'\\');
                    i += 2;
                }
                Some(b'x') => {
                    let hi = bytes.get(i + 2).copied().and_then(hex_val);
                    let lo = bytes.get(i + 3).copied().and_then(hex_val);
                    match (hi, lo) {
                        (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
                        _ => return Err(UnescapeError::BadHex(i)),
                    }
                    i += 4;
                }
                Some(_) => return Err(UnescapeError::UnknownEscape(i)),
            }
        } else if b < 0x20 || b == 0x7F {
            return Err(UnescapeError::RawControl(i));
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

impl Serialize for BStr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.escaped())
    }
}

impl<'de> Deserialize<'de> for BStr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<BStr, D::Error> {
        let s = String::deserialize(deserializer)?;
        BStr::from_escaped(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_is_unchanged() {
        assert_eq!(escape(b"/usr/bin/bash"), "/usr/bin/bash");
    }

    #[test]
    fn backslash_control_and_invalid_bytes_are_escaped() {
        assert_eq!(escape(b"a\\b"), "a\\\\b");
        assert_eq!(escape(b"\x1b[31m\n"), "\\x1B[31m\\x0A");
        assert_eq!(escape(b"\x7f"), "\\x7F");
        assert_eq!(escape(b"\xff\xfe"), "\\xFF\\xFE");
        // A truncated multi-byte sequence is invalid and escaped byte by byte.
        assert_eq!(escape(b"caf\xc3"), "caf\\xC3");
    }

    #[test]
    fn valid_utf8_passes_through() {
        assert_eq!(escape("café ✓".as_bytes()), "café ✓");
    }

    #[test]
    fn unescape_rejects_malformed_input() {
        assert_eq!(unescape("a\\"), Err(UnescapeError::DanglingBackslash));
        assert_eq!(unescape("\\n"), Err(UnescapeError::UnknownEscape(0)));
        assert_eq!(unescape("\\x1"), Err(UnescapeError::BadHex(0)));
        assert_eq!(unescape("\\xff"), Err(UnescapeError::BadHex(0)));
        assert_eq!(unescape("a\nb"), Err(UnescapeError::RawControl(1)));
    }

    #[test]
    fn json_form_is_the_escaped_string() {
        let b = BStr::new(b"x\n".to_vec());
        assert_eq!(serde_json::to_string(&b).unwrap(), r#""x\\x0A""#);
        let back: BStr = serde_json::from_str(r#""x\\x0A""#).unwrap();
        assert_eq!(back, b);
    }
}
