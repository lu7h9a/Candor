//! Length-prefixed framing: `u32` little-endian length, then that many bytes.
//!
//! The reader checks the length against a maximum *before* allocating, so a
//! hostile peer cannot make us reserve gigabytes. A clean end-of-stream before
//! the first length byte is reported as `Ok(None)`; any other short read is an
//! error. Nothing here panics, whatever bytes arrive.

use std::io::{self, Read, Write};

/// Largest frame a client may send to the daemon (1 MiB).
pub const MAX_CLIENT_FRAME: u32 = 1024 * 1024;
/// Largest frame the daemon may send to a client (16 MiB).
pub const MAX_DAEMON_FRAME: u32 = 16 * 1024 * 1024;

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The length prefix exceeds the allowed maximum.
    #[error("frame of {len} bytes exceeds the limit of {max}")]
    TooLarge {
        /// Announced length.
        len: u64,
        /// Allowed maximum.
        max: u32,
    },
    /// The stream ended in the middle of a frame.
    #[error("stream ended inside a frame")]
    Truncated,
    /// Any other I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

/// Reads one frame body. `Ok(None)` means the peer closed cleanly between frames.
pub fn read_frame<R: Read>(r: &mut R, max: u32) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len_buf = [0u8; 4];
    let mut got = 0;
    while got < len_buf.len() {
        let dst = len_buf.get_mut(got..).unwrap_or(&mut []);
        match r.read(dst) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let len = u32::from_le_bytes(len_buf);
    if len > max {
        return Err(FrameError::TooLarge {
            len: u64::from(len),
            max,
        });
    }
    let mut body = vec![0u8; len as usize];
    match r.read_exact(&mut body) {
        Ok(()) => Ok(Some(body)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(FrameError::Truncated),
        Err(e) => Err(FrameError::Io(e)),
    }
}

/// Writes one frame. Refuses bodies larger than `max`.
pub fn write_frame<W: Write>(w: &mut W, body: &[u8], max: u32) -> Result<(), FrameError> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|l| *l <= max)
        .ok_or(FrameError::TooLarge {
            len: body.len() as u64,
            max,
        })?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(body)?;
    Ok(())
}

/// One line of a JSONL file, read with a size cap.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A complete line (without the newline).
    Text(Vec<u8>),
    /// A line longer than the cap; its bytes were skipped, not kept.
    TooLong,
}

/// Reads the next line of at most `max` bytes. Longer lines are skipped in
/// small chunks (never held in memory) and reported as `TooLong`; `Ok(None)`
/// at the end of the input. For replay files from untrusted sources.
pub fn read_line_bounded<R: std::io::BufRead>(
    r: &mut R,
    max: usize,
) -> Result<Option<Line>, FrameError> {
    let mut buf = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            if buf.is_empty() && !too_long {
                return Ok(None);
            }
            break;
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (chunk.len(), false),
        };
        if !too_long {
            if buf.len() + take > max {
                too_long = true;
                buf = Vec::new();
            } else {
                buf.extend_from_slice(chunk.get(..take).unwrap_or(&[]));
            }
        }
        r.consume(if done { take + 1 } else { take });
        if done {
            break;
        }
    }
    Ok(Some(if too_long {
        Line::TooLong
    } else {
        Line::Text(buf)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_clean_eof() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello", 100).unwrap();
        write_frame(&mut buf, b"", 100).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 100).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_frame(&mut r, 100).unwrap(), Some(Vec::new()));
        assert_eq!(read_frame(&mut r, 100).unwrap(), None);
    }

    #[test]
    fn oversize_is_rejected_before_allocation() {
        let bytes = u32::MAX.to_le_bytes();
        let err = read_frame(&mut &bytes[..], MAX_CLIENT_FRAME).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { .. }));
        let err = write_frame(&mut Vec::new(), &[0u8; 11], 10).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { .. }));
    }

    #[test]
    fn bounded_lines_skip_giant_lines_without_storing_them() {
        let mut data = b"short\n".to_vec();
        data.extend(std::iter::repeat_n(b'x', 100_000));
        data.extend_from_slice(b"\nlast");
        let mut r = std::io::BufReader::with_capacity(64, &data[..]);
        assert_eq!(
            read_line_bounded(&mut r, 10).unwrap(),
            Some(Line::Text(b"short".to_vec()))
        );
        assert_eq!(read_line_bounded(&mut r, 10).unwrap(), Some(Line::TooLong));
        assert_eq!(
            read_line_bounded(&mut r, 10).unwrap(),
            Some(Line::Text(b"last".to_vec()))
        );
        assert_eq!(read_line_bounded(&mut r, 10).unwrap(), None);
    }

    #[test]
    fn truncated_length_and_body() {
        assert!(matches!(
            read_frame(&mut &[1u8, 0][..], 100),
            Err(FrameError::Truncated)
        ));
        assert!(matches!(
            read_frame(&mut &[5u8, 0, 0, 0, b'a'][..], 100),
            Err(FrameError::Truncated)
        ));
    }
}
