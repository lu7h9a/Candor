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
