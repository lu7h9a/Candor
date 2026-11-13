//! Turning raw socket addresses from the kernel into display form (WP07).
//!
//! The bytes are a `struct sockaddr_*` exactly as the program passed it to
//! connect(): network byte order, family-specific layout, possibly short or
//! garbage. Parsing never panics; anything unexpected becomes family
//! "other". IPv4-mapped IPv6 addresses are shown as plain IPv4. Unix socket
//! paths are escaped like every byte string (I10), abstract ones get "@".

use std::net::{Ipv4Addr, Ipv6Addr};
use sysscope_proto::{BStr, Family, SockType};

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Socket type number to protocol enum.
pub fn sock_type(t: u16) -> SockType {
    match t {
        1 => SockType::Stream,
        2 => SockType::Dgram,
        _ => SockType::Other,
    }
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

fn v6_text(bytes: [u8; 16]) -> (Family, String) {
    let ip = Ipv6Addr::from(bytes);
    match ip.to_ipv4_mapped() {
        Some(v4) => (Family::Inet, v4.to_string()),
        None => (Family::Inet6, ip.to_string()),
    }
}

/// (family, address text, port) of a raw sockaddr.
pub fn parse(raw: &[u8]) -> (Family, String, u16) {
    let Some(&lo) = raw.first() else {
        return (Family::Other, String::new(), 0);
    };
    let family = u16::from_le_bytes([lo, raw.get(1).copied().unwrap_or(0)]);
    match family {
        AF_INET => {
            let a: Option<[u8; 4]> = raw.get(4..8).and_then(|a| a.try_into().ok());
            match (be16(raw, 2), a) {
                (Some(port), Some(a)) => (Family::Inet, Ipv4Addr::from(a).to_string(), port),
                _ => (Family::Other, String::new(), 0),
            }
        }
        AF_INET6 => match (be16(raw, 2), raw.get(8..24)) {
            (Some(port), Some(a)) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(a);
                let (f, text) = v6_text(b);
                (f, text, port)
            }
            _ => (Family::Other, String::new(), 0),
        },
        AF_UNIX => {
            let path = raw.get(2..).unwrap_or(b"");
            let text = match path.first() {
                Some(0) => {
                    // Abstract socket: name is every remaining byte.
                    format!("@{}", BStr::new(path.get(1..).unwrap_or(b"").to_vec()))
                }
                _ => {
                    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
                    BStr::new(path.get(..end).unwrap_or(b"").to_vec()).escaped()
                }
            };
            (Family::Unix, text, 0)
        }
        _ => (Family::Other, String::new(), 0),
    }
}

/// (family, address text) of a LISTEN record's address bytes.
pub fn listen_addr(family: u16, addr: &[u8; 16]) -> (Family, String) {
    match family {
        AF_INET => (
            Family::Inet,
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
        ),
        AF_INET6 => v6_text(*addr),
        _ => (Family::Other, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_inet6_mapped_unix_and_garbage() {
        let v4 = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse(&v4), (Family::Inet, "127.0.0.1".into(), 8080));
        let mut v6 = vec![10, 0, 0x01, 0xbb, 0, 0, 0, 0];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(parse(&v6), (Family::Inet6, "::1".into(), 443));
        let mut mapped = vec![10, 0, 0, 80, 0, 0, 0, 0];
        mapped.extend_from_slice(&Ipv4Addr::new(10, 1, 2, 3).to_ipv6_mapped().octets());
        assert_eq!(parse(&mapped), (Family::Inet, "10.1.2.3".into(), 80));
        let unix = b"\x01\x00/run/x\x1b.sock\x00junk";
        assert_eq!(parse(unix), (Family::Unix, "/run/x\\x1B.sock".into(), 0));
        let abs = b"\x01\x00\x00name\xff";
        assert_eq!(parse(abs), (Family::Unix, "@name\\xFF".into(), 0));
        assert_eq!(parse(&[2, 0, 1]).0, Family::Other);
        assert_eq!(parse(&[]).0, Family::Other);
        assert_eq!(parse(&[99, 0, 1, 2]).0, Family::Other);
    }
}
