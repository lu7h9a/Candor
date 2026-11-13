//! Wire protocol shared by the daemon and its clients.
//!
//! Every message that crosses the Unix socket is defined here, together
//! with the length-prefixed framing and the byte-string escaping rules
//! (docs/MASTER_PLAN.md section 4.5). This crate does no I/O of its own:
//! it only reads from and writes to things that implement `Read`/`Write`.
#![forbid(unsafe_code)]

/// Protocol version spoken by this build. Bumped on any breaking change.
pub const PROTO_VERSION: u32 = 1;
