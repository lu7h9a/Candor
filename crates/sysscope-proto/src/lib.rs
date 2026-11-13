//! Wire protocol shared by the daemon and its clients.
//!
//! Every message that crosses the Unix socket is defined here, together
//! with the length-prefixed framing and the byte-string escaping rules
//! (docs/MASTER_PLAN.md section 4.5). This crate does no I/O of its own:
//! it only reads from and writes to things that implement `Read`/`Write`.
#![forbid(unsafe_code)]

pub mod bstr;
pub mod float;
pub mod frame;
pub mod msg;
pub mod types;

pub use bstr::BStr;
pub use frame::{FrameError, MAX_CLIENT_FRAME, MAX_DAEMON_FRAME, read_frame, write_frame};
pub use msg::{
    ActAction, ClientKind, ClientMsg, DaemonMsg, DecodeError, EventSub, EventSubMode, GhState,
    decode_client, decode_daemon, encode,
};
pub use types::*;

/// Protocol version spoken by this build. Bumped on any breaking change.
pub const PROTO_VERSION: u32 = 1;
