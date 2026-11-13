//! The messages clients and the daemon exchange (plan section 4.5).
//!
//! Every message is a JSON object with a `"t"` field naming its type. serde
//! maps that to a Rust enum variant (`#[serde(tag = "t")]`). Decoding first
//! checks the type name against the known list, so an unknown type gives a
//! distinct error (`unknown_type`) from a known type with bad fields.

use crate::bstr::BStr;
use crate::types::{
    ConnStat, Event, FileStat, Finding, GhReport, Loss, MapRow, Mode, ProcKey, ProcRow, Series,
    SysStat,
};
use serde::{Deserialize, Serialize};

/// Which events a client wants streamed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventSub {
    /// The string "none" or "all".
    Simple(EventSubMode),
    /// `{"proc": ProcKey}`: events of one process only.
    Proc {
        /// The process.
        proc: ProcKey,
    },
}

/// The two string forms of [`EventSub`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSubMode {
    /// No events.
    None,
    /// All events.
    All,
}

/// Actions on a process (experimental act mode, D19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActAction {
    /// SIGSTOP.
    Pause,
    /// SIGCONT.
    Resume,
    /// SIGKILL.
    Kill,
}

/// Which client is speaking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
    /// The desktop GUI.
    Gui,
    /// The command-line client.
    Cli,
}

/// Messages from a client to the daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum ClientMsg {
    /// First message on a connection.
    Hello {
        /// Protocol version the client speaks.
        proto: u32,
        /// Kind of client.
        client: ClientKind,
        /// Client version string.
        version: String,
    },
    /// Choose what the daemon sends.
    Subscribe {
        /// Send snapshots at 2 Hz.
        snapshots: bool,
        /// Send alerts.
        alerts: bool,
        /// Which events to stream.
        events: EventSub,
    },
    /// Switch to follow mode on a process tree.
    Follow {
        /// Root of the tree.
        root: ProcKey,
    },
    /// Return to system-wide mode.
    Unfollow {},
    /// Ask for per-process detail.
    GetDetail {
        /// The process.
        proc: ProcKey,
        /// Include /proc/<pid>/maps.
        maps: bool,
    },
    /// Start uploading a Glasshouse sample.
    GhUploadBegin {
        /// Sample file name (display only).
        name: BStr,
        /// Total size in bytes (max 256 MiB).
        size: u64,
    },
    /// One chunk of sample bytes, base64, at most 64 KiB raw.
    GhUploadChunk {
        /// Chunk sequence number from 0.
        seq: u32,
        /// Base64-encoded bytes.
        b64: String,
    },
    /// Run the uploaded sample.
    GhRun {
        /// Arguments.
        args: Vec<BStr>,
        /// Timeout in seconds.
        timeout_s: u32,
    },
    /// Cancel the current Glasshouse run.
    GhCancel {},
    /// Pause, resume or kill a process (only with --enable-act).
    Act {
        /// Target process.
        proc: ProcKey,
        /// What to do.
        action: ActAction,
        /// Client-chosen id echoed in logs.
        nonce: String,
    },
    /// Liveness check.
    Ping {
        /// Echoed back in Pong.
        n: u64,
    },
}

/// Glasshouse run state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GhState {
    /// Receiving sample bytes.
    Uploading,
    /// Preparing the sandbox.
    Starting,
    /// Sample is running.
    Running,
    /// Run finished, report follows.
    Finished,
    /// Run failed.
    Failed,
}

/// Messages from the daemon to a client.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum DaemonMsg {
    /// Reply to Hello.
    Welcome {
        /// Protocol version the daemon speaks.
        proto: u32,
        /// Daemon version string.
        daemon_version: String,
        /// Kernel release.
        kernel: String,
        /// Add this to a boot-time ns value to get Unix-epoch ns.
        boot_to_wall_ns: u64,
        /// Optional features available on this kernel.
        features: Vec<String>,
        /// True if act mode is enabled.
        act_enabled: bool,
    },
    /// Full process table, sent at 2 Hz.
    Snapshot {
        /// Increasing sequence number.
        seq: u64,
        /// Snapshot time (boot ns).
        ts_ns: u64,
        /// System-wide or following.
        mode: Mode,
        /// All tracked processes.
        procs: Vec<ProcRow>,
        /// Kernel loss counters.
        loss: Loss,
    },
    /// A batch of streamed events.
    Events {
        /// The events.
        events: Vec<Event>,
        /// Events this client missed because its queue was full.
        client_dropped: u64,
    },
    /// A new or escalated finding.
    Alert {
        /// The finding.
        finding: Finding,
    },
    /// Per-process detail, reply to GetDetail.
    Detail {
        /// The process.
        proc: ProcKey,
        /// CPU and memory history.
        series: Series,
        /// Recent events.
        recent: Vec<Event>,
        /// Files touched.
        files: Vec<FileStat>,
        /// Connections made.
        conns: Vec<ConnStat>,
        /// Syscall counts.
        syscalls: Vec<SysStat>,
        /// Direct children.
        children: Vec<ProcKey>,
        /// Memory maps if requested.
        maps: Option<Vec<MapRow>>,
        /// Findings on this process.
        findings: Vec<Finding>,
    },
    /// Glasshouse progress.
    GhStatus {
        /// Current state.
        state: GhState,
        /// Run id.
        run_id: String,
        /// Human-readable message.
        message: String,
    },
    /// Glasshouse final report.
    GhReport {
        /// The report.
        report: GhReport,
    },
    /// Result of an Act request.
    ActResult {
        /// True if the action was performed.
        ok: bool,
        /// Explanation.
        message: String,
    },
    /// Protocol or request error.
    Error {
        /// Machine-readable code, e.g. "unknown_type", "proto_mismatch".
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// Reply to Ping.
    Pong {
        /// Echo of Ping.n.
        n: u64,
    },
}

/// Type names a client may send.
pub const CLIENT_TYPES: &[&str] = &[
    "Hello",
    "Subscribe",
    "Follow",
    "Unfollow",
    "GetDetail",
    "GhUploadBegin",
    "GhUploadChunk",
    "GhRun",
    "GhCancel",
    "Act",
    "Ping",
];

/// Type names the daemon may send.
pub const DAEMON_TYPES: &[&str] = &[
    "Welcome",
    "Snapshot",
    "Events",
    "Alert",
    "Detail",
    "GhStatus",
    "GhReport",
    "ActResult",
    "Error",
    "Pong",
];

/// Why a frame body could not be decoded into a message.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Body is not a JSON object with a string "t".
    #[error("malformed message: {0}")]
    Malformed(String),
    /// "t" names a type this side does not know.
    #[error("unknown message type {0:?}")]
    UnknownType(String),
}

impl DecodeError {
    /// The `Error.code` the daemon should send back for this error.
    pub fn code(&self) -> &'static str {
        match self {
            DecodeError::Malformed(_) => "malformed",
            DecodeError::UnknownType(_) => "unknown_type",
        }
    }
}

fn decode_tagged<T: serde::de::DeserializeOwned>(
    body: &[u8],
    known: &[&str],
) -> Result<T, DecodeError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let tag = match value.get("t") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return Err(DecodeError::Malformed("missing string field \"t\"".into())),
    };
    if !known.contains(&tag.as_str()) {
        // Cap and escape the echoed name: it is untrusted and may end up in
        // a log or terminal (invariant I10).
        let raw = tag.as_bytes();
        let shown = crate::bstr::escape(raw.get(..64).unwrap_or(raw));
        return Err(DecodeError::UnknownType(shown));
    }
    serde_json::from_value(value).map_err(|e| DecodeError::Malformed(e.to_string()))
}

/// Decodes a frame body sent by a client.
pub fn decode_client(body: &[u8]) -> Result<ClientMsg, DecodeError> {
    decode_tagged(body, CLIENT_TYPES)
}

/// Decodes a frame body sent by the daemon.
pub fn decode_daemon(body: &[u8]) -> Result<DaemonMsg, DecodeError> {
    decode_tagged(body, DAEMON_TYPES)
}

/// Encodes any message to compact JSON bytes.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(msg)
}
