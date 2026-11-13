//! Core data types that appear inside protocol messages.
//!
//! These are plain structs and enums with serde derives. Field names are the
//! JSON names from plan section 4.5; where the Rust name differs it is mapped
//! with `#[serde(rename = ...)]`. Unknown JSON fields are ignored so newer
//! daemons can add fields without breaking older clients.

use crate::bstr::BStr;
use crate::float::{ser_f32, ser_f32_vec, ser_opt_f32};
use serde::{Deserialize, Serialize};

/// Identity of a process: thread-group id plus start time (invariant I4).
///
/// A bare pid can be reused by the kernel; the pair never is during one boot.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct ProcKey {
    /// Thread-group id, what users call the PID.
    pub tgid: u32,
    /// Start time in clock ticks since boot (field 22 of /proc/<pid>/stat).
    #[serde(rename = "start")]
    pub start_ticks: u64,
}

/// One row of the process table sent in every snapshot.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcRow {
    /// Identity of this process.
    pub key: ProcKey,
    /// Parent process, if known.
    pub parent: Option<ProcKey>,
    /// Executable path from the exec event (display only, invariant I5).
    pub exe: BStr,
    /// Kernel `comm` name; attacker controlled, shown only as secondary info.
    pub comm: BStr,
    /// Real user id.
    pub uid: u32,
    /// True for kernel threads.
    pub kthread: bool,
    /// CPU usage in percent of one core over the last sample (can exceed 100).
    #[serde(serialize_with = "ser_f32")]
    pub cpu_pct: f32,
    /// Resident set size in bytes.
    pub rss: u64,
    /// Number of threads.
    pub threads: u32,
    /// Bytes read (from /proc/<pid>/io).
    pub io_r: u64,
    /// Bytes written (from /proc/<pid>/io).
    pub io_w: u64,
    /// Number of file opens observed.
    pub n_open: u64,
    /// Number of outbound connects observed.
    pub n_conn: u64,
    /// Number of execs observed.
    pub n_exec: u64,
    /// Number of children observed.
    pub n_child: u64,
    /// Number of syscalls counted.
    pub n_sys: u64,
    /// Suspicion score of this process, 0-100.
    pub score: u8,
    /// Suspicion score of this process and its descendants, 0-100.
    pub tree_score: u8,
    /// Id of the rule contributing most to the score.
    pub top_rule: Option<String>,
    /// Exit time (boot ns) if the process has exited.
    pub exited_ts: Option<u64>,
    /// True if the process is inside the followed tree.
    pub followed: bool,
    /// Events dropped by the kernel budget for this process.
    pub ev_dropped: u64,
}

/// Counters of events lost in the kernel (invariant I3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loss {
    /// Ring buffer was full.
    pub ringbuf: u64,
    /// A process exceeded its per-process event budget.
    pub budget: u64,
    /// Per-CPU scratch buffer was unavailable.
    pub scratch: u64,
    /// Kernel records the daemon could not decode (added in the M1/M2
    /// gate review; additive).
    #[serde(default)]
    pub decode: u64,
    /// Boot-time ns since which these counts were accumulated.
    pub since_ts_ns: u64,
}

/// Address family of a connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    /// IPv4 (including v4-mapped IPv6, normalised to v4).
    Inet,
    /// IPv6.
    Inet6,
    /// Unix domain socket.
    Unix,
    /// Any other family.
    Other,
}

/// Socket type of a connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SockType {
    /// SOCK_STREAM.
    Stream,
    /// SOCK_DGRAM.
    Dgram,
    /// Anything else.
    Other,
}

/// What happened in one event. The JSON form is an object tagged by `"k"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k")]
pub enum EventKind {
    /// A program was executed.
    Exec {
        /// Executable path.
        exe: BStr,
        /// First bytes of the argument vector, NUL separated.
        argv: BStr,
        /// True if argv was cut at the cap.
        argv_trunc: bool,
        /// True if the executable had no link on disk (e.g. memfd).
        fileless: bool,
        /// Device of the executable.
        dev: u64,
        /// Inode of the executable.
        ino: u64,
    },
    /// The process created a child process.
    Fork {
        /// The new child.
        child: ProcKey,
    },
    /// The process exited.
    Exit {},
    /// A file was opened.
    Open {
        /// Resolved path (display only).
        path: BStr,
        /// Device of the file.
        dev: u64,
        /// Inode of the file.
        ino: u64,
        /// Opened for reading.
        read: bool,
        /// Opened for writing.
        write: bool,
        /// O_CREAT was set.
        create: bool,
        /// O_TRUNC was set.
        trunc: bool,
        /// Path was cut at the cap (only the leaf may be present).
        path_trunc: bool,
    },
    /// A file was renamed.
    Rename {
        /// Old path.
        old: BStr,
        /// New path.
        new: BStr,
        /// Device of the file.
        dev: u64,
        /// Inode of the file.
        ino: u64,
        /// Paths were rebuilt from dentries and may be approximate.
        approx: bool,
    },
    /// A file was unlinked.
    Unlink {
        /// Path of the removed name.
        path: BStr,
        /// Device of the file.
        dev: u64,
        /// Inode of the file.
        ino: u64,
        /// Path was rebuilt from dentries and may be approximate.
        approx: bool,
    },
    /// An outbound connect was attempted.
    Connect {
        /// Address family.
        family: Family,
        /// Address as text (IP, or escaped unix path, `@` for abstract).
        addr: String,
        /// Destination port (0 for unix).
        port: u16,
        /// Socket type.
        sock: SockType,
    },
    /// A socket started listening.
    Listen {
        /// Bound address as text.
        addr: String,
        /// Bound port.
        port: u16,
    },
}

/// One observed event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Daemon-assigned, increasing event id.
    pub id: u64,
    /// CLOCK_BOOTTIME timestamp in ns.
    pub ts_ns: u64,
    /// Process the event belongs to.
    pub proc: ProcKey,
    /// Thread id that caused it.
    pub tid: u32,
    /// User id at the time of the event.
    pub uid: u32,
    /// What happened.
    pub kind: EventKind,
}

/// A rule match with its evidence (invariant I9).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Daemon-assigned finding id.
    pub id: u64,
    /// Rule id such as "R001".
    pub rule: String,
    /// Rule title.
    pub title: String,
    /// What the finding is about within the rule (file class, destination
    /// or window), e.g. "ssh_keys". Part of the de-duplication key and of
    /// the allowlist entry that would silence it. Added in WP15 (additive).
    #[serde(default)]
    pub subject: String,
    /// MITRE ATT&CK technique id, if one fits.
    pub attack: Option<String>,
    /// Process the finding is about.
    pub proc: ProcKey,
    /// Executable of that process.
    pub exe: BStr,
    /// Time of the latest evidence (boot ns).
    pub ts_ns: u64,
    /// Rule weight in (0, 1].
    #[serde(serialize_with = "ser_f32")]
    pub weight: f32,
    /// Confidence of this finding in (0, 1].
    #[serde(serialize_with = "ser_f32")]
    pub confidence: f32,
    /// One-line description of what happened.
    pub summary: String,
    /// Reasons it is flagged.
    pub why: Vec<String>,
    /// Harmless explanations.
    pub benign: Vec<String>,
    /// Ids of all evidence events.
    pub evidence: Vec<u64>,
    /// Up to 10 of the evidence events in full.
    pub evidence_events: Vec<Event>,
}

/// Snapshot mode: everything, or one followed tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Mode {
    /// The string "system".
    System(SystemMode),
    /// `{"follow": ProcKey}`.
    Follow {
        /// Root of the followed tree.
        follow: ProcKey,
    },
}

/// The single string value `"system"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemMode {
    /// System-wide tracing.
    System,
}

/// CPU and memory history of one process (1 Hz samples).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Series {
    /// Sample times (boot ns).
    pub t: Vec<u64>,
    /// CPU percent per sample.
    #[serde(serialize_with = "ser_f32_vec")]
    pub cpu: Vec<f32>,
    /// RSS bytes per sample.
    pub rss: Vec<u64>,
}

/// Per-file summary for one process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStat {
    /// Last known path (display only).
    pub path: BStr,
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Number of opens.
    pub opens: u64,
    /// Opened for reading at least once.
    pub read: bool,
    /// Opened for writing at least once.
    pub write: bool,
    /// Bytes read (followed processes only, else 0).
    pub rbytes: u64,
    /// Bytes written (followed processes only, else 0).
    pub wbytes: u64,
    /// Time of the last open (boot ns).
    pub last_ts: u64,
}

/// Per-destination connection summary for one process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnStat {
    /// Address family.
    pub family: Family,
    /// Destination address.
    pub addr: String,
    /// Destination port.
    pub port: u16,
    /// Socket type.
    pub sock: SockType,
    /// Number of connects.
    pub count: u64,
    /// Time of the last connect (boot ns).
    pub last_ts: u64,
}

/// Per-syscall statistics for one process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysStat {
    /// Syscall number.
    pub nr: u32,
    /// Syscall name.
    pub name: String,
    /// Number of calls.
    pub count: u64,
    /// Latency samples (followed processes only).
    pub lat_count: u64,
    /// Total latency in ns (followed processes only).
    pub lat_total_ns: u64,
    /// Maximum latency in ns (followed processes only).
    pub lat_max_ns: u64,
}

/// One line of /proc/<pid>/maps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapRow {
    /// Start address.
    pub start: u64,
    /// End address.
    pub end: u64,
    /// Permissions such as "r-xp".
    pub perms: String,
    /// File offset.
    pub offset: u64,
    /// Device as "maj:min".
    pub dev: String,
    /// Inode.
    pub inode: u64,
    /// Path or pseudo-name such as "[heap]".
    pub path: BStr,
}

/// What happened to one decoy file in a Glasshouse run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecoyState {
    /// Not touched.
    Untouched,
    /// Opened for reading (from the trace).
    Read,
    /// Content changed.
    Modified,
    /// Same inode under a new name.
    Renamed,
    /// Removed.
    Deleted,
}

/// Status of one decoy in a Glasshouse report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecoyStatus {
    /// Path inside the sandbox.
    pub path: BStr,
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// All states that apply, e.g. ["read", "modified", "renamed"].
    pub states: Vec<DecoyState>,
    /// New name if renamed.
    pub new_path: Option<BStr>,
    /// Size before the run.
    pub size_before: u64,
    /// Size after the run, if the file still exists.
    pub size_after: Option<u64>,
    /// Shannon entropy before, bits per byte.
    #[serde(serialize_with = "ser_f32")]
    pub entropy_before: f32,
    /// Shannon entropy after, bits per byte.
    #[serde(serialize_with = "ser_opt_f32")]
    pub entropy_after: Option<f32>,
}

/// A file the sample created.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreatedFile {
    /// Path inside the sandbox.
    pub path: BStr,
    /// Size in bytes.
    pub size: u64,
    /// Shannon entropy, bits per byte.
    #[serde(serialize_with = "ser_f32")]
    pub entropy: f32,
    /// First 256 bytes, only if printable text.
    pub preview: Option<BStr>,
}

/// Final report of a Glasshouse run (plan section 6.3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GhReport {
    /// Run id.
    pub run_id: String,
    /// Sample file name.
    pub sample: BStr,
    /// Arguments given to the sample.
    pub args: Vec<BStr>,
    /// Timeout in seconds.
    pub timeout_s: u32,
    /// Start time (boot ns).
    pub started_ts: u64,
    /// End time (boot ns).
    pub ended_ts: u64,
    /// Exit code of the sample if it exited normally.
    pub exit_code: Option<i32>,
    /// True if the run was killed at the timeout.
    pub timed_out: bool,
    /// One entry per decoy.
    pub decoys: Vec<DecoyStatus>,
    /// Files created by the sample.
    pub created: Vec<CreatedFile>,
    /// All events of the run, in order.
    pub timeline: Vec<Event>,
    /// Connection attempts.
    pub connections: Vec<ConnStat>,
    /// Processes started in the box.
    pub children: Vec<ProcKey>,
    /// Findings raised during the run.
    pub findings: Vec<Finding>,
    /// Loss counters during the run.
    pub loss: Loss,
    /// The limitation text from plan section 6.4.
    pub limitation: String,
}
