//! Inputs to the core, and the `*.events.jsonl` recording format.
//!
//! The daemon turns kernel records and /proc samples into these values and
//! feeds them to `State`. The same values, one JSON object per line, make up
//! an events recording, so any run can be replayed exactly (invariant I7).

use serde::{Deserialize, Serialize};
use sysscope_proto::{BStr, Event, Loss, ProcKey, SysStat};

/// One process as read from /proc by the sampler.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcSample {
    /// Identity.
    pub key: ProcKey,
    /// Parent pid (field 4 of stat).
    pub ppid: u32,
    /// readlink of /proc/<pid>/exe (may be empty for kernel threads).
    pub exe: BStr,
    /// comm.
    pub comm: BStr,
    /// Real uid.
    pub uid: u32,
    /// True for kernel threads.
    pub kthread: bool,
    /// utime + stime in clock ticks.
    pub cpu_ticks: u64,
    /// Resident set size in bytes.
    pub rss: u64,
    /// Number of threads.
    pub threads: u32,
    /// Bytes read (rchar or read_bytes).
    pub io_r: u64,
    /// Bytes written.
    pub io_w: u64,
}

/// One input to the core. The JSON form is tagged by `"t"`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Input {
    /// A kernel event.
    RawEvent {
        /// The event.
        event: Event,
    },
    /// A full /proc scan taken at `ts_ns`.
    Samples {
        /// Scan time (boot ns).
        ts_ns: u64,
        /// Every process found.
        samples: Vec<ProcSample>,
    },
    /// Kernel loss counters read at `ts_ns`.
    Loss {
        /// The counters.
        loss: Loss,
    },
    /// What the daemon verified about a process's executable at exec time.
    ExeMeta {
        /// The process.
        proc: ProcKey,
        /// Owned by root, and neither the file nor its directory is group-
        /// or world-writable (required for allowlist matches, plan 5.3).
        trusted: bool,
        /// Lives in a root-owned system directory such as /usr/bin.
        system_dir: bool,
        /// Home directory of the process's uid (for "~/" path classes).
        home: BStr,
        /// The executable's directory is world-writable (R002).
        #[serde(default)]
        world_writable_dir: bool,
        /// The interpreter's script (Proc::script) passed the same check
        /// as `trusted` (for allowlist entries with `script`).
        #[serde(default)]
        script_trusted: bool,
        /// The exe path names a different file (or none) on the host: the
        /// process sees its own mount namespace or root (Q7 answer A).
        #[serde(default)]
        private_view: bool,
    },
    /// Files whose (dev, ino) are decoys: Glasshouse manifest entries or
    /// host canaries from /etc/sysscope/canaries.toml (R012). Replaces the set.
    Decoys {
        /// (dev, ino) pairs.
        inodes: Vec<(u64, u64)>,
    },
    /// Per-process kernel budget drops during the second ending at `ts_ns`
    /// (R008 and ProcRow.ev_dropped). Processes without drops are omitted.
    BudgetDrops {
        /// End of the one-second interval (boot ns).
        ts_ns: u64,
        /// (process, events dropped in that second).
        drops: Vec<(ProcKey, u64)>,
    },
    /// Cumulative syscall statistics per process (WP08), read once a second.
    SysTotals {
        /// Read time (boot ns).
        ts_ns: u64,
        /// (process, statistics of one syscall number).
        totals: Vec<(ProcKey, SysStat)>,
    },
    /// Time passes (retention, rules).
    Tick {
        /// Current time (boot ns).
        ts_ns: u64,
    },
}
