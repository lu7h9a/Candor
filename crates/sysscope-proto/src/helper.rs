//! The line protocol between the daemon and the Glasshouse helper (plan
//! 6.1): one JSON object per line over the helper's stdin/stdout. The
//! daemon treats helper output like client input: lines are length-capped
//! before parsing and unknown fields are refused.

use crate::{CreatedFile, DecoyStatus, GhState};
use serde::{Deserialize, Serialize};

/// Longest helper line the daemon accepts (a differ result with 20 000
/// entries fits easily).
pub const MAX_HELPER_LINE: usize = 16 * 1024 * 1024;

/// What the job file of one run holds (written by the daemon next to the
/// uploaded sample, read by the helper and by stage2). Passing these in a
/// file keeps untrusted names and arguments off every command line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhJob {
    /// Sample file name inside the box (`/sample/<name>`), already sanitised.
    pub name: String,
    /// Arguments for the sample (raw bytes, escaped as BStr).
    pub args: Vec<crate::BStr>,
    /// Timeout in seconds (1..=600).
    pub timeout_s: u32,
    /// Calibration run: no seccomp filter, sample under `strace -f -c`
    /// (only `sysscope-glasshouse run-local --calibrate`, never the daemon).
    #[serde(default)]
    pub calibrate: bool,
}

/// Helper -> daemon.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", deny_unknown_fields)]
pub enum HelperOut {
    /// Progress for the client.
    Status {
        /// State.
        state: GhState,
        /// Human-readable text.
        message: String,
    },
    /// The box exists and is waiting: trace it, then answer `Go`.
    Need {
        /// cgroup v2 id of the box unit (inode of its cgroup directory).
        cgroup_id: u64,
        /// Main pid of the box unit (stage2, later bubblewrap).
        pid: u32,
        /// st_dev of the run directory's tmpfs (userspace encoding).
        run_dev: u64,
        /// Host path of the run directory.
        run_dir: String,
        /// Every decoy, state untouched.
        decoys: Vec<DecoyStatus>,
    },
    /// The box is empty; the differ (running as the sandbox user) starts
    /// now, so the daemon stops attributing that user's events to the run.
    Ended {},
    /// The differ result after the box is empty.
    Diff {
        /// Exit code of the box unit, if it exited normally.
        exit_code: Option<i32>,
        /// Killed at the timeout.
        timed_out: bool,
        /// Cancelled by the client.
        cancelled: bool,
        /// One entry per decoy (states from the file system only).
        decoys: Vec<DecoyStatus>,
        /// New files.
        created: Vec<CreatedFile>,
        /// Caps reached, changed non-decoy files.
        notes: Vec<String>,
    },
    /// The run could not happen or broke off.
    Failed {
        /// Why (shown to the user, escaped).
        message: String,
    },
}

/// Daemon -> helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", deny_unknown_fields)]
pub enum HelperIn {
    /// Tracing is set up: release the box.
    Go {},
    /// Tracing could not be set up: do not run.
    Refuse {
        /// Why.
        message: String,
    },
    /// Stop the run now (kill the box).
    Cancel {},
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_lines_round_trip_and_refuse_unknown_fields() {
        let m = HelperOut::Status {
            state: GhState::Running,
            message: "x".into(),
        };
        let s = serde_json::to_string(&m).unwrap_or_default();
        assert_eq!(serde_json::from_str::<HelperOut>(&s).ok(), Some(m));
        assert!(serde_json::from_str::<HelperIn>(r#"{"t":"Go","x":1}"#).is_err());
        assert_eq!(
            serde_json::from_str::<HelperIn>(r#"{"t":"Cancel"}"#).ok(),
            Some(HelperIn::Cancel {})
        );
    }
}
