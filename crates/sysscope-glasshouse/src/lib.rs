//! Glasshouse: run a program in a decoy-filled sandbox and report what it touched.
//!
//! This library holds the decoy generator, the run-directory differ and the
//! report builder (docs/MASTER_PLAN.md section 6). Glasshouse is a
//! behaviour-demonstration sandbox, not a malware containment system.
#![forbid(unsafe_code)]

pub mod decoys;
pub mod seccomp;
