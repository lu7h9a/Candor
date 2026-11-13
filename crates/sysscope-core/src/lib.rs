//! Pure core of SysScope: process table, retention, rules and scoring.
//!
//! "Pure" means this crate never touches files, sockets, clocks or threads
//! (invariant I7). Time only enters through event timestamps, so feeding
//! the same recorded events in always produces the same output. That is
//! what makes the detector testable by replaying fixture files.
#![forbid(unsafe_code)]
