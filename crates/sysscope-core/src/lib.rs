//! Pure core of SysScope: process table, retention, rules and scoring.
//!
//! "Pure" means this crate never touches files, sockets, clocks or threads
//! (invariant I7). Time only enters through event timestamps, so feeding
//! the same recorded events in always produces the same output. That is
//! what makes the detector testable by replaying fixture files.
#![forbid(unsafe_code)]

pub mod config;
pub mod detect;
pub mod engine;
pub mod explain;
pub mod glob;
pub mod input;
pub mod limits;
pub mod proc;
pub mod replay;
pub mod rules;
pub mod state;

pub use detect::{Band, Detector, Hit};
pub use engine::Engine;
pub use input::{Input, ProcSample};
pub use state::{State, StateStats};
