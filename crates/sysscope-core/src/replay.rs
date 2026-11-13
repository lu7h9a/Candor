//! Replaying an events recording (`*.events.jsonl`) through a fresh `State`.
//!
//! The first line is the header `{"sysscope_record":1, ...}`; every other
//! line is one `Input`. Bad lines are reported with their line number; the
//! function never panics, whatever the text (the input is untrusted when a
//! user replays a file someone sent them).

use crate::input::Input;
use crate::state::State;

/// Recording format version this build reads.
pub const RECORD_VERSION: u64 = 1;

/// Why a recording could not be replayed.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// First line is not a valid header.
    #[error("line 1: not a sysscope recording header ({0})")]
    BadHeader(String),
    /// Unsupported recording version.
    #[error("line 1: recording version {0} is not supported (this build reads {RECORD_VERSION})")]
    Version(u64),
    /// A line is not a valid input.
    #[error("line {line}: {msg}")]
    BadLine {
        /// 1-based line number.
        line: usize,
        /// Parser message.
        msg: String,
    },
}

/// Parses a recording into its inputs.
pub fn parse(text: &str) -> Result<Vec<Input>, ReplayError> {
    let mut inputs = Vec::new();
    for_each_input(text.lines(), |i| inputs.push(i))?;
    Ok(inputs)
}

/// Streams a recording line by line, calling `f` for every input, so large
/// recordings never have to be held in memory.
pub fn for_each_input<S: AsRef<str>>(
    lines: impl Iterator<Item = S>,
    mut f: impl FnMut(Input),
) -> Result<(), ReplayError> {
    let mut lines = lines
        .enumerate()
        .filter(|(_, l)| !l.as_ref().trim().is_empty());
    let (_, first) = lines
        .next()
        .ok_or_else(|| ReplayError::BadHeader("empty file".into()))?;
    let header: serde_json::Value =
        serde_json::from_str(first.as_ref()).map_err(|e| ReplayError::BadHeader(e.to_string()))?;
    let version = header
        .get("sysscope_record")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ReplayError::BadHeader("missing \"sysscope_record\"".into()))?;
    if version != RECORD_VERSION {
        return Err(ReplayError::Version(version));
    }
    for (i, line) in lines {
        let input: Input =
            serde_json::from_str(line.as_ref()).map_err(|e| ReplayError::BadLine {
                line: i + 1,
                msg: e.to_string(),
            })?;
        f(input);
    }
    Ok(())
}

/// Replays a recording and returns the final state.
pub fn replay(text: &str) -> Result<State, ReplayError> {
    replay_lines(text.lines())
}

/// Replays a recording given as lines (for example from a `BufRead`).
pub fn replay_lines<S: AsRef<str>>(lines: impl Iterator<Item = S>) -> Result<State, ReplayError> {
    let mut state = State::new();
    for_each_input(lines, |input| state.apply(&input))?;
    Ok(state)
}

/// Replays a recording through a full `Engine` (state + detector) and
/// returns it together with every alert raised, in order.
pub fn replay_engine<S: AsRef<str>>(
    engine: &mut crate::engine::Engine,
    lines: impl Iterator<Item = S>,
) -> Result<Vec<sysscope_proto::Finding>, ReplayError> {
    let mut alerts = Vec::new();
    for_each_input(lines, |input| alerts.extend(engine.apply(&input)))?;
    Ok(alerts)
}
