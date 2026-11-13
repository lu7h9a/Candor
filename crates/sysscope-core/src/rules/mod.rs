//! Rule functions (plan 5.4). Each rule looks at one event (or one tick)
//! together with the state and returns the hits it sees. Thresholds, path
//! classes and texts come from `config::Rules`, never from constants here.

pub mod files;
pub mod procs;
pub mod windows;

use crate::glob;
use crate::proc::Proc;
use std::collections::BTreeMap;
use sysscope_proto::BStr;

/// Expands a class pattern for one process: "~/" becomes the process's home
/// directory, or, when that is unknown, any /home/<user> or /root.
pub fn pattern_variants(pattern: &str, p: Option<&Proc>) -> Vec<Vec<u8>> {
    if !pattern.starts_with("~/") {
        return vec![pattern.as_bytes().to_vec()];
    }
    match p.map(|p| p.home.as_bytes()).filter(|h| !h.is_empty()) {
        Some(home) => vec![glob::expand_home(pattern, home)],
        None => vec![
            glob::expand_home(pattern, b"/home/*"),
            glob::expand_home(pattern, b"/root"),
        ],
    }
}

/// True if `path` matches any pattern of a class for this process.
pub fn class_matches(
    patterns: &[String],
    excludes: &[String],
    path: &BStr,
    p: Option<&Proc>,
) -> bool {
    let bytes = path.as_bytes();
    if excludes.iter().any(|x| bytes.ends_with(x.as_bytes())) {
        return false;
    }
    patterns
        .iter()
        .flat_map(|pat| pattern_variants(pat, p))
        .any(|pat| glob::matches(&pat, bytes))
}

/// Placeholder values for rule texts.
pub fn vars(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}
