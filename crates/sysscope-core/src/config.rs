//! Detection configuration: `rules.toml` and `allow.toml`.
//!
//! Both files exist twice: an embedded default (compiled into the binary)
//! and an optional root-owned override in /etc/sysscope/. The daemon reads
//! the override files and passes their text here; this module stays pure.
//! Override values replace defaults key by key; allowlist entries are added.
//! Any unknown key, wrong type or out-of-range value is an error with a
//! clear message, and the daemon refuses to start on it.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The embedded default rules.
pub const DEFAULT_RULES: &str = include_str!("../rules.toml");
/// The embedded default allowlist.
pub const DEFAULT_ALLOW: &str = include_str!("../allow.toml");

/// Why a configuration file was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Not valid TOML or does not match the schema.
    #[error("{file}: {msg}")]
    Parse {
        /// Which file.
        file: String,
        /// Parser message (includes line and column).
        msg: String,
    },
    /// A value is out of range or inconsistent.
    #[error("{file}: {msg}")]
    Invalid {
        /// Which file.
        file: String,
        /// What is wrong.
        msg: String,
    },
}

/// Score settings.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScoreCfg {
    /// Half-life of a finding's contribution, seconds.
    pub half_life_s: f64,
    /// Score at which a process becomes "suspicious".
    pub suspicious_at: u8,
    /// Score at which a process becomes "high".
    pub high_at: u8,
    /// Evidence events copied into a finding.
    pub max_evidence_events: usize,
}

/// One rule's text, weight and parameters. Parameters not used by a rule
/// stay at their defaults.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleCfg {
    /// Title.
    pub title: String,
    /// ATT&CK technique id.
    pub attack: Option<String>,
    /// Weight in (0, 1].
    pub weight: f64,
    /// Reasons, with {placeholders}.
    pub why: Vec<String>,
    /// Harmless explanations.
    pub benign: Vec<String>,
    /// Rule switched off.
    #[serde(default)]
    pub disabled: bool,
    /// Generic confidence.
    pub confidence: Option<f64>,
    /// R001: exe outside root-owned system dirs.
    pub confidence_untrusted_exe: Option<f64>,
    /// R001: exe in a root-owned system dir.
    pub confidence_system_exe: Option<f64>,
    /// R004/R012: stronger confidence.
    pub confidence_strong: Option<f64>,
    /// R004: subjects with the strong confidence.
    #[serde(default)]
    pub strong_subjects: Vec<String>,
    /// R002: temp directories (prefixes).
    #[serde(default)]
    pub dirs: Vec<String>,
    /// Window length, seconds.
    pub window_s: Option<u64>,
    /// R005.
    pub rename_min_files: Option<usize>,
    /// R005.
    pub rename_common_ext_share: Option<f64>,
    /// R005.
    pub confidence_common_ext: Option<f64>,
    /// R005.
    pub confidence_mixed: Option<f64>,
    /// R005.
    pub trunc_min_files: Option<usize>,
    /// R005.
    pub trunc_min_dirs: Option<usize>,
    /// R005.
    pub confidence_trunc: Option<f64>,
    /// R005: user-data roots.
    #[serde(default)]
    pub roots: Vec<String>,
    /// R005: path components that exclude a file.
    #[serde(default)]
    pub excluded_components: Vec<String>,
    /// R006.
    pub confidence_public: Option<f64>,
    /// R006.
    pub min_connects: Option<usize>,
    /// R006.
    pub min_span_s: Option<u64>,
    /// R006.
    pub min_mean_interval_s: Option<f64>,
    /// R006.
    pub max_mean_interval_s: Option<f64>,
    /// R006.
    pub max_cv: Option<f64>,
    /// R006.
    pub max_keys: Option<usize>,
    /// R007.
    pub distinct_dests: Option<usize>,
    /// R007.
    pub ports_one_addr: Option<usize>,
    /// R007.
    pub addrs_one_port: Option<usize>,
    /// R008.
    pub consecutive_s: Option<u64>,
    /// R012.
    pub confidence_write: Option<f64>,
    /// R012.
    pub confidence_read: Option<f64>,
    /// R009: shells and interpreters (exe patterns).
    #[serde(default)]
    pub programs: Vec<String>,
    /// R009: parents that should not start them (exe patterns).
    #[serde(default)]
    pub parents: Vec<String>,
    /// R006: also count loopback destinations. Test-only (owner's Q3
    /// answer A: the beacon simulator talks to 127.0.0.1); never in the
    /// shipped rules.
    pub include_loopback: Option<bool>,
    /// R011: known debuggers and tracers (exe patterns).
    #[serde(default)]
    pub debuggers: Vec<String>,
}

/// A named group of path patterns.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PathClass {
    /// Subject id, e.g. "ssh_keys".
    pub subject: String,
    /// Description used in explanations.
    pub desc: String,
    /// Patterns ("~/" = user's home, "*" = any bytes except "/").
    pub paths: Vec<String>,
    /// Suffixes that exclude a match (e.g. ".pub").
    #[serde(default)]
    pub exclude_suffix: Vec<String>,
}

/// The whole rules file.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Format version (1).
    pub version: u32,
    /// Score settings.
    pub score: ScoreCfg,
    /// Rules by id.
    pub rules: BTreeMap<String, RuleCfg>,
    /// Credential path classes.
    #[serde(default)]
    pub credentials: Vec<PathClass>,
    /// Persistence path classes.
    #[serde(default)]
    pub persistence: Vec<PathClass>,
}

/// One allowlist entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// Rule id.
    pub rule: String,
    /// Executable path; "*" allowed in the last component only.
    pub exe: String,
    /// Subject, or "*".
    pub subject: String,
    /// Why this is harmless.
    pub reason: String,
    /// For an interpreter (`exe` is perl, python, a shell...): the script it
    /// must be running. The script file must pass the same root-owned,
    /// not-writable check as executables (an extension of plan 5.3 for
    /// system scripts such as dpkg-preconfigure).
    #[serde(default)]
    pub script: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    #[serde(default)]
    allow: Vec<AllowEntry>,
}

/// Replaces values of `base` with those of `over`, table by table.
fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

fn parse_table(file: &str, text: &str) -> Result<toml::Table, ConfigError> {
    text.parse::<toml::Table>().map_err(|e| ConfigError::Parse {
        file: file.into(),
        msg: e.to_string(),
    })
}

fn invalid(file: &str, msg: String) -> ConfigError {
    ConfigError::Invalid {
        file: file.into(),
        msg,
    }
}

fn check_unit(file: &str, what: &str, v: Option<f64>) -> Result<(), ConfigError> {
    match v {
        Some(x) if x.is_nan() || x <= 0.0 || x > 1.0 => {
            Err(invalid(file, format!("{what} must be in (0, 1], got {x}")))
        }
        _ => Ok(()),
    }
}

impl Rules {
    /// Parses the embedded defaults merged with an optional override text.
    pub fn load(override_text: Option<&str>) -> Result<Rules, ConfigError> {
        let mut table = parse_table("embedded rules.toml", DEFAULT_RULES)?;
        let file = if override_text.is_some() {
            "/etc/sysscope/rules.toml"
        } else {
            "embedded rules.toml"
        };
        if let Some(text) = override_text {
            merge(&mut table, parse_table(file, text)?);
        }
        let rules: Rules = toml::Value::Table(table)
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::Parse {
                file: file.into(),
                msg: e.to_string(),
            })?;
        rules.validate(file)?;
        Ok(rules)
    }

    fn validate(&self, file: &str) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(invalid(
                file,
                format!("version must be 1, got {}", self.version),
            ));
        }
        // Written this way so NaN is rejected too.
        if self.score.half_life_s.is_nan() || self.score.half_life_s <= 0.0 {
            return Err(invalid(file, "score.half_life_s must be > 0".into()));
        }
        if self.score.suspicious_at == 0
            || self.score.suspicious_at >= self.score.high_at
            || self.score.high_at > 100
        {
            return Err(invalid(
                file,
                "need 0 < score.suspicious_at < score.high_at <= 100".into(),
            ));
        }
        for (id, r) in &self.rules {
            check_unit(file, &format!("rules.{id}.weight"), Some(r.weight))?;
            for (name, v) in [
                ("confidence", r.confidence),
                ("confidence_untrusted_exe", r.confidence_untrusted_exe),
                ("confidence_system_exe", r.confidence_system_exe),
                ("confidence_strong", r.confidence_strong),
                ("confidence_common_ext", r.confidence_common_ext),
                ("confidence_mixed", r.confidence_mixed),
                ("confidence_trunc", r.confidence_trunc),
                ("confidence_public", r.confidence_public),
                ("confidence_write", r.confidence_write),
                ("confidence_read", r.confidence_read),
            ] {
                check_unit(file, &format!("rules.{id}.{name}"), v)?;
            }
            if r.title.is_empty() {
                return Err(invalid(file, format!("rules.{id}.title is empty")));
            }
        }
        for c in self.credentials.iter().chain(&self.persistence) {
            if c.subject.is_empty() || c.paths.is_empty() {
                return Err(invalid(
                    file,
                    "every path class needs a subject and paths".into(),
                ));
            }
        }
        Ok(())
    }

    /// The rule with this id, if configured and not disabled.
    pub fn rule(&self, id: &str) -> Option<&RuleCfg> {
        self.rules.get(id).filter(|r| !r.disabled)
    }
}

/// Parses the embedded allowlist plus an optional override (entries are added).
pub fn load_allow(
    rules: &Rules,
    override_text: Option<&str>,
) -> Result<Vec<AllowEntry>, ConfigError> {
    let mut out = Vec::new();
    let mut texts = vec![("embedded allow.toml", DEFAULT_ALLOW)];
    if let Some(t) = override_text {
        texts.push(("/etc/sysscope/allow.toml", t));
    }
    for (file, text) in texts {
        let parsed: AllowFile = toml::from_str(text).map_err(|e| ConfigError::Parse {
            file: file.into(),
            msg: e.to_string(),
        })?;
        for a in parsed.allow {
            if !rules.rules.contains_key(&a.rule) {
                return Err(invalid(
                    file,
                    format!("allow entry for unknown rule {:?}", a.rule),
                ));
            }
            if !a.exe.starts_with('/') {
                return Err(invalid(
                    file,
                    format!("allow exe must be absolute: {:?}", a.exe),
                ));
            }
            let dir = a.exe.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
            if dir.contains('*') {
                return Err(invalid(
                    file,
                    format!(
                        "allow exe may use * only in its last component: {:?}",
                        a.exe
                    ),
                ));
            }
            if a.reason.trim().is_empty() {
                return Err(invalid(
                    file,
                    format!("allow entry for {:?} needs a reason", a.exe),
                ));
            }
            out.push(a);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_load() {
        let r = Rules::load(None).unwrap();
        assert_eq!(r.rule("R001").unwrap().weight, 0.6);
        assert_eq!(load_allow(&r, None).unwrap().len(), 44);
    }

    #[test]
    fn override_replaces_values() {
        let r = Rules::load(Some("[rules.R002]\nweight = 0.5\n")).unwrap();
        assert_eq!(r.rule("R002").unwrap().weight, 0.5);
        assert_eq!(
            r.rule("R002").unwrap().title,
            "Execution from a writable temp location"
        );
    }

    #[test]
    fn bad_files_are_rejected_with_clear_errors() {
        let e = Rules::load(Some("[rules.R002]\nwieght = 0.5\n")).unwrap_err();
        assert!(e.to_string().contains("wieght"), "{e}");
        let e = Rules::load(Some("[rules.R002]\nweight = 1.5\n")).unwrap_err();
        assert!(e.to_string().contains("rules.R002.weight"), "{e}");
        let e = Rules::load(Some("not toml [")).unwrap_err();
        assert!(e.to_string().starts_with("/etc/sysscope/rules.toml"), "{e}");
        let r = Rules::load(None).unwrap();
        assert!(
            load_allow(
                &r,
                Some("[[allow]]\nrule=\"R001\"\nexe=\"/tmp/*/x\"\nsubject=\"*\"\nreason=\"r\"\n")
            )
            .is_err()
        );
        assert!(
            load_allow(
                &r,
                Some("[[allow]]\nrule=\"R999\"\nexe=\"/x\"\nsubject=\"*\"\nreason=\"r\"\n")
            )
            .is_err()
        );
        assert!(
            load_allow(
                &r,
                Some("[[allow]]\nrule=\"R001\"\nexe=\"/x\"\nsubject=\"*\"\nreason=\" \"\n")
            )
            .is_err()
        );
    }
}
