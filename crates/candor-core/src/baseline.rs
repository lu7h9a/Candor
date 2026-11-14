//! R100 "Unlike itself" (WP28, experimental, off by default).
//!
//! Each run of an executable is summarised as a behaviour vector: its top 32
//! syscalls by count, the directory classes of the files it opened, its
//! number of distinct network destinations and of children. The vectors of
//! earlier runs are averaged into a per-executable baseline. A run is
//! flagged when the Jensen-Shannon divergence (base 2, 0..1) between it and
//! the baseline exceeds the 99th percentile of the baseline's own earlier
//! divergences - but only once the baseline is at least 6 hours old and has
//! at least 20 runs. Flagged runs are not learned. The store is bounded
//! (500 executables, 64 features each, 200 divergences each) and versioned.

use crate::proc::Proc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Store format version.
pub const VERSION: u32 = 1;
/// Executables kept.
pub const MAX_EXES: usize = 500;
/// Features kept per executable.
pub const MAX_FEATURES: usize = 64;
/// Past divergences kept per executable.
pub const MAX_DIVS: usize = 200;
/// Minimum runs before flagging.
pub const MIN_RUNS: u32 = 20;
/// Minimum age before flagging (6 h, boot ns).
pub const MIN_AGE_NS: u64 = 6 * 3600 * 1_000_000_000;

/// A behaviour vector: feature -> weight (normalised when compared).
pub type Vector = BTreeMap<String, f64>;

/// One executable's baseline.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExeBaseline {
    /// First run seen (boot ns of this daemon's clock at learning time).
    pub first_ts: u64,
    /// Last run seen.
    pub last_ts: u64,
    /// Runs learned.
    pub runs: u32,
    /// Average normalised vector.
    pub agg: Vector,
    /// Divergences of learned runs from the baseline at the time.
    pub divs: Vec<f32>,
}

/// All baselines (`/var/lib/candor/baselines.json`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baselines {
    /// Format version.
    pub version: u32,
    /// By executable path (escaped).
    pub exes: BTreeMap<String, ExeBaseline>,
}

impl Default for Baselines {
    fn default() -> Self {
        Baselines {
            version: VERSION,
            exes: BTreeMap::new(),
        }
    }
}

/// A run that does not look like its executable's baseline.
#[derive(Clone, Debug, PartialEq)]
pub struct Unlike {
    /// Divergence of this run.
    pub divergence: f64,
    /// The baseline's 99th percentile.
    pub p99: f64,
    /// Runs in the baseline.
    pub runs: u32,
}

fn normalise(v: &Vector) -> Vector {
    let sum: f64 = v.values().filter(|x| x.is_finite() && **x > 0.0).sum();
    if sum <= 0.0 {
        return Vector::new();
    }
    v.iter()
        .filter(|(_, x)| x.is_finite() && **x > 0.0)
        .map(|(k, x)| (k.clone(), x / sum))
        .collect()
}

/// Jensen-Shannon divergence, base 2 (0 = same, 1 = disjoint).
pub fn js_divergence(a: &Vector, b: &Vector) -> f64 {
    let (p, q) = (normalise(a), normalise(b));
    if p.is_empty() || q.is_empty() {
        return if p.is_empty() && q.is_empty() {
            0.0
        } else {
            1.0
        };
    }
    let mut keys: Vec<&String> = p.keys().chain(q.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut d = 0.0;
    for k in keys {
        let pi = p.get(k).copied().unwrap_or(0.0);
        let qi = q.get(k).copied().unwrap_or(0.0);
        let m = (pi + qi) / 2.0;
        if pi > 0.0 {
            d += 0.5 * pi * (pi / m).log2();
        }
        if qi > 0.0 {
            d += 0.5 * qi * (qi / m).log2();
        }
    }
    d.clamp(0.0, 1.0)
}

/// 99th percentile (nearest rank) of the values.
pub fn p99(values: &[f32]) -> f64 {
    if values.is_empty() {
        return 1.0;
    }
    let mut v: Vec<f32> = values.iter().copied().filter(|x| x.is_finite()).collect();
    v.sort_by(f32::total_cmp);
    let rank = ((0.99 * v.len() as f64).ceil() as usize).clamp(1, v.len());
    f64::from(v.get(rank - 1).copied().unwrap_or(1.0))
}

/// Directory class of a path: the first two components, with user and
/// process names generalised ("/home/*", "/proc/*").
fn dir_class(path: &[u8]) -> String {
    let s = String::from_utf8_lossy(path);
    let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).take(2).collect();
    match parts.as_slice() {
        ["home", _] => "/home/*".into(),
        ["proc", p] if p.chars().all(|c| c.is_ascii_digit()) => "/proc/*".into(),
        ["tmp", _] => "/tmp/*".into(),
        [a, b] => format!("/{a}/{b}"),
        [a] => format!("/{a}"),
        _ => "/".into(),
    }
}

/// The behaviour vector of one run of a process.
pub fn vector_of(p: &Proc) -> Vector {
    let mut v = Vector::new();
    let mut sys: Vec<(&String, u64)> = p.syscalls.values().map(|s| (&s.name, s.count)).collect();
    sys.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (name, n) in sys.into_iter().take(32) {
        *v.entry(format!("sys:{name}")).or_default() += n as f64;
    }
    for f in p.files.values() {
        *v.entry(format!("dir:{}", dir_class(f.path.as_bytes())))
            .or_default() += f.opens as f64;
    }
    let dsts = p.conns.len() as f64 + p.conns_other as f64;
    if dsts > 0.0 {
        v.insert("net:destinations".into(), dsts);
    }
    if p.n_child > 0 {
        v.insert("proc:children".into(), p.n_child as f64);
    }
    v
}

fn cap_features(v: &mut Vector) {
    if v.len() <= MAX_FEATURES {
        return;
    }
    let mut items: Vec<(String, f64)> = std::mem::take(v).into_iter().collect();
    items.sort_by(|a, b| b.1.total_cmp(&a.1));
    items.truncate(MAX_FEATURES);
    *v = items.into_iter().collect();
}

impl Baselines {
    /// Parses a stored file; a wrong version or malformed file is an error
    /// (the caller then starts empty and says so).
    pub fn from_json(text: &str) -> Result<Baselines, String> {
        let b: Baselines = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if b.version != VERSION {
            return Err(format!(
                "baseline version {} (expected {VERSION})",
                b.version
            ));
        }
        if b.exes.len() > MAX_EXES {
            return Err("too many executables".into());
        }
        Ok(b)
    }

    /// Serialised form.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Compares one finished run with its executable's baseline and learns
    /// from it unless it is flagged.
    pub fn observe(&mut self, exe: &str, run: &Vector, now: u64) -> Option<Unlike> {
        if run.is_empty() {
            return None;
        }
        if !self.exes.contains_key(exe) && self.exes.len() >= MAX_EXES {
            // Forget the executable seen longest ago.
            if let Some(old) = self
                .exes
                .iter()
                .min_by_key(|(_, b)| b.last_ts)
                .map(|(k, _)| k.clone())
            {
                self.exes.remove(&old);
            }
        }
        let b = self
            .exes
            .entry(exe.to_string())
            .or_insert_with(|| ExeBaseline {
                first_ts: now,
                ..ExeBaseline::default()
            });
        let p = normalise(run);
        let d = if b.agg.is_empty() {
            None
        } else {
            Some(js_divergence(&p, &b.agg))
        };
        let mature = b.runs >= MIN_RUNS
            && now.saturating_sub(b.first_ts) >= MIN_AGE_NS
            && b.divs.len() >= MIN_RUNS as usize;
        if let Some(d) = d
            && mature
        {
            let limit = p99(&b.divs);
            if d > limit {
                b.last_ts = now;
                return Some(Unlike {
                    divergence: d,
                    p99: limit,
                    runs: b.runs,
                });
            }
        }
        if let Some(d) = d {
            b.divs.push(d as f32);
            if b.divs.len() > MAX_DIVS {
                b.divs.remove(0);
            }
        }
        // Running average of normalised vectors.
        let n = f64::from(b.runs);
        let mut keys: Vec<String> = b.agg.keys().chain(p.keys()).cloned().collect();
        keys.sort();
        keys.dedup();
        let mut agg = Vector::new();
        for k in keys {
            let old = b.agg.get(&k).copied().unwrap_or(0.0);
            let new = p.get(&k).copied().unwrap_or(0.0);
            agg.insert(k, (old * n + new) / (n + 1.0));
        }
        cap_features(&mut agg);
        b.agg = agg;
        b.runs = b.runs.saturating_add(1);
        b.last_ts = now;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_of(pairs: &[(&str, f64)]) -> Vector {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn divergence_bounds_and_symmetry() {
        let a = vec_of(&[("sys:read", 10.0), ("sys:write", 10.0)]);
        let b = vec_of(&[("sys:connect", 5.0)]);
        assert!(js_divergence(&a, &a) < 1e-12);
        assert!((js_divergence(&a, &b) - 1.0).abs() < 1e-12);
        let c = vec_of(&[("sys:read", 10.0), ("sys:connect", 10.0)]);
        let (x, y) = (js_divergence(&a, &c), js_divergence(&c, &a));
        assert!((x - y).abs() < 1e-12 && x > 0.0 && x < 1.0);
        // Scale does not matter, only proportions.
        let a10 = vec_of(&[("sys:read", 100.0), ("sys:write", 100.0)]);
        assert!(js_divergence(&a, &a10) < 1e-12);
    }

    #[test]
    fn p99_uses_nearest_rank() {
        let v: Vec<f32> = (1..=100).map(|i| i as f32 / 100.0).collect();
        assert!((p99(&v) - 0.99).abs() < 1e-6);
        assert_eq!(p99(&[]), 1.0);
    }

    #[test]
    fn young_or_small_baselines_never_flag_then_an_unlike_run_is_flagged() {
        let mut bl = Baselines::default();
        let hour = 3600 * 1_000_000_000u64;
        let normal = |i: u32| {
            vec_of(&[
                ("sys:read", 50.0 + f64::from(i % 5)),
                ("sys:write", 20.0),
                ("dir:/usr/lib", 10.0),
            ])
        };
        let odd = vec_of(&[
            ("sys:connect", 40.0),
            ("net:destinations", 30.0),
            ("dir:/home/*", 25.0),
        ]);
        // 25 normal runs within one hour: never flagged, even the odd one.
        for i in 0..25 {
            assert!(
                bl.observe("/usr/bin/x", &normal(i), hour + u64::from(i))
                    .is_none()
            );
        }
        // Another executable, young: an odd run is not flagged (and is
        // learned, as everything is while the baseline grows).
        for i in 0..25 {
            bl.observe("/usr/bin/y", &normal(i), hour + u64::from(i));
        }
        assert!(
            bl.observe("/usr/bin/y", &odd, 2 * hour).is_none(),
            "baseline too young"
        );
        // 7 h later, a normal run passes and an odd one is flagged.
        let later = 8 * hour;
        assert!(bl.observe("/usr/bin/x", &normal(3), later).is_none());
        let u = bl.observe("/usr/bin/x", &odd, later + 1).expect("flagged");
        assert!(u.divergence > u.p99 && u.runs >= MIN_RUNS);
        // A flagged run is not learned.
        let runs = bl.exes["/usr/bin/x"].runs;
        assert!(bl.observe("/usr/bin/x", &odd, later + 2).is_some());
        assert_eq!(bl.exes["/usr/bin/x"].runs, runs);
    }

    #[test]
    fn store_is_bounded_and_round_trips() {
        let mut bl = Baselines::default();
        for i in 0..(MAX_EXES + 10) {
            let mut v = Vector::new();
            for f in 0..(MAX_FEATURES + 20) {
                v.insert(format!("sys:s{f}"), (f + 1) as f64);
            }
            bl.observe(&format!("/bin/e{i}"), &v, i as u64);
        }
        assert_eq!(bl.exes.len(), MAX_EXES);
        assert!(!bl.exes.contains_key("/bin/e0"), "oldest evicted");
        assert!(bl.exes.values().all(|b| b.agg.len() <= MAX_FEATURES));
        let back = Baselines::from_json(&bl.to_json()).unwrap();
        assert_eq!(back.exes.len(), bl.exes.len());
        assert!(Baselines::from_json(r#"{"version":2,"exes":{}}"#).is_err());
        assert!(Baselines::from_json("not json").is_err());
    }

    #[test]
    fn dir_classes_generalise_names() {
        assert_eq!(dir_class(b"/home/alice/.ssh/id"), "/home/*");
        assert_eq!(dir_class(b"/proc/1234/status"), "/proc/*");
        assert_eq!(dir_class(b"/usr/lib/x/y.so"), "/usr/lib");
        assert_eq!(dir_class(b"/etc"), "/etc");
    }
}
