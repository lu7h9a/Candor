//! The detection engine: findings, allowlist, scores and alerts (plan 5.1-5.3).
//!
//! Rule functions (in `rules/`) look at the state and an event and report a
//! `Hit`. `Detector::raise` turns a hit into a finding: it drops hits the
//! allowlist covers, merges repeats of the same (rule, process, subject) into
//! one finding, and keeps at most MAX_FINDINGS. Scores combine findings with
//! a noisy-OR and decay by half every `half_life_s` (600 s). Nothing here
//! acts on a finding (invariant I9); it is only shown to the user.

use crate::config::{AllowEntry, Rules};
use crate::glob;
use crate::limits;
use crate::state::State;
use std::collections::BTreeMap;
use sysscope_proto::{Event, Finding, ProcKey, ProcRow};

/// A rule match before allowlisting and de-duplication.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    /// Rule id.
    pub rule: String,
    /// Process.
    pub proc: ProcKey,
    /// Subject within the rule (file class, destination, window).
    pub subject: String,
    /// Confidence in (0, 1].
    pub confidence: f32,
    /// Time of the evidence (boot ns).
    pub ts_ns: u64,
    /// Evidence events (at least one: no finding without evidence, I9).
    pub evidence: Vec<Event>,
    /// One line: what happened.
    pub summary: String,
    /// Values for {placeholders} in the rule texts.
    pub vars: BTreeMap<String, String>,
    /// Extra reasons computed by the rule, appended to the configured ones.
    pub extra_why: Vec<String>,
}

/// Score band of a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    /// 0.
    None,
    /// 1-29.
    Low,
    /// 30-59.
    Suspicious,
    /// 60-100.
    High,
}

impl Band {
    /// Upper-case label used in explanations ("HIGH").
    pub fn label(self) -> &'static str {
        match self {
            Band::None => "NONE",
            Band::Low => "LOW",
            Band::Suspicious => "SUSPICIOUS",
            Band::High => "HIGH",
        }
    }
}

type FindingKey = (String, ProcKey, String);

/// Findings, allowlist and per-process alert state.
#[derive(Clone, Debug)]
pub struct Detector {
    rules: Rules,
    allow: Vec<AllowEntry>,
    findings: BTreeMap<FindingKey, Finding>,
    next_id: u64,
    allowlisted: BTreeMap<String, u64>,
    alerted: BTreeMap<ProcKey, Band>,
}

fn fill(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

/// Decay factor for evidence `age_ns` old.
fn decay(age_ns: u64, half_life_s: f64) -> f64 {
    0.5f64.powf(age_ns as f64 / 1e9 / half_life_s)
}

impl Detector {
    /// A detector with the given configuration.
    pub fn new(rules: Rules, allow: Vec<AllowEntry>) -> Detector {
        Detector {
            rules,
            allow,
            findings: BTreeMap::new(),
            next_id: 1,
            allowlisted: BTreeMap::new(),
            alerted: BTreeMap::new(),
        }
    }

    /// The configuration in use.
    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    /// All findings, in key order.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.values()
    }

    /// Findings about one process.
    pub fn findings_for(&self, proc: &ProcKey) -> Vec<Finding> {
        self.findings
            .values()
            .filter(|f| f.proc == *proc)
            .cloned()
            .collect()
    }

    /// How many hits each rule had suppressed by the allowlist.
    pub fn allowlisted(&self) -> &BTreeMap<String, u64> {
        &self.allowlisted
    }

    /// The allowlist entry that would silence a finding, as TOML text (5.6).
    pub fn silence_entry(rule: &str, exe: &str, subject: &str) -> String {
        format!(
            "{{ rule = \"{rule}\", exe = \"{}\", subject = \"{}\", reason = \"...\" }}",
            exe.replace('\\', "\\\\").replace('"', "\\\""),
            subject.replace('\\', "\\\\").replace('"', "\\\"")
        )
    }

    fn is_allowlisted(&self, state: &State, hit: &Hit) -> bool {
        let Some(p) = state.get(&hit.proc) else {
            return false;
        };
        if !p.exe_trusted {
            return false; // only a verified root-owned executable can match (5.3)
        }
        self.allow.iter().any(|a| {
            a.rule == hit.rule
                && (a.subject == "*" || a.subject == hit.subject)
                && glob::matches(a.exe.as_bytes(), p.exe.as_bytes())
        })
    }

    /// Records a hit. Returns an alert if the process just entered the
    /// suspicious or the high band for the first time.
    pub fn raise(&mut self, state: &State, hit: Hit) -> Option<Finding> {
        let cfg = self.rules.rule(&hit.rule).cloned()?;
        if hit.evidence.is_empty() {
            return None; // no finding without evidence (I9)
        }
        if self.is_allowlisted(state, &hit) {
            *self.allowlisted.entry(hit.rule.clone()).or_default() += 1;
            return None;
        }
        let exe = state
            .get(&hit.proc)
            .map(|p| p.exe.clone())
            .unwrap_or_default();
        let key = (hit.rule.clone(), hit.proc, hit.subject.clone());
        let max_ev = self.rules.score.max_evidence_events;
        match self.findings.get_mut(&key) {
            Some(f) => {
                // Repeat: update evidence and time, keep one finding.
                for e in &hit.evidence {
                    if f.evidence.len() >= limits::MAX_EVIDENCE_IDS {
                        break; // bounded (I8); the finding already has evidence
                    }
                    if !f.evidence.contains(&e.id) {
                        f.evidence.push(e.id);
                        if f.evidence_events.len() < max_ev {
                            f.evidence_events.push(e.clone());
                        }
                    }
                }
                f.ts_ns = f.ts_ns.max(hit.ts_ns);
                f.confidence = f.confidence.max(hit.confidence);
            }
            None => {
                let mut why: Vec<String> = cfg.why.iter().map(|w| fill(w, &hit.vars)).collect();
                why.extend(hit.extra_why.iter().cloned());
                let finding = Finding {
                    id: self.next_id,
                    rule: hit.rule.clone(),
                    title: cfg.title.clone(),
                    subject: hit.subject.clone(),
                    attack: cfg.attack.clone(),
                    proc: hit.proc,
                    exe,
                    ts_ns: hit.ts_ns,
                    weight: cfg.weight as f32,
                    confidence: hit.confidence,
                    summary: hit.summary.clone(),
                    why,
                    benign: cfg.benign.iter().map(|b| fill(b, &hit.vars)).collect(),
                    evidence: hit
                        .evidence
                        .iter()
                        .take(limits::MAX_EVIDENCE_IDS)
                        .map(|e| e.id)
                        .collect(),
                    evidence_events: hit.evidence.iter().take(max_ev).cloned().collect(),
                };
                self.next_id += 1;
                self.findings.insert(key.clone(), finding);
                self.enforce_cap();
            }
        }
        let now = state.now().max(hit.ts_ns);
        let band = self.band(self.score(&hit.proc, now));
        let prev = self.alerted.get(&hit.proc).copied().unwrap_or(Band::None);
        if band >= Band::Suspicious && band > prev {
            self.alerted.insert(hit.proc, band);
            return self.findings.get(&key).cloned();
        }
        None
    }

    fn enforce_cap(&mut self) {
        while self.findings.len() > limits::MAX_FINDINGS {
            let oldest = self
                .findings
                .iter()
                .min_by_key(|(_, f)| (f.ts_ns, f.id))
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.findings.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Band for a score.
    pub fn band(&self, score: u8) -> Band {
        if score == 0 {
            Band::None
        } else if score < self.rules.score.suspicious_at {
            Band::Low
        } else if score < self.rules.score.high_at {
            Band::Suspicious
        } else {
            Band::High
        }
    }

    /// Per-rule contributions s_r for one process at `now`, and the top rule.
    fn contributions(&self, procs: &[ProcKey], now: u64) -> BTreeMap<String, f64> {
        let mut s: BTreeMap<String, f64> = BTreeMap::new();
        for f in self.findings.values().filter(|f| procs.contains(&f.proc)) {
            let v = f64::from(f.weight)
                * f64::from(f.confidence)
                * decay(now.saturating_sub(f.ts_ns), self.rules.score.half_life_s);
            let e = s.entry(f.rule.clone()).or_insert(0.0);
            if v > *e {
                *e = v;
            }
        }
        s
    }

    fn combine(s: &BTreeMap<String, f64>) -> u8 {
        let keep: f64 = s.values().map(|v| 1.0 - v.clamp(0.0, 1.0)).product();
        (100.0 * (1.0 - keep)).round().clamp(0.0, 100.0) as u8
    }

    /// Score of one process at `now` (plan 5.2).
    pub fn score(&self, proc: &ProcKey, now: u64) -> u8 {
        Self::combine(&self.contributions(&[*proc], now))
    }

    /// Rule with the largest contribution for one process, if any.
    pub fn top_rule(&self, proc: &ProcKey, now: u64) -> Option<String> {
        self.contributions(&[*proc], now)
            .into_iter()
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(r, _)| r)
    }

    /// Score of a process and all its descendants still in the state.
    pub fn tree_score(&self, state: &State, proc: &ProcKey, now: u64) -> u8 {
        let mut keys = vec![*proc];
        let mut i = 0;
        while let Some(k) = keys.get(i).copied() {
            if let Some(p) = state.get(&k) {
                for c in &p.children {
                    if !keys.contains(c) {
                        keys.push(*c);
                    }
                }
            }
            i += 1;
        }
        Self::combine(&self.contributions(&keys, now))
    }

    /// Fills score, tree_score and top_rule into snapshot rows.
    pub fn annotate(&self, state: &State, rows: &mut [ProcRow], now: u64) {
        let flagged: std::collections::BTreeSet<ProcKey> =
            self.findings.values().map(|f| f.proc).collect();
        if flagged.is_empty() {
            return;
        }
        // Only flagged processes and their ancestors can have a tree score.
        let mut ancestors = flagged.clone();
        for k in &flagged {
            let mut cur = state.get(k).and_then(|p| p.parent);
            for _ in 0..state.len() {
                match cur {
                    Some(a) if ancestors.insert(a) => cur = state.get(&a).and_then(|p| p.parent),
                    _ => break,
                }
            }
        }
        for r in rows.iter_mut() {
            if flagged.contains(&r.key) {
                r.score = self.score(&r.key, now);
                r.top_rule = self.top_rule(&r.key, now);
            }
            if ancestors.contains(&r.key) {
                r.tree_score = self.tree_score(state, &r.key, now);
            }
        }
    }
}
