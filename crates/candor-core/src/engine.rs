//! `Engine`: the state plus the detector, driven by inputs.
//!
//! This is what the daemon's core thread runs and what replay runs, so a
//! recording replayed through an `Engine` gives exactly the findings the
//! daemon raised live (invariant I7). Each input first updates the state,
//! then the event-driven rules look at it. Rules never act on anything (I9).

use crate::config::{AllowEntry, Rules};
use crate::detect::{Detector, Hit};
use crate::input::Input;
use crate::rules::files;
use crate::rules::windows::WindowState;
use crate::state::State;
use candor_proto::{DaemonMsg, Event, EventKind, Finding};
use std::collections::BTreeSet;

/// State + detector + decoy set.
#[derive(Clone, Debug)]
pub struct Engine {
    /// Process table.
    pub state: State,
    /// Findings and scores.
    pub detector: Detector,
    decoys: BTreeSet<(u64, u64)>,
    windows: WindowState,
    /// R100 baselines (experimental; only when R100 is enabled).
    pub baselines: Option<crate::baseline::Baselines>,
}

impl Engine {
    /// A fresh engine.
    pub fn new(rules: Rules, allow: Vec<AllowEntry>) -> Engine {
        Engine {
            state: State::new(),
            detector: Detector::new(rules, allow),
            decoys: BTreeSet::new(),
            windows: WindowState::default(),
            baselines: None,
        }
    }

    /// True if the experimental R100 rule is switched on in the rules.
    pub fn r100_enabled(&self) -> bool {
        self.detector.rules().rule("R100").is_some()
    }

    /// An engine with the embedded default rules and allowlist.
    pub fn with_defaults() -> Result<Engine, crate::config::ConfigError> {
        let rules = Rules::load(None)?;
        let allow = crate::config::load_allow(&rules, None)?;
        Ok(Engine::new(rules, allow))
    }

    /// Applies one input; returns the alerts it caused.
    pub fn apply(&mut self, input: &Input) -> Vec<Finding> {
        self.state.apply(input);
        let mut hits = Vec::new();
        match input {
            Input::RawEvent { event } => {
                hits = self.event_hits(event);
                hits.extend(self.r100(event));
                hits.extend(
                    self.windows
                        .on_event(self.detector.rules(), &self.state, event),
                );
            }
            Input::BudgetDrops { ts_ns, drops } => {
                hits =
                    self.windows
                        .on_budget_drops(self.detector.rules(), &self.state, *ts_ns, drops);
            }
            Input::Tick { .. } => {
                self.windows.prune(&self.state);
                self.detector.prune(&self.state);
            }
            Input::Decoys { inodes } => self.decoys = inodes.iter().copied().collect(),
            Input::ExeMeta {
                proc,
                world_writable_dir: true,
                ..
            } => {
                // R002 for an executable in a world-writable directory that
                // is not one of the listed temp dirs: evidence is its exec.
                let last_exec = self.state.get(proc).and_then(|p| {
                    p.recent
                        .iter()
                        .rev()
                        .find(|e| matches!(e.kind, EventKind::Exec { .. }))
                        .cloned()
                });
                if let Some(ev) = last_exec {
                    hits.extend(files::r002(self.detector.rules(), &ev, true));
                }
            }
            _ => {}
        }
        let mut alerts = Vec::new();
        for h in hits {
            alerts.extend(self.detector.raise(&self.state, h));
        }
        alerts
    }

    fn event_hits(&self, ev: &Event) -> Vec<Hit> {
        let rules = self.detector.rules();
        let mut hits = Vec::new();
        hits.extend(files::r001(rules, &self.state, ev));
        hits.extend(files::r002(rules, ev, false));
        hits.extend(files::r003(rules, ev));
        hits.extend(files::r004(rules, &self.state, ev));
        hits.extend(files::r012(rules, &self.decoys, ev));
        hits.extend(crate::rules::procs::r009(rules, &self.state, ev));
        hits.extend(crate::rules::procs::r011(rules, &self.state, ev));
        hits
    }

    /// R100: a finished run compared with its executable's baseline.
    fn r100(&mut self, ev: &Event) -> Option<crate::detect::Hit> {
        if !matches!(ev.kind, EventKind::Exit {}) {
            return None;
        }
        let cfg = self.detector.rules().rule("R100")?.clone();
        let p = self.state.get(&ev.proc)?;
        if p.kthread || p.exe.as_bytes().is_empty() {
            return None;
        }
        let exe = p.exe.to_string();
        let v = crate::baseline::vector_of(p);
        let bl = self.baselines.get_or_insert_with(Default::default);
        let u = bl.observe(&exe, &v, ev.ts_ns)?;
        Some(crate::detect::Hit {
            rule: "R100".into(),
            proc: ev.proc,
            subject: "behaviour".into(),
            confidence: cfg.confidence? as f32,
            ts_ns: ev.ts_ns,
            evidence: vec![ev.clone()],
            summary: format!(
                "this run of {exe} differed from its usual behaviour (divergence {:.2}, usual at most {:.2} over {} runs)",
                u.divergence, u.p99, u.runs
            ),
            vars: crate::rules::vars(&[
                ("divergence", format!("{:.2}", u.divergence)),
                ("p99", format!("{:.2}", u.p99)),
                ("runs", u.runs.to_string()),
            ]),
            extra_why: Vec::new(),
        })
    }

    /// Window state of the windowed rules (for tests).
    pub fn windows(&self) -> &WindowState {
        &self.windows
    }

    /// Snapshot with scores filled in.
    pub fn snapshot(&self, seq: u64) -> DaemonMsg {
        let mut msg = self.state.snapshot(seq);
        if let DaemonMsg::Snapshot { procs, ts_ns, .. } = &mut msg {
            let now = *ts_ns;
            self.detector.annotate(&self.state, procs, now);
        }
        msg
    }
}
