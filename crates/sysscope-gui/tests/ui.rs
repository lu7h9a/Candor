//! WP20 UI tests (egui_kittest): drives the real window code headless
//! against the demo replay and checks every labelled element and the main
//! interactions (plan WP20 Verify, T15).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sysscope_gui::app::App;
use sysscope_gui::model::{Column, Tab};
use sysscope_gui::net::{self, Pace};

fn frames() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/gui/demo.frames.jsonl")
}

/// A harness whose app has received the whole demo replay.
fn harness() -> Harness<'static, App> {
    let app = App::new(net::replay(frames(), Pace::Max), None, Vec::new());
    let mut h = Harness::builder()
        .with_size(egui::vec2(1400.0, 900.0))
        .build_ui_state(|ui, app: &mut App| app.frame(ui), app);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        h.step();
        if h.state().model.rows.len() >= 30 && !h.state().model.alerts.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Drain the rest of the file (details come after the snapshots).
    for _ in 0..50 {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
    }
    h
}

#[test]
fn every_required_element_has_its_label() {
    let mut h = harness();
    for label in [
        "status", "mode", "search", "pause", "export", "loss", "procs", "alerts",
    ] {
        assert!(
            h.query_by_label(label).is_some(),
            "missing element {label:?}"
        );
    }
    // Detail tabs appear once a process is selected.
    h.state_mut()
        .act(sysscope_gui::model::Action::SelectPid(1600));
    h.run_steps(3);
    for t in Tab::all() {
        let label = format!("detail-{}", t.name());
        assert!(h.query_by_label(&label).is_some(), "missing {label}");
    }
}

#[test]
fn search_sort_pause_tab_and_alert_click_change_the_model() {
    let mut h = harness();
    // Search.
    h.get_by_label("search").click();
    h.run_steps(1);
    h.get_by_label("search").type_text("update-helper");
    h.run_steps(2);
    assert_eq!(h.state().model.filter, "update-helper");
    assert_eq!(h.state().model.visible_rows().len(), 1);
    // Sort by memory via its header button.
    h.get_by_label_contains("memory").click();
    h.run_steps(2);
    assert_eq!(h.state().model.sort.0, Column::Mem);
    // Pause.
    h.get_by_label("pause").click();
    h.run_steps(2);
    assert!(h.state().model.paused);
    // Alert click selects the process and opens Findings.
    h.state_mut().model.filter.clear();
    h.run_steps(1);
    let first_alert = h.state().model.alerts[0].proc;
    h.get_by_label_contains("R001 Credential file read").click();
    h.run_steps(2);
    let alert_proc = h
        .state()
        .model
        .alerts
        .iter()
        .find(|f| f.rule == "R001")
        .unwrap()
        .proc;
    assert_eq!(
        h.state().model.selected,
        Some(alert_proc),
        "first alert was {first_alert:?}"
    );
    assert_eq!(h.state().model.tab, Tab::Findings);
    // Tab switch.
    h.get_by_label("detail-files").click();
    h.run_steps(2);
    assert_eq!(h.state().model.tab, Tab::Files);
}

#[test]
fn glasshouse_limits_text_is_in_the_window() {
    let mut h = harness();
    h.get_by_label("Glasshouse").click();
    h.run_steps(3);
    assert!(
        h.query_by_label_contains("not a malware containment system")
            .is_some()
    );
}

#[test]
fn glasshouse_page_shows_the_report() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/gui/glasshouse.frames.jsonl");
    let app = App::new(net::replay(path, Pace::Max), None, Vec::new());
    let mut h = Harness::builder()
        .with_size(egui::vec2(1400.0, 900.0))
        .build_ui_state(|ui, app: &mut App| app.frame(ui), app);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && h.state().model.gh.report.is_none() {
        h.step();
        std::thread::sleep(Duration::from_millis(20));
    }
    h.run_steps(3);
    h.get_by_label("Glasshouse").click();
    h.run_steps(3);
    assert_eq!(h.state().model.page, sysscope_gui::model::Page::Glasshouse);
    for label in [
        "gh-path",
        "gh-browse",
        "gh-args",
        "gh-timeout",
        "gh-run",
        "gh-cancel",
        "gh-status",
        "gh-decoys",
        "gh-report",
        "gh-timeline",
        "gh-export",
    ] {
        assert!(
            h.query_by_label(label).is_some(),
            "missing element {label:?}"
        );
    }
    // Shown at the top of the page and again under the report.
    assert!(
        h.query_all_by_label_contains("not a malware containment system")
            .count()
            >= 2
    );
    // The report's own numbers, as the daemon produced them in the VM.
    assert!(
        h.query_by_label_contains("2 decoys read, 20 modified, 20 renamed, 10 deleted; 1 new file(s); 1 connection attempt(s)")
            .is_some()
    );
    let touched = h
        .state()
        .model
        .gh
        .decoys
        .iter()
        .filter(|d| d.states != vec![sysscope_proto::DecoyState::Untouched])
        .count();
    assert_eq!((touched, h.state().model.gh.decoys.len()), (32, 42));
    // A replay has no daemon: running is not offered.
    h.state_mut().model.gh.path = "/bin/true".into();
    h.run_steps(2);
    h.get_by_label("gh-run").click();
    h.run_steps(2);
    assert_eq!(
        h.state().model.gh.state,
        Some(sysscope_proto::GhState::Finished)
    );
}
