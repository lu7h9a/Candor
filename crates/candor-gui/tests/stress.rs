//! WP21 stress: 2000 processes at 2 Hz through the real UI code; no frame
//! may take more than 50 ms (plan WP21, T17). Generates its own frames file.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use candor_gui::app::App;
use candor_gui::model::Action;
use candor_gui::net::{self, Pace};
use candor_proto::{BStr, DaemonMsg, Loss, Mode, ProcKey, ProcRow, SystemMode};
use egui_kittest::Harness;
use std::io::Write;
use std::time::{Duration, Instant};

/// Writes `snapshots` snapshots of `n` processes (a 4-level tree).
pub fn write_stress_frames(path: &std::path::Path, n: u32, snapshots: u64) {
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    for seq in 0..snapshots {
        let procs: Vec<ProcRow> = (0..n)
            .map(|i| ProcRow {
                key: ProcKey {
                    tgid: 100 + i,
                    start_ticks: 1,
                },
                parent: (i > 0).then_some(ProcKey {
                    tgid: 100 + i / 8,
                    start_ticks: 1,
                }),
                exe: BStr::from(
                    format!("/usr/lib/stress/worker-{:04}/bin/process-{i}", i % 97).as_str(),
                ),
                comm: BStr::from("worker"),
                uid: 1000 + i % 3,
                cpu_pct: ((i as u64 * 7 + seq * 13) % 1000) as f32 / 10.0,
                rss: u64::from(i) * 4096 * 10,
                threads: 1 + i % 8,
                n_open: u64::from(i) * seq,
                score: if i % 250 == 0 { 72 } else { 0 },
                tree_score: if i % 250 == 0 { 72 } else { 0 },
                ..ProcRow::default()
            })
            .collect();
        let m = DaemonMsg::Snapshot {
            seq,
            ts_ns: seq * 500_000_000,
            mode: Mode::System(SystemMode::System),
            procs,
            loss: Loss::default(),
        };
        writeln!(f, "{}", serde_json::to_string(&m).unwrap()).unwrap();
    }
}

#[test]
fn no_frame_over_50ms_with_2000_processes() {
    let path =
        std::env::temp_dir().join(format!("candor-stress-{}.frames.jsonl", std::process::id()));
    let n: u32 = std::env::var("STRESS_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    write_stress_frames(&path, n, 40);
    let app = App::new(net::replay(path.clone(), Pace::Max), None, vec![]);
    let mut h = Harness::builder()
        .with_size(egui::vec2(1400.0, 900.0))
        .build_ui_state(|ui, app: &mut App| app.frame(ui), app);
    let mut worst = Duration::ZERO;
    let mut frames = 0;
    let mut seen_seq = 0;
    let deadline = Instant::now() + Duration::from_secs(60);
    while seen_seq < 39 && Instant::now() < deadline {
        let t = Instant::now();
        h.step();
        worst = worst.max(t.elapsed());
        frames += 1;
        seen_seq = h.state().model.seq;
        if frames == 20 {
            h.state_mut().act(Action::ToggleTree); // tree mode is the heavier layout
        }
    }
    let _ = std::fs::remove_file(&path);
    assert_eq!(h.state().model.rows.len(), n as usize);
    assert!(seen_seq >= 39, "only reached snapshot {seen_seq}");
    assert!(
        worst < Duration::from_millis(50),
        "worst frame {worst:?} over {frames} frames"
    );
}
