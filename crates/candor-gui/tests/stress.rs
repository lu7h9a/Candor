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

/// The access map (redesign spec 6.5): with 150 and with 2000 touched
/// objects, layout never blocks a frame (worst < 50 ms while settling), and
/// idle and panning frames average under 16.7 ms (60 fps). Run on the
/// release build by `make test`, like the 2000-process test.
#[test]
fn map_stays_at_60fps_with_150_and_2000_objects() {
    use candor_gui::map::MapAction;
    use candor_gui::model::{Incoming, Tab};
    use candor_proto::{FileStat, Series};
    for objects in [150u32, 2000] {
        let (in_tx, in_rx) = crossbeam_channel::bounded(64);
        let (req_tx, _req_rx) = crossbeam_channel::bounded(1024);
        let src = net::Source {
            rx: in_rx,
            tx: req_tx,
            waker: Default::default(),
        };
        let centre = ProcKey {
            tgid: 500,
            start_ticks: 1,
        };
        let procs = vec![ProcRow {
            key: centre,
            exe: BStr::from("/usr/bin/heavy"),
            ..ProcRow::default()
        }];
        in_tx
            .send(Incoming::Msg(Box::new(DaemonMsg::Snapshot {
                seq: 1,
                ts_ns: 1,
                mode: Mode::System(SystemMode::System),
                procs,
                loss: Loss::default(),
            })))
            .unwrap();
        let files: Vec<FileStat> = (0..objects)
            .map(|i| FileStat {
                path: BStr::from(format!("/data/d{i}/file").as_str()),
                dev: 1,
                ino: u64::from(i),
                opens: u64::from(i % 40 + 1),
                read: true,
                write: i % 5 == 0,
                rbytes: 0,
                wbytes: 0,
                last_ts: u64::from(i) * 1_000_000,
            })
            .collect();
        in_tx
            .send(Incoming::Msg(Box::new(DaemonMsg::Detail {
                proc: centre,
                series: Series::default(),
                recent: vec![],
                files,
                conns: vec![],
                syscalls: vec![],
                children: vec![],
                maps: None,
                findings: vec![],
            })))
            .unwrap();
        let app = App::new(src, None, vec![]);
        let mut h = Harness::builder()
            .with_size(egui::vec2(1400.0, 900.0))
            .build_ui_state(|ui, app: &mut App| app.frame(ui), app);
        h.run_steps(2);
        h.state_mut().act(Action::Open(centre));
        h.state_mut().act(Action::ShowTab(Tab::Map));
        let mut worst = Duration::ZERO;
        let mut frames = 0;
        while (h.state().model.map.moving() || frames < 5) && frames < 3000 {
            let t = Instant::now();
            h.step();
            worst = worst.max(t.elapsed());
            frames += 1;
        }
        let nodes = h.state().model.map.graph.nodes.len();
        assert!(nodes <= candor_gui::map::CAP, "{nodes} nodes");
        assert!(
            !h.state().model.map.moving(),
            "{objects}: not settled after {frames} frames"
        );
        assert!(
            worst < Duration::from_millis(50),
            "{objects}: worst settling frame {worst:?}"
        );
        let time = |h: &mut Harness<'static, App>, pan: bool| {
            let t = Instant::now();
            for i in 0..60 {
                if pan {
                    let d = if i % 2 == 0 { 3.0 } else { -3.0 };
                    h.state_mut()
                        .act(Action::Map(MapAction::Pan(candor_gui::map::P {
                            x: d,
                            y: d,
                        })));
                }
                h.step();
            }
            t.elapsed() / 60
        };
        let idle = time(&mut h, false);
        let panning = time(&mut h, true);
        eprintln!(
            "map {objects} objects: {nodes} nodes, settled in {frames} frames, worst {worst:?}, idle {idle:?}/frame, panning {panning:?}/frame"
        );
        assert!(
            idle < Duration::from_micros(16_700),
            "{objects}: idle {idle:?}"
        );
        assert!(
            panning < Duration::from_micros(16_700),
            "{objects}: panning {panning:?}"
        );
    }
}
