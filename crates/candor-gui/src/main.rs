//! `candor-gui`: the desktop client.
//!
//! An unprivileged egui window that shows the daemon's snapshots. The UI is
//! a pure function of a view-model (`model.rs`); a reader thread
//! (`net.rs`) feeds that model from the socket or from a replay file.
//! It refuses to run as root (invariant I1).
//!
//! Debug flags: --replay FILE [--pace recorded|max|MS], --screenshot PNG
//! --after-frames N, --select PID, --tab NAME, --socket PATH, --paused,
//! --shot-at SECONDS:FILE (repeatable; exits after the last one),
//! --page processes|glasshouse.
#![forbid(unsafe_code)]

use candor_gui::app::App;
use candor_gui::model::{Action, Page, Tab};
use candor_gui::net::{self, Pace};
use std::path::PathBuf;
use std::time::Duration;

fn euid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn fail(msg: &str) -> ! {
    eprintln!("candor-gui: {msg}");
    std::process::exit(2);
}

fn main() {
    // Fail closed: if the effective uid cannot be read, do not start (I1).
    match euid() {
        Some(0) => fail(
            "refusing to run as root. Run the GUI as your normal user; only the daemon runs as root.",
        ),
        None => {
            fail("cannot read /proc/self/status to check that this is not root; refusing to start.")
        }
        Some(_) => {}
    }
    let mut replay: Option<PathBuf> = None;
    let mut pace = Pace::Fixed(Duration::from_millis(500));
    let mut shot: Option<PathBuf> = None;
    let mut after = 30u64;
    let mut initial = Vec::new();
    let mut timed: Vec<(f64, PathBuf)> = Vec::new();
    let mut sockets = vec![
        PathBuf::from("/run/candor-dev/candor.sock"),
        PathBuf::from("/run/candor/candor.sock"),
    ];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || {
            args.next()
                .unwrap_or_else(|| fail(&format!("{a} needs a value")))
        };
        match a.as_str() {
            "--replay" => replay = Some(val().into()),
            "--pace" => {
                pace = match val().as_str() {
                    "recorded" => Pace::Recorded,
                    "max" => Pace::Max,
                    ms => Pace::Fixed(Duration::from_millis(
                        ms.parse().unwrap_or_else(|_| fail("bad --pace")),
                    )),
                }
            }
            "--screenshot" => shot = Some(val().into()),
            "--after-frames" => {
                after = val().parse().unwrap_or_else(|_| fail("bad --after-frames"))
            }
            "--select" => initial.push(Action::SelectPid(
                val().parse().unwrap_or_else(|_| fail("bad --select")),
            )),
            "--tab" => initial.push(Action::ShowTab(
                Tab::from_name(&val()).unwrap_or_else(|| fail("unknown --tab")),
            )),
            "--socket" => sockets = vec![val().into()],
            "--paused" => initial.push(Action::TogglePause),
            "--page" => initial.push(Action::ShowPage(match val().as_str() {
                "processes" => Page::Processes,
                "glasshouse" => Page::Glasshouse,
                _ => fail("--page processes|glasshouse"),
            })),
            "--shot-at" => {
                let v = val();
                let (t, p) = v
                    .split_once(':')
                    .unwrap_or_else(|| fail("--shot-at SECONDS:FILE"));
                timed.push((
                    t.parse().unwrap_or_else(|_| fail("bad --shot-at time")),
                    p.into(),
                ));
            }
            "--version" => {
                println!("candor-gui {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            other => fail(&format!("unknown argument {other:?}")),
        }
    }
    let source = match replay {
        Some(p) => net::replay(p, pace),
        None => net::live(sockets),
    };
    let app = App::new(source, shot.map(|p| (p, after)), initial).with_timed_shots(timed);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_title("Candor"),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    if let Err(e) = eframe::run_native(
        "Candor",
        options,
        Box::new(|cc| {
            app.set_waker(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    ) {
        fail(&format!("could not open a window: {e}"));
    }
}
