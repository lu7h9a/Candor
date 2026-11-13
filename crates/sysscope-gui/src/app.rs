//! The eframe application: pumps data into the model each frame, draws the
//! UI, turns actions into model changes and daemon requests, and handles the
//! debug flags (--screenshot after N frames, then exit).

use crate::model::{Action, Model};
use crate::net::Source;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use sysscope_core::display::safe;
use sysscope_core::redact::Redactor;

/// Messages taken from the reader per frame (the rest wait for the next).
const MAX_PER_FRAME: usize = 2000;

/// The running application.
pub struct App {
    /// View state.
    pub model: Model,
    source: Source,
    screenshot: Option<(PathBuf, u64)>,
    frames: u64,
    requested: bool,
    done: Arc<AtomicBool>,
    initial: Vec<Action>,
    /// --shot-at: (seconds after start, file), taken in order; exit after the last.
    timed: Vec<(f64, PathBuf)>,
    started: std::time::Instant,
    timed_done: Arc<std::sync::atomic::AtomicUsize>,
    timed_requested: usize,
}

impl App {
    /// A new app over a data source; `initial` actions run once data arrives.
    pub fn new(source: Source, screenshot: Option<(PathBuf, u64)>, initial: Vec<Action>) -> App {
        App {
            model: Model::new(),
            source,
            screenshot,
            frames: 0,
            requested: false,
            done: Arc::new(AtomicBool::new(false)),
            initial,
            timed: Vec::new(),
            started: std::time::Instant::now(),
            timed_done: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            timed_requested: 0,
        }
    }

    /// Screenshots at fixed times after start (debug: daemon restart test).
    pub fn with_timed_shots(mut self, shots: Vec<(f64, PathBuf)>) -> App {
        self.timed = shots;
        self
    }

    fn handle_timed(&mut self, ctx: &egui::Context) {
        if self.timed.is_empty() {
            return;
        }
        let done = self.timed_done.load(Ordering::SeqCst);
        if done >= self.timed.len() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if self.timed_requested == done
            && let Some((at, path)) = self.timed.get(done).cloned()
            && self.started.elapsed().as_secs_f64() >= at
        {
            self.timed_requested += 1;
            let counter = Arc::clone(&self.timed_done);
            ctx.request_screenshot(move |img| {
                if let Err(e) = write_png(&path, &img) {
                    eprintln!("sysscope-gui: screenshot failed: {e}");
                }
                counter.fetch_add(1, Ordering::SeqCst);
            });
        }
        ctx.request_repaint_after(Duration::from_millis(200));
    }

    /// Takes pending messages from the reader into the model.
    pub fn pump(&mut self) {
        for _ in 0..MAX_PER_FRAME {
            match self.source.rx.try_recv() {
                Ok(inc) => {
                    let reconnected = matches!(&inc, crate::model::Incoming::Msg(m)
                        if matches!(**m, sysscope_proto::DaemonMsg::Welcome { .. }));
                    self.model.apply(inc);
                    // Requests in flight when the daemon went away are lost:
                    // ask again for what the window shows.
                    if reconnected && let Some(k) = self.model.selected {
                        let maps = self.model.tab == crate::model::Tab::Maps;
                        self.send(sysscope_proto::ClientMsg::GetDetail { proc: k, maps });
                    }
                }
                Err(_) => break,
            }
        }
        if !self.initial.is_empty() && !self.model.rows.is_empty() {
            for a in std::mem::take(&mut self.initial) {
                self.act(a);
            }
        }
    }

    /// Lets the reader thread wake this window when data arrives.
    pub fn set_waker(&self, ctx: &egui::Context) {
        if let Ok(mut g) = self.source.waker.lock() {
            *g = Some(ctx.clone());
        }
    }

    /// Applies one action.
    pub fn act(&mut self, a: Action) {
        if a == Action::Export {
            self.export();
            return;
        }
        for req in self.model.on_action(a) {
            self.send(req);
        }
    }

    fn send(&mut self, req: sysscope_proto::ClientMsg) {
        if self.source.tx.try_send(req).is_err() {
            self.model.notice = Some("Too many requests waiting for the daemon; try again.".into());
        }
    }

    /// One frame: pump, draw, act.
    pub fn frame(&mut self, ui: &mut egui::Ui) {
        self.pump();
        for a in crate::ui::draw(ui, &self.model) {
            self.act(a);
        }
    }

    fn export(&mut self) {
        let home = std::env::var("HOME").unwrap_or_default();
        let user = std::env::var("USER").unwrap_or_default();
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
        let mut r = Redactor::new(&home, &user, host.trim(), false);
        let rows: Vec<serde_json::Value> = self
            .model
            .rows
            .iter()
            .map(|p| {
                serde_json::json!({"pid": p.key.tgid, "exe": r.text(&safe(&p.exe)), "uid": p.uid,
                    "cpu_pct": p.cpu_pct, "rss": p.rss, "score": p.score, "top_rule": p.top_rule.as_deref().map(sysscope_core::display::safe_str)})
            })
            .collect();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = PathBuf::from(&home).join(format!("sysscope-export-{stamp}.json"));
        let text = serde_json::to_string_pretty(&serde_json::json!({"processes": rows}))
            .unwrap_or_default();
        // create_new: never follows or overwrites an existing file or link.
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()));
        self.model.notice = Some(match written {
            Ok(()) => format!(
                "Exported (redacted) to {} - review it before sharing",
                path.display()
            ),
            Err(e) => format!("Export failed: {e}"),
        });
    }

    fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let Some((path, after)) = self.screenshot.clone() else {
            return;
        };
        if self.done.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if !self.requested && self.frames >= after {
            self.requested = true;
            let done = Arc::clone(&self.done);
            ctx.request_screenshot(move |img| {
                if let Err(e) = write_png(&path, &img) {
                    eprintln!("sysscope-gui: screenshot failed: {e}");
                }
                done.store(true, Ordering::SeqCst);
            });
        }
    }
}

/// Writes an egui image as an RGBA PNG.
pub fn write_png(path: &std::path::Path, img: &egui::ColorImage) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let [w, h] = img.size;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut writer = enc.write_header().map_err(|e| e.to_string())?;
    let bytes: Vec<u8> = img.pixels.iter().flat_map(|p| p.to_array()).collect();
    writer.write_image_data(&bytes).map_err(|e| e.to_string())
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
        self.frames += 1;
        let ctx = ui.ctx().clone();
        self.handle_screenshot(&ctx);
        self.handle_timed(&ctx);
        // Data wakes the window (net.rs); this is only a heartbeat.
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}
