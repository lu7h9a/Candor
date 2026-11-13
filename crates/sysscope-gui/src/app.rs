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
        }
    }

    /// Takes pending messages from the reader into the model.
    pub fn pump(&mut self) {
        for _ in 0..MAX_PER_FRAME {
            match self.source.rx.try_recv() {
                Ok(inc) => self.model.apply(inc),
                Err(_) => break,
            }
        }
        if !self.initial.is_empty() && !self.model.rows.is_empty() {
            for a in std::mem::take(&mut self.initial) {
                self.act(a);
            }
        }
    }

    /// Applies one action.
    pub fn act(&mut self, a: Action) {
        if a == Action::Export {
            self.export();
            return;
        }
        for req in self.model.on_action(a) {
            let _ = self.source.tx.try_send(req);
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
                    "cpu_pct": p.cpu_pct, "rss": p.rss, "score": p.score, "top_rule": p.top_rule})
            })
            .collect();
        let path = PathBuf::from(&home).join(format!("sysscope-export-{}.json", self.model.seq));
        let text = serde_json::to_string_pretty(&serde_json::json!({"processes": rows}))
            .unwrap_or_default();
        self.model.notice = Some(match std::fs::write(&path, text) {
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
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}
