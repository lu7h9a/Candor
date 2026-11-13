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
        match a {
            Action::Export => return self.export(),
            Action::GhBrowse(dir) => return self.browse(dir),
            Action::GhRun => return self.gh_run(),
            Action::GhExport => return self.gh_export(),
            _ => {}
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

    /// Lists a directory for the Glasshouse picker (names escaped,
    /// directories first, at most 2000 entries; symlinks are not followed
    /// for the directory flag).
    fn browse(&mut self, dir: PathBuf) {
        const CAP: usize = 2000;
        let mut entries: Vec<(String, bool)> = Vec::new();
        let mut note = None;
        match std::fs::read_dir(&dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    if entries.len() >= CAP {
                        note = Some(format!("showing the first {CAP} entries"));
                        break;
                    }
                    let name = e.file_name();
                    let Some(name) = name.to_str() else { continue };
                    if name.starts_with('.') || sysscope_core::display::safe_str(name) != name {
                        continue; // hidden, or a name that needs escaping
                    }
                    let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
                    entries.push((name.to_string(), is_dir));
                }
            }
            Err(e) => note = Some(format!("cannot list this directory: {e}")),
        }
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        self.model.gh.browse = Some(crate::model::Browse { dir, entries, note });
    }

    /// Reads the chosen file and uploads it, then asks for the run. The
    /// GUI reads the file as the user; the daemon only gets bytes (D25).
    fn gh_run(&mut self) {
        use sysscope_proto::{BStr, ClientMsg, GhState};
        let path = PathBuf::from(self.model.gh.path.trim());
        let meta = match std::fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() > 0 && m.len() <= 256 * 1024 * 1024 => m,
            Ok(_) => {
                self.model.gh.state = Some(GhState::Failed);
                self.model.gh.message = "choose a regular file of 1 byte to 256 MiB".into();
                return;
            }
            Err(e) => {
                self.model.gh.state = Some(GhState::Failed);
                self.model.gh.message = format!("cannot open the file: {e}");
                return;
            }
        };
        let name = path
            .file_name()
            .map(|n| BStr(std::os::unix::ffi::OsStrExt::as_bytes(n).to_vec()))
            .unwrap_or_else(|| BStr::from("sample"));
        let args: Vec<BStr> = self
            .model
            .gh
            .args
            .split_whitespace()
            .map(BStr::from)
            .collect();
        let timeout_s = self.model.gh.timeout_s;
        let size = meta.len();
        let tx = self.source.tx.clone();
        self.model.gh.state = Some(GhState::Uploading);
        self.model.gh.message = format!("uploading {size} bytes");
        self.model.gh.report = None;
        self.model.gh.decoys.clear();
        std::thread::spawn(move || {
            let send = |m: ClientMsg| tx.send_timeout(m, Duration::from_secs(30)).is_ok();
            let Ok(mut f) = std::fs::File::open(&path) else {
                return;
            };
            if !send(ClientMsg::GhUploadBegin { name, size }) {
                return;
            }
            let mut buf = vec![0u8; 64 * 1024];
            let (mut sent, mut seq) = (0u64, 0u32);
            while sent < size {
                let Ok(n) = std::io::Read::read(&mut f, &mut buf) else {
                    return;
                };
                if n == 0 {
                    return; // file shrank: the daemon sees an incomplete upload
                }
                let n = n.min((size - sent) as usize);
                let b64 = sysscope_proto::b64::encode(buf.get(..n).unwrap_or(&[]));
                if !send(ClientMsg::GhUploadChunk { seq, b64 }) {
                    return;
                }
                sent += n as u64;
                seq += 1;
            }
            send(ClientMsg::GhRun { args, timeout_s });
        });
    }

    /// Writes the report as text and JSON into the home directory.
    fn gh_export(&mut self) {
        let Some(r) = self.model.gh.report.as_deref() else {
            return;
        };
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
        let id: String = r
            .run_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        let base = home.join(format!("sysscope-glasshouse-{id}"));
        let write = |ext: &str, data: &[u8]| {
            let p = base.with_extension(ext);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)
                .and_then(|mut f| std::io::Write::write_all(&mut f, data))
                .map(|()| p)
        };
        let text = sysscope_core::ghreport::render_text(r);
        let json = serde_json::to_vec_pretty(r).unwrap_or_default();
        self.model.notice = Some(
            match (write("txt", text.as_bytes()), write("json", &json)) {
                (Ok(t), Ok(_)) => format!("Report saved to {} (and .json)", t.display()),
                (Err(e), _) | (_, Err(e)) => format!("Report export failed: {e}"),
            },
        );
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
