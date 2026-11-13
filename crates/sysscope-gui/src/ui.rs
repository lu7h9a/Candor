//! The window (WP20): a pure function of the `Model` that returns the
//! `Action`s the user took this frame.
//!
//! Layout: top bar (status, mode, search, pause, export, loss), process
//! table or tree on the left, detail tabs on the right, alerts at the
//! bottom. Every element the tests look for has a stable accessibility
//! label (`status`, `mode`, `search`, `pause`, `export`, `loss`, `procs`,
//! `detail-<tab>`, `alerts`). Scores are shown as words as well as colour.

use crate::model::{Action, Column, ConnState, Model, Page, RowView, Tab};
use egui::{Color32, Response, RichText, Role, Ui, WidgetInfo};
use sysscope_core::display::{safe, safe_str};
use sysscope_core::explain;
use sysscope_proto::{DaemonMsg, Mode};

/// The 6.4 text, shown verbatim on the Glasshouse page (I13).
pub const GLASSHOUSE_LIMITS: &str = sysscope_core::explain::GLASSHOUSE_LIMITATION;

/// Product statement (plan section 1).
pub const STATEMENT: &str = "SysScope shows what programs on your Linux machine are doing and explains why some behaviour looks suspicious. It is a visibility tool with explainable heuristics, not an antivirus, and it cannot be relied on to stop or contain malware.";

/// Gives a widget a stable accessibility label for tests.
fn tag(r: &Response, role: Role, name: &'static str) {
    r.widget_info(|| WidgetInfo::labeled(role, true, name));
}

fn band_color(band: &str) -> Color32 {
    match band {
        "high" => Color32::from_rgb(0xd0, 0x30, 0x30),
        "suspicious" => Color32::from_rgb(0xd0, 0x90, 0x10),
        "low" => Color32::from_rgb(0x60, 0x90, 0xd0),
        _ => Color32::GRAY,
    }
}

fn size(b: u64) -> String {
    let mut v = b as f64;
    let mut u = 0;
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", units.get(u).copied().unwrap_or("B"))
}

/// Draws the whole window into the root `ui`; returns this frame's actions.
pub fn draw(ui: &mut Ui, m: &Model) -> Vec<Action> {
    let mut acts = Vec::new();
    egui::Panel::top("top").show(ui, |ui| top_bar(ui, m, &mut acts));
    if !matches!(m.conn, ConnState::Connected { .. } | ConnState::Replay(_)) && !m.rows.is_empty() {
        egui::Panel::top("stale").show(ui, |ui| {
            let r = ui.label(
                RichText::new(
                    "Not connected to the daemon: showing the last data received. Reconnecting...",
                )
                .color(Color32::BLACK)
                .background_color(Color32::from_rgb(0xe8, 0x9a, 0x20)),
            );
            tag(&r, Role::Label, "stale");
        });
    }
    if m.loss_banner() {
        egui::Panel::top("loss-banner").show(ui, |ui| loss_banner(ui, m, &mut acts));
    }
    if let Some(k) = m.confirm_follow {
        confirm_follow(ui, m, k, &mut acts);
    }
    if m.page == Page::Glasshouse {
        egui::CentralPanel::default().show(ui, |ui| crate::ghui::page(ui, m, &mut acts));
        return acts;
    }
    if !matches!(m.conn, ConnState::Connected { .. } | ConnState::Replay(_)) && m.rows.is_empty() {
        egui::CentralPanel::default().show(ui, |ui| conn_state(ui, m));
        return acts;
    }
    egui::Panel::bottom("alerts")
        .resizable(true)
        .default_size(140.0)
        .show(ui, |ui| alerts(ui, m, &mut acts));
    egui::Panel::right("detail")
        .resizable(true)
        .default_size(520.0)
        .show(ui, |ui| detail(ui, m, &mut acts));
    egui::CentralPanel::default().show(ui, |ui| procs(ui, m, &mut acts));
    acts
}

fn top_bar(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    ui.horizontal_wrapped(|ui| {
        for (p, text) in [
            (Page::Processes, "Processes"),
            (Page::Glasshouse, "Glasshouse"),
        ] {
            if ui.selectable_label(m.page == p, text).clicked() && m.page != p {
                acts.push(Action::ShowPage(p));
            }
        }
        ui.separator();
        let status = match &m.conn {
            ConnState::Connected {
                version, kernel, ..
            } => format!("daemon {version} on {kernel}"),
            ConnState::Connecting => "connecting...".into(),
            ConnState::DaemonDown(_) => "daemon not running".into(),
            ConnState::PermissionDenied(_) => "permission denied".into(),
            ConnState::ProtoMismatch(_) => "protocol mismatch".into(),
            ConnState::Replay(p) => format!("replay of {}", safe_str(p)),
        };
        let live = matches!(m.conn, ConnState::Connected { .. } | ConnState::Replay(_));
        let status_color = if live {
            Color32::from_rgb(0x60, 0xc0, 0x60)
        } else {
            Color32::from_rgb(0xe0, 0x50, 0x40)
        };
        let r = ui.label(RichText::new(status.clone()).strong().color(status_color));
        tag(&r, Role::Label, "status");
        let mode = if !live {
            "Not connected".to_string()
        } else {
            match m.mode {
                Mode::System(_) => "System-wide".to_string(),
                Mode::Follow { follow } => {
                    let exe = m
                        .rows
                        .iter()
                        .find(|r| r.key == follow)
                        .map(|r| safe(&r.exe))
                        .unwrap_or_default();
                    format!("Following {exe} ({})", follow.tgid)
                }
            }
        };
        let r = ui.label(
            RichText::new(mode)
                .background_color(Color32::from_rgb(0x30, 0x50, 0x80))
                .color(Color32::WHITE),
        );
        tag(&r, Role::Label, "mode");
        let mut text = m.filter.clone();
        let r = ui.add(
            egui::TextEdit::singleline(&mut text)
                .hint_text("filter: exe, pid, uid, rule")
                .desired_width(220.0),
        );
        tag(&r, Role::TextInput, "search");
        if text != m.filter {
            acts.push(Action::Filter(text));
        }
        let r = ui.add_enabled(
            live,
            egui::Button::new(if m.paused { "Resume" } else { "Pause" }),
        );
        tag(&r, Role::Button, "pause");
        if r.clicked() {
            acts.push(Action::TogglePause);
        }
        if m.paused {
            ui.label(
                RichText::new(format!("PAUSED ({} updates skipped)", m.skipped))
                    .color(Color32::from_rgb(0xd0, 0x90, 0x10)),
            );
        }
        let r = ui.add_enabled(live, egui::Button::new("Export"));
        tag(&r, Role::Button, "export");
        if r.clicked() {
            acts.push(Action::Export);
        }
        let lost = m.loss_total();
        if lost > 0 {
            let r = ui.label(
                RichText::new(format!(
                    "LOST EVENTS: ring buffer {}, budget {}, scratch {}, undecodable {}",
                    m.loss.ringbuf, m.loss.budget, m.loss.scratch, m.loss.decode
                ))
                .color(Color32::from_rgb(0xd0, 0x30, 0x30)),
            );
            tag(&r, Role::Label, "loss");
        }
        if m.multi_user_now() {
            ui.label("Monitoring all users on this machine");
        }
        if let Some(n) = &m.notice {
            ui.label(RichText::new(n).italics());
        }
    });
}

fn loss_banner(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    egui::Frame::new()
        .fill(Color32::from_rgb(0x5a, 0x1e, 0x1e))
        .inner_margin(6.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let r = ui.label(RichText::new(format!(
                    "Some activity was not recorded: {} events lost (ring buffer {}, per-process budget {}, scratch {}, undecodable {}). What you see is incomplete.",
                    m.loss_total(), m.loss.ringbuf, m.loss.budget, m.loss.scratch, m.loss.decode
                )).color(Color32::WHITE));
                tag(&r, Role::Label, "loss-banner");
                if ui.button("Dismiss").clicked() {
                    acts.push(Action::DismissLoss);
                }
            });
        });
}

fn confirm_follow(ui: &mut Ui, m: &Model, k: sysscope_proto::ProcKey, acts: &mut Vec<Action>) {
    let name = m
        .rows
        .iter()
        .find(|r| r.key == k)
        .map(|r| safe(&r.exe))
        .unwrap_or_default();
    egui::Window::new("Follow this process tree?")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ui.ctx(), |ui| {
            ui.label(format!(
                "Follow {name} (pid {}) and everything it starts?",
                k.tgid
            ));
            ui.label(RichText::new("Other processes will not be traced while following.").strong());
            ui.horizontal(|ui| {
                let r = ui.button("Follow");
                tag(&r, Role::Button, "confirm-follow");
                if r.clicked() {
                    acts.push(Action::ConfirmFollow);
                }
                if ui.button("Cancel").clicked() {
                    acts.push(Action::CancelFollow);
                }
            });
        });
}

fn conn_state(ui: &mut Ui, m: &Model) {
    let warn = Color32::from_rgb(0xe8, 0x9a, 0x20);
    ui.add_space(40.0);
    egui::Frame::group(ui.style())
        .fill(Color32::from_rgb(0x2a, 0x24, 0x1c))
        .stroke(egui::Stroke::new(1.5, warn))
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.vertical_centered(|ui| match &m.conn {
                ConnState::DaemonDown(why) => {
                    ui.heading(
                        RichText::new("Warning: the SysScope daemon is not running").color(warn),
                    );
                    ui.label(safe_str(why));
                    ui.add_space(8.0);
                    ui.label("Start it with:");
                    ui.code("sudo systemctl start sysscoped");
                    ui.label("or, for development:");
                    ui.code("sudo ./target/debug/sysscoped --dev");
                    ui.label(RichText::new("This window reconnects by itself.").italics());
                }
                ConnState::PermissionDenied(path) => {
                    ui.heading(
                        RichText::new("Warning: permission denied on the daemon socket")
                            .color(warn),
                    );
                    ui.label(safe_str(path));
                    ui.label("Join the sysscope group, then log out and back in:");
                    ui.code("sudo usermod -aG sysscope $USER");
                }
                ConnState::ProtoMismatch(msg) => {
                    ui.heading(
                        RichText::new("Warning: the daemon speaks a different protocol version")
                            .color(warn),
                    );
                    ui.label(safe_str(msg));
                    ui.label("Install matching versions of sysscoped and sysscope-gui.");
                }
                ConnState::Connecting => {
                    ui.heading("Connecting to the daemon...");
                }
                _ => {
                    ui.heading("No data yet");
                }
            });
        });
    ui.add_space(20.0);
    ui.label(RichText::new("About SysScope").strong());
    ui.label(STATEMENT);
    ui.label("The daemon runs as root and does the tracing; this window runs as you and only displays what the daemon sends.");
}

fn procs(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        let r = ui.selectable_label(!m.tree, "Table");
        if r.clicked() && m.tree {
            acts.push(Action::ToggleTree);
        }
        let r = ui.selectable_label(m.tree, "Tree");
        if r.clicked() && !m.tree {
            acts.push(Action::ToggleTree);
        }
        ui.label(format!("{} processes", m.rows.len()));
    });
    let rows = m.visible();
    if rows.is_empty() {
        ui.label("No processes match.");
    }
    let cols: [(&str, Column); 10] = [
        ("exe", Column::Exe),
        ("pid", Column::Pid),
        ("user", Column::User),
        ("CPU%", Column::Cpu),
        ("memory", Column::Mem),
        ("thr", Column::Threads),
        ("opens", Column::Opens),
        ("conns", Column::Conns),
        ("children", Column::Children),
        ("score", Column::Score),
    ];
    let resp = ui.push_id("procs", |ui| {
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .resizable(false)
            .sense(egui::Sense::click())
            // The exe column takes the remaining width; the others are fixed.
            // Auto-sized columns measure every row on the first layout, which
            // with 2000 rows cost a 50 ms frame (WP21).
            .column(egui_extras::Column::remainder().at_least(160.0).clip(true))
            .columns(egui_extras::Column::exact(62.0), 9)
            .header(20.0, |mut h| {
                for (name, col) in cols {
                    h.col(|ui| {
                        let arrow = if m.sort.0 == col {
                            if m.sort.1 { " v" } else { " ^" }
                        } else {
                            ""
                        };
                        if ui.button(format!("{name}{arrow}")).clicked() {
                            acts.push(Action::Sort(col));
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let Some(v) = rows.get(row.index()) else {
                        return;
                    };
                    row.set_selected(m.selected == Some(v.row.key));
                    proc_cells(&mut row, v);
                    let resp = row.response();
                    if resp.clicked() {
                        acts.push(Action::Select(Some(v.row.key)));
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Follow this process tree").clicked() {
                            acts.push(Action::RequestFollow(v.row.key));
                            ui.close();
                        }
                        if ui.button("Show details").clicked() {
                            acts.push(Action::Select(Some(v.row.key)));
                            ui.close();
                        }
                    });
                });
            });
    });
    tag(&resp.response, Role::Table, "procs");
}

fn proc_cells(row: &mut egui_extras::TableRow<'_, '_>, v: &RowView) {
    let r = &v.row;
    let exited = if r.exited_ts.is_some() {
        " (exited)"
    } else {
        ""
    };
    row.col(|ui| {
        ui.label(format!(
            "{}{}{}{}",
            "  ".repeat(v.depth.min(30)),
            if r.followed { "* " } else { "" },
            v.name,
            exited
        ));
    });
    row.col(|ui| {
        ui.label(r.key.tgid.to_string());
    });
    row.col(|ui| {
        ui.label(r.uid.to_string());
    });
    row.col(|ui| {
        ui.label(format!("{:.1}", r.cpu_pct));
    });
    row.col(|ui| {
        ui.label(size(r.rss));
    });
    row.col(|ui| {
        ui.label(r.threads.to_string());
    });
    row.col(|ui| {
        ui.label(r.n_open.to_string());
    });
    row.col(|ui| {
        ui.label(r.n_conn.to_string());
    });
    row.col(|ui| {
        ui.label(r.n_child.to_string());
    });
    row.col(|ui| {
        if r.score > 0 {
            ui.label(
                RichText::new(format!("{} {}", r.score, v.band))
                    .color(band_color(v.band))
                    .strong(),
            );
        } else if r.tree_score > 0 {
            ui.label(format!("tree {}", r.tree_score));
        }
    });
}

fn detail(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let Some(sel) = m.selected else {
        ui.heading("Select a process");
        ui.label("Click a row to see its files, connections, syscalls and findings.");
        ui.separator();
        ui.label("To run a program in a sandbox full of decoy files and see what it touches, open the Glasshouse page (top left).");
        return;
    };
    let row = m.rows.iter().find(|r| r.key == sel);
    let name = row.map(|r| safe(&r.exe)).unwrap_or_default();
    ui.heading(format!("{name} (pid {})", sel.tgid));
    ui.horizontal(|ui| {
        if matches!(m.mode, Mode::Follow { .. }) {
            if ui.button("Stop following").clicked() {
                acts.push(Action::Unfollow);
            }
        } else {
            let r = ui
                .button("Follow this process tree")
                .on_hover_text("Other processes will not be traced while following.");
            tag(&r, Role::Button, "follow");
            if r.clicked() {
                acts.push(Action::RequestFollow(sel));
            }
        }
    });
    ui.horizontal_wrapped(|ui| {
        for t in Tab::all() {
            let label = match t {
                Tab::Maps => "Memory maps".to_string(),
                other => {
                    let n = other.name();
                    let mut c = n.chars();
                    c.next()
                        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                        .unwrap_or_default()
                }
            };
            let r = ui.selectable_label(m.tab == t, label);
            let id: &'static str = match t {
                Tab::Overview => "detail-overview",
                Tab::Files => "detail-files",
                Tab::Network => "detail-network",
                Tab::Syscalls => "detail-syscalls",
                Tab::Children => "detail-children",
                Tab::Maps => "detail-maps",
                Tab::Findings => "detail-findings",
            };
            tag(&r, Role::Tab, id);
            if r.clicked() {
                acts.push(Action::ShowTab(t));
            }
        }
    });
    ui.separator();
    let Some(DaemonMsg::Detail {
        series,
        files,
        conns,
        syscalls,
        children,
        maps,
        findings,
        ..
    }) = m.detail()
    else {
        ui.label("Waiting for details...");
        return;
    };
    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| match m.tab {
            Tab::Overview => {
                let cpu: Vec<[f64; 2]> = series
                    .t
                    .iter()
                    .zip(&series.cpu)
                    .map(|(t, c)| [*t as f64 / 1e9, f64::from(*c)])
                    .collect();
                let mem: Vec<[f64; 2]> = series
                    .t
                    .iter()
                    .zip(&series.rss)
                    .map(|(t, r)| [*t as f64 / 1e9, *r as f64 / 1048576.0])
                    .collect();
                ui.label("CPU %");
                egui_plot::Plot::new("cpu")
                    .height(150.0)
                    .show(ui, |p| p.line(egui_plot::Line::new("cpu %", cpu)));
                ui.label("Memory (MiB)");
                egui_plot::Plot::new("mem")
                    .height(150.0)
                    .show(ui, |p| p.line(egui_plot::Line::new("rss MiB", mem)));
            }
            Tab::Files => {
                for f in files.iter().take(500) {
                    ui.label(format!(
                        "{}  opens {}  {}{}",
                        safe(&f.path),
                        f.opens,
                        if f.read { "r" } else { "" },
                        if f.write { "w" } else { "" }
                    ));
                }
                if files.is_empty() {
                    ui.label("No files opened while traced.");
                }
            }
            Tab::Network => {
                for c in conns.iter().take(1000) {
                    ui.label(format!("{}:{}  x{}", safe_str(&c.addr), c.port, c.count));
                }
                if conns.is_empty() {
                    ui.label("No outbound connections seen.");
                }
            }
            Tab::Syscalls => {
                let mut s = syscalls.clone();
                s.sort_by_key(|x| std::cmp::Reverse(x.count));
                for x in s.iter().take(100) {
                    ui.label(format!("{:<20} {}", safe_str(&x.name), x.count));
                }
            }
            Tab::Children => {
                let names: std::collections::BTreeMap<_, _> =
                    m.rows.iter().map(|r| (r.key, &r.exe)).collect();
                for c in children.iter().take(1000) {
                    let n = names.get(c).map(|e| safe(e)).unwrap_or_default();
                    ui.label(format!("{} {n}", c.tgid));
                }
            }
            Tab::Maps => match maps {
                Some(rows) => {
                    for r in rows.iter().take(1000) {
                        ui.monospace(format!(
                            "{:012x}-{:012x} {} {}",
                            r.start,
                            r.end,
                            safe_str(&r.perms),
                            safe(&r.path)
                        ));
                    }
                }
                None => {
                    ui.label("Loading memory maps...");
                }
            },
            Tab::Findings => {
                if findings.is_empty() {
                    ui.label("No findings for this process.");
                }
                let wall = match &m.conn {
                    ConnState::Connected {
                        boot_to_wall_ns, ..
                    } => *boot_to_wall_ns,
                    _ => 0,
                };
                for f in findings {
                    let score = row.map(|r| r.score).unwrap_or(0);
                    let parent = row
                        .and_then(|r| r.parent)
                        .and_then(|p| m.rows.iter().find(|x| x.key == p));
                    let ctx = explain::ExplainCtx {
                        score,
                        band: match score {
                            0 => sysscope_core::Band::None,
                            1..=29 => sysscope_core::Band::Low,
                            30..=59 => sysscope_core::Band::Suspicious,
                            _ => sysscope_core::Band::High,
                        },
                        start_ns: f.proc.start_ticks.saturating_mul(10_000_000),
                        parent: parent.map(|p| (p.exe.clone(), p.key.tgid)),
                        uid: row.map(|r| r.uid).unwrap_or(0),
                        boot_to_wall_ns: wall,
                        tz_offset_s: 0,
                    };
                    ui.monospace(explain::render_safe(f, &ctx));
                    ui.separator();
                }
            }
        });
}

fn alerts(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let r = ui.label(RichText::new(format!("Alerts ({})", m.alerts.len())).strong());
    tag(&r, Role::List, "alerts");
    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            if m.alerts.is_empty() {
                ui.label("No alerts.");
            }
            for (i, f) in m.alerts.iter().enumerate() {
                let text = format!(
                    "{} {} - {} (pid {}): {}",
                    safe_str(&f.rule),
                    safe_str(&f.title),
                    safe(&f.exe),
                    f.proc.tgid,
                    safe_str(&f.summary)
                );
                if ui.selectable_label(false, text).clicked() {
                    acts.push(Action::ClickAlert(i));
                }
            }
        });
}
