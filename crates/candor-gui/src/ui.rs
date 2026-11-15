//! The window (spec sections 4, 5, 8): a pure function of the `Model` that
//! returns the `Action`s the user took this frame.
//!
//! Layout: a top bar (the word "candor", Processes / Findings / Glasshouse,
//! search, a menu with daemon status and settings), then one page. The
//! Processes page is either the overview (stat cards and the process table)
//! or one process's detail (Overview, Map, Events).
//!
//! Every element the tests look for has a stable accessibility label
//! (`status`, `mode`, `search`, `pause`, `export`, `loss`, `procs`,
//! `alerts`, `sort-<column>`, `detail-<tab>`, `back`, `follow`). Findings
//! always have a dot and words or a score, never colour alone.

use crate::model::{
    Action, Column, ConnState, DetailView, EventKindFilter, Model, Page, RowView, Tab,
};
use crate::theme::{self, color, space};
use crate::widgets::{self, Severity, tag};
use candor_core::display::{safe, safe_str};
use candor_proto::{DaemonMsg, Event, EventKind, Finding, Mode};
use egui::{Key, Role, Ui, vec2};

/// The 6.4 text, shown verbatim on the Glasshouse page (I13).
pub const GLASSHOUSE_LIMITS: &str = candor_core::explain::GLASSHOUSE_LIMITATION;

/// Product statement (plan section 1).
pub const STATEMENT: &str = "Candor shows what programs on your Linux machine are doing and explains why some behaviour looks suspicious. It is a visibility tool with explainable heuristics, not an antivirus, and it cannot be relied on to stop or contain malware.";

/// The page frame: background colour and the spec's page padding, with the
/// content centred at most `CONTENT_MAX` wide.
fn page_frame(ui: &Ui) -> egui::Frame {
    let w = ui.available_width();
    let side = ((w - space::CONTENT_MAX) / 2.0).max(space::PAGE_X);
    egui::Frame::new()
        .fill(color::BG)
        .inner_margin(egui::Margin {
            left: side as i8,
            right: side as i8,
            top: space::PAGE_TOP as i8,
            bottom: space::XXXL as i8,
        })
}

fn live(m: &Model) -> bool {
    matches!(m.conn, ConnState::Connected { .. } | ConnState::Replay(_))
}

/// Draws the whole window into the root `ui`; returns this frame's actions.
pub fn draw(ui: &mut Ui, m: &Model) -> Vec<Action> {
    let mut acts = Vec::new();
    keyboard(ui, m, &mut acts);
    let frame = page_frame(ui);
    egui::Panel::top("top")
        .frame(egui::Frame {
            inner_margin: egui::Margin {
                bottom: space::S as i8,
                ..frame.inner_margin
            },
            ..frame
        })
        .show(ui, |ui| top_bar(ui, m, &mut acts));
    if let Some(k) = m.confirm_follow {
        confirm_follow(ui, m, k, &mut acts);
    }
    egui::CentralPanel::default()
        .frame(egui::Frame {
            inner_margin: egui::Margin {
                top: space::L as i8,
                ..frame.inner_margin
            },
            ..frame
        })
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt(("page", page_key(m)))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = space::L;
                    banners(ui, m, &mut acts);
                    if !live(m) && m.rows.is_empty() && m.page != Page::Glasshouse {
                        conn_state(ui, m, &mut acts);
                        return;
                    }
                    match m.page {
                        Page::Glasshouse => crate::ghui::page(ui, m, &mut acts),
                        Page::Findings => findings_page(ui, m, &mut acts),
                        Page::Processes if m.detail_open && m.selected.is_some() => {
                            detail(ui, m, &mut acts)
                        }
                        Page::Processes => overview(ui, m, &mut acts),
                    }
                });
        });
    acts
}

/// Each page, and each detail view, keeps its own scroll position.
fn page_key(m: &Model) -> u8 {
    match (m.page, m.detail_open) {
        (Page::Processes, false) => 0,
        (Page::Processes, true) => match m.tab.view() {
            DetailView::Overview => 1,
            DetailView::Map => 4,
            DetailView::Events => 5,
        },
        (Page::Findings, _) => 2,
        (Page::Glasshouse, _) => 3,
    }
}

/// `/` search, `Esc` back, arrows move, `Enter` opens, `f` follows.
fn keyboard(ui: &Ui, m: &Model, acts: &mut Vec<Action>) {
    let typing = ui.ctx().memory(|mem| mem.focused().is_some());
    let (slash, esc, up, down, enter, f) = ui.input(|i| {
        (
            i.key_pressed(Key::Slash),
            i.key_pressed(Key::Escape),
            i.key_pressed(Key::ArrowUp),
            i.key_pressed(Key::ArrowDown),
            i.key_pressed(Key::Enter),
            i.key_pressed(Key::F),
        )
    });
    if esc {
        if typing {
            ui.ctx().memory_mut(|mem| mem.request_focus(egui::Id::NULL));
        } else if m.confirm_follow.is_some() {
            acts.push(Action::CancelFollow);
        } else {
            acts.push(Action::Back);
        }
    }
    if typing || m.tab == Tab::Map && m.detail_open {
        return; // the map has its own keys
    }
    if slash {
        ui.ctx()
            .memory_mut(|mem| mem.request_focus(egui::Id::unique("search-field")));
    }
    let on_list = m.page == Page::Processes && !m.detail_open;
    if on_list && up {
        acts.push(Action::Cursor(-1));
    }
    if on_list && down {
        acts.push(Action::Cursor(1));
    }
    if on_list
        && enter
        && let Some(k) = m.selected
    {
        acts.push(Action::Open(k));
    }
    if f && m.page == Page::Processes
        && let Some(k) = m.selected
        && !matches!(m.mode, Mode::Follow { .. })
    {
        acts.push(Action::RequestFollow(k));
    }
}

fn top_bar(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = space::XS;
        ui.label(theme::brand("candor"));
        ui.add_space(space::XL);
        let r = widgets::nav_tab(ui, "Processes", m.page == Page::Processes);
        if r.clicked() {
            acts.push(Action::ShowPage(Page::Processes));
            if m.detail_open && m.page == Page::Processes {
                acts.push(Action::Back);
            }
        }
        let n = m.alerts.len();
        let r = widgets::nav_tab(
            ui,
            &if n > 0 {
                format!("Findings  {n}")
            } else {
                "Findings".into()
            },
            m.page == Page::Findings,
        );
        tag(&r, Role::Tab, "alerts");
        if r.clicked() {
            acts.push(Action::ShowPage(Page::Findings));
        }
        let r = widgets::nav_tab(ui, "Glasshouse", m.page == Page::Glasshouse);
        if r.clicked() {
            acts.push(Action::ShowPage(Page::Glasshouse));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = space::S;
            menu(ui, m, acts);
            let mut text = m.filter.clone();
            let r = egui::Frame::new()
                .fill(color::SURFACE)
                .corner_radius(egui::CornerRadius::same(theme::radius::CONTROL))
                .inner_margin(egui::Margin::symmetric(space::M as i8, space::S as i8))
                .show(ui, |ui| {
                    let size = vec2(space::SEARCH_W + space::XL, space::CONTROL - space::L);
                    ui.allocate_ui_with_layout(
                        size,
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            widgets::search_icon(ui);
                            ui.add(
                                egui::TextEdit::singleline(&mut text)
                                    .id(egui::Id::unique("search-field"))
                                    .hint_text(theme::dim("Search processes"))
                                    .frame(egui::Frame::NONE)
                                    .text_color(color::TEXT)
                                    .desired_width(space::SEARCH_W),
                            )
                        },
                    )
                    .inner
                })
                .inner;
            tag(&r, Role::TextInput, "search");
            if text != m.filter {
                acts.push(Action::Filter(text));
                if m.page != Page::Processes {
                    acts.push(Action::ShowPage(Page::Processes));
                }
            }
        });
    });
}

/// The menu at the far right: daemon status, settings, about.
fn menu(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let (word, sev) = match &m.conn {
        ConnState::Connected { .. } => ("Live", None),
        ConnState::Replay(_) => ("Replay", None),
        ConnState::Connecting => ("Connecting", Some(Severity::Caution)),
        _ => ("Offline", Some(Severity::Caution)),
    };
    let r = ui.add(
        egui::Button::new(theme::dim(format!("{word}  ...")))
            .fill(color::SURFACE)
            .stroke(egui::Stroke::NONE)
            .corner_radius(egui::CornerRadius::same(theme::radius::CONTROL))
            .min_size(vec2(0.0, space::CONTROL)),
    );
    let status = status_text(m);
    r.widget_info(|| egui::WidgetInfo::labeled(Role::Button, true, "status"));
    if let Some(s) = sev {
        let p = r.rect.left_center() + vec2(space::S, 0.0);
        ui.painter().circle_filled(p, space::MENU_DOT_R, s.color());
    }
    egui::Popup::menu(&r).show(|ui| {
        ui.set_min_width(space::SIDE_PANEL);
        ui.spacing_mut().item_spacing.y = space::S;
        ui.label(theme::section("Daemon"));
        ui.label(theme::body(status));
        if m.multi_user_now() {
            ui.label(theme::dim("Monitoring all users on this machine"));
        }
        for n in &m.unavailable {
            let r = ui.label(theme::dim(n.clone()));
            tag(&r, Role::Label, "feature-unavailable");
        }
        widgets::hairline(ui);
        ui.label(theme::section("Permissions"));
        group_access(ui, m, acts);
        widgets::hairline(ui);
        ui.label(theme::section("Settings"));
        let mut auto = m.autostart;
        if ui
            .checkbox(&mut auto, theme::body("Open Candor when I log in"))
            .on_hover_text("Adds Candor to your desktop's startup programs (~/.config/autostart). The daemon itself starts at boot separately.")
            .clicked()
        {
            acts.push(Action::SetAutostart(auto));
        }
        let mut min = m.settings.start_minimised;
        if ui
            .checkbox(&mut min, theme::body("Start minimised"))
            .on_hover_text("When Candor opens at login, it starts minimised to the taskbar.")
            .clicked()
        {
            acts.push(Action::SetStartMinimised(min));
        }
        let mut red = m.redact;
        if ui
            .checkbox(&mut red, theme::body("Hide personal details in paths"))
            .on_hover_text("Home folder, user name and host name are replaced, as in exports.")
            .clicked()
        {
            acts.push(Action::ToggleRedact);
        }
        widgets::hairline(ui);
        ui.label(theme::section("About Candor"));
        ui.add(egui::Label::new(theme::dim(STATEMENT)).wrap());
    });
}

/// Follow (and act) need the candor-act group: show where the user stands
/// and offer to join. Joining asks the system for the password.
fn group_access(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    use crate::access::GroupState;
    match m.act_access {
        GroupState::Active => {
            ui.label(theme::body("You may follow processes (group candor-act)."));
        }
        GroupState::NeedsRelogin => {
            ui.label(theme::body(
                "You are in candor-act. Log out and back in to start using it.",
            ));
        }
        GroupState::NotMember => {
            ui.label(theme::body(
                "Following a process needs the candor-act group.",
            ));
            let r = widgets::secondary(ui, "Add me to candor-act", !m.joining);
            tag(&r, Role::Button, "join-act");
            if r.clicked() {
                acts.push(Action::JoinGroup("candor-act"));
            }
            ui.label(theme::dim(
                "Your system asks for your password; Candor never sees it. Then log out and back in.",
            ));
        }
        GroupState::NoGroup => {
            ui.label(theme::dim(
                "The candor-act group does not exist here: install the Candor package first.",
            ));
        }
    }
    if crate::model::act_enabled(m) {
        ui.label(theme::dim(
            "Act mode (pause, resume, kill) is on in the daemon.",
        ));
    } else {
        ui.label(theme::dim(
            "Act mode (pause, resume, kill) is off. Root turns it on with enable_act = true in /etc/candor/candord.toml.",
        ));
    }
}

fn status_text(m: &Model) -> String {
    match &m.conn {
        ConnState::Connected {
            version, kernel, ..
        } => format!("Daemon {version} on kernel {kernel}"),
        ConnState::Connecting => "Connecting to the daemon...".into(),
        ConnState::DaemonDown(_) => "The daemon is not running".into(),
        ConnState::PermissionDenied(_) => "Permission denied on the daemon socket".into(),
        ConnState::ProtoMismatch(_) => "The daemon speaks a different protocol version".into(),
        ConnState::Replay(p) => format!("Replay of {}", safe_str(p)),
    }
}

/// Banners that must stay visible: stale data, events not recorded.
fn banners(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    if !live(m) && !m.rows.is_empty() {
        widgets::card(ui, |ui| {
            let r = widgets::caution_line(
                ui,
                "Not connected to the daemon: showing the last data received. Reconnecting...",
            );
            tag(&r, Role::Label, "stale");
        });
    }
    if m.loss_banner() {
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                let r = ui
                    .scope(|ui| {
                        ui.set_max_width(ui.available_width() - space::BANNER_ACTIONS);
                        widgets::caution_line(ui, &format!(
                            "Some activity was not recorded: {} events lost (ring buffer {}, per-process budget {}, scratch {}, undecodable {}, untracked because the process table was full {}, skipped by the kernel {}). What you see is incomplete.",
                            m.loss_total(), m.loss.ringbuf, m.loss.budget, m.loss.scratch, m.loss.decode, m.loss.untracked, m.loss.missed
                        ))
                    })
                    .inner;
                tag(&r, Role::Label, "loss-banner");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if widgets::secondary(ui, "Dismiss", true).clicked() {
                        acts.push(Action::DismissLoss);
                    }
                });
            });
            loss_explained(ui, m);
        });
    }
    if let Some(n) = &m.notice {
        ui.label(theme::dim(n.clone()));
    }
}

/// What each loss counter means, in plain words, and which processes lost
/// the most events (their events were cut, not the whole system's).
fn loss_explained(ui: &mut Ui, m: &Model) {
    egui::CollapsingHeader::new(theme::dim("What does this mean?"))
        .id_salt("loss-why")
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = space::S;
            let lines = [
                (
                    "Per-process budget",
                    m.loss.budget,
                    "Candor's own limit: each process may report about 2000 file and network events a second. Beyond that its extra events are counted here instead of recorded, so one busy program (a build, a backup, a file indexer) cannot flood the daemon or slow the computer. Program starts and exits are never dropped.",
                ),
                (
                    "Ring buffer",
                    m.loss.ringbuf,
                    "The kernel-to-daemon queue was full for a moment, usually during a sudden burst.",
                ),
                (
                    "Skipped by the kernel",
                    m.loss.missed,
                    "The Linux kernel did not run Candor's probe because the same probe was already running on that CPU. This is a kernel limit, not a Candor setting; it happens more on fully preemptible kernels.",
                ),
                (
                    "Untracked",
                    m.loss.untracked,
                    "Events of processes started while Candor's process table was full.",
                ),
                (
                    "Scratch and undecodable",
                    m.loss.scratch.saturating_add(m.loss.decode),
                    "Events the probe could not build or the daemon could not read. Normally zero.",
                ),
            ];
            for (name, n, why) in lines {
                if n == 0 {
                    continue;
                }
                ui.horizontal_wrapped(|ui| {
                    ui.label(theme::name(name));
                    ui.label(theme::mono(n.to_string()));
                });
                ui.add(egui::Label::new(theme::dim(why)).wrap());
            }
            let mut top: Vec<&candor_proto::ProcRow> =
                m.rows.iter().filter(|r| r.ev_dropped > 0).collect();
            top.sort_by_key(|r| std::cmp::Reverse(r.ev_dropped));
            if !top.is_empty() {
                ui.label(theme::label("Processes that lost the most events"));
                for r in top.into_iter().take(5) {
                    let n = m.shown(&candor_core::display::exe_shown(r));
                    ui.label(theme::mono(format!(
                        "{}  ({})  {} not recorded",
                        n.rsplit('/').next().unwrap_or(&n),
                        r.key.tgid,
                        r.ev_dropped
                    )));
                }
                ui.label(theme::dim(
                    "Their other activity, and every other process, is still recorded.",
                ));
            }
        });
}

fn confirm_follow(ui: &mut Ui, m: &Model, k: candor_proto::ProcKey, acts: &mut Vec<Action>) {
    let name = m
        .rows
        .iter()
        .find(|r| r.key == k)
        .map(candor_core::display::exe_shown)
        .unwrap_or_default();
    egui::Window::new(theme::section("Follow this process?"))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0))
        .show(ui.ctx(), |ui| {
            ui.spacing_mut().item_spacing.y = space::M;
            ui.label(theme::body(format!(
                "Follow {} (pid {}) and everything it starts?",
                m.shown(&name),
                k.tgid
            )));
            widgets::caution_line(ui, "Other processes will not be traced while following.");
            ui.horizontal(|ui| {
                let r = widgets::primary(ui, "Follow", true);
                tag(&r, Role::Button, "confirm-follow");
                if r.clicked() {
                    acts.push(Action::ConfirmFollow);
                }
                if widgets::secondary(ui, "Cancel", true).clicked() {
                    acts.push(Action::CancelFollow);
                }
            });
        });
}

/// The daemon cannot be reached: one centred message and the fix.
fn conn_state(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    ui.add_space(space::MESSAGE_TOP);
    ui.vertical_centered(|ui| {
        ui.set_max_width(space::MESSAGE_W);
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = space::M;
            let (title, why, fix): (&str, String, Vec<&str>) = match &m.conn {
                ConnState::DaemonDown(why) => (
                    "The Candor daemon is not running",
                    safe_str(why),
                    vec![
                        "Start it, and at every boot, with:",
                        "sudo systemctl enable --now candord",
                    ],
                ),
                ConnState::PermissionDenied(path) => (
                    "You may not read the daemon's socket",
                    safe_str(path),
                    vec![
                        "Join the candor group, then log out and back in. Use the button below, or in a terminal:",
                        "sudo usermod -aG candor $USER",
                    ],
                ),
                ConnState::ProtoMismatch(msg) => (
                    "The daemon is a different version",
                    safe_str(msg),
                    vec!["Install matching versions of candord and candor-gui."],
                ),
                ConnState::Connecting => ("Connecting to the daemon...", String::new(), vec![]),
                _ => ("No data yet", String::new(), vec![]),
            };
            ui.horizontal(|ui| {
                widgets::status_dot(ui, Severity::Caution);
                ui.label(theme::title(title));
            });
            if !why.is_empty() {
                ui.label(theme::dim(why));
            }
            for (i, line) in fix.iter().enumerate() {
                if line.starts_with("sudo") {
                    egui::Frame::new()
                        .fill(color::BG)
                        .corner_radius(egui::CornerRadius::same(theme::radius::CONTROL))
                        .inner_margin(egui::Margin::same(space::M as i8))
                        .show(ui, |ui| {
                            ui.label(theme::mono(*line).color(color::TEXT_STRONG));
                        });
                } else {
                    ui.label(theme::body(*line));
                }
                let _ = i;
            }
            if matches!(m.conn, ConnState::PermissionDenied(_)) {
                match m.view_access {
                    crate::access::GroupState::NeedsRelogin | crate::access::GroupState::Active => {
                        ui.label(theme::body("You are in the candor group: log out and back in."));
                    }
                    _ => {
                        let r = widgets::primary(ui, "Add me to the candor group", !m.joining);
                        tag(&r, Role::Button, "join-candor");
                        if r.clicked() {
                            acts.push(Action::JoinGroup("candor"));
                        }
                    }
                }
            }
            if matches!(m.conn, ConnState::DaemonDown(_)) {
                ui.label(theme::dim(
                    "For development: sudo ./target/debug/candord --dev",
                ));
            }
            ui.label(theme::dim("This window reconnects by itself."));
        });
        ui.add_space(space::XL);
        ui.add(egui::Label::new(theme::dim(STATEMENT)).wrap());
    });
}

// ----- Processes overview (5.1) ---------------------------------------------

/// Label, value, optional line under it, series.
type StatCard<'a> = (
    &'static str,
    String,
    Option<(String, egui::Color32, &'static str)>,
    &'a [f32],
);

fn last(q: &std::collections::VecDeque<f32>) -> f32 {
    q.back().copied().unwrap_or(0.0)
}

fn overview(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    // Stat strip.
    let lost = m.loss_total();
    let cols = if ui.available_width() < space::NARROW {
        1
    } else {
        3
    };
    let cpu: Vec<f32> = m.sys_cpu.iter().copied().collect();
    let mem: Vec<f32> = m.sys_mem.iter().copied().collect();
    let eps: Vec<f32> = m.sys_eps.iter().copied().collect();
    let lost_line = (
        format!("{lost} not recorded"),
        if lost > 0 {
            color::CAUTION
        } else {
            color::TEXT_DIM
        },
        "loss",
    );
    let cards: [StatCard<'_>; 3] = [
        ("CPU", format!("{:.0}%", last(&m.sys_cpu)), None, &cpu),
        (
            "Memory",
            widgets::bytes(last(&m.sys_mem) as u64),
            None,
            &mem,
        ),
        (
            "Events / sec",
            format!("{:.0}", last(&m.sys_eps)),
            Some(lost_line),
            &eps,
        ),
    ];
    ui.columns(cols, |c| {
        for (i, (label, value, sub, series)) in cards.into_iter().enumerate() {
            if let Some(col) = c.get_mut(i % cols) {
                widgets::stat_card(col, label, &value, sub, series);
            }
        }
    });
    // Heading row: count, mode, and on the right the actions.
    let flagged = m.rows.iter().filter(|r| r.score >= 30).count();
    ui.horizontal(|ui| {
        ui.label(theme::section(format!("{} processes", m.rows.len())));
        ui.label(theme::dim(format!("· {flagged} flagged ·")));
        let r = match m.mode {
            Mode::Follow { follow } if live(m) => {
                let exe = m
                    .rows
                    .iter()
                    .find(|r| r.key == follow)
                    .map(candor_core::display::exe_shown)
                    .unwrap_or_default();
                let shown = m.shown(&exe);
                let short = shown.rsplit('/').next().unwrap_or(&shown).to_string();
                let r = ui.label(
                    theme::dim(format!("following {short} ({})", follow.tgid)).color(color::ACCENT),
                );
                if widgets::text_button(ui, "Stop").clicked() {
                    acts.push(Action::Unfollow);
                }
                r
            }
            _ if live(m) => ui.label(theme::dim("watching all processes")),
            _ => ui.label(theme::dim("not connected")),
        };
        tag(&r, Role::Label, "mode");
        if m.paused {
            ui.label(
                theme::dim(format!("· paused, {} updates skipped", m.skipped))
                    .color(color::CAUTION),
            );
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Right to left: the last item here is the leftmost on screen.
            if let Some(i) = widgets::segmented(
                ui,
                &[
                    ("Table", !m.tree, "view-table"),
                    ("Tree", m.tree, "view-tree"),
                ],
            ) && (i == 1) != m.tree
            {
                acts.push(Action::ToggleTree);
            }
            column_picker(ui, m, acts);
            if m.tree {
                let all_open = m.visible().iter().all(|v| v.below == 0 || v.open);
                let r = widgets::secondary(
                    ui,
                    if all_open {
                        "Collapse all"
                    } else {
                        "Expand all"
                    },
                    true,
                );
                tag(&r, Role::Button, "tree-all");
                if r.clicked() {
                    acts.push(Action::OpenAll(!all_open));
                }
            }
            let r = widgets::secondary(ui, "Export", live(m));
            tag(&r, Role::Button, "export");
            if r.clicked() {
                acts.push(Action::Export);
            }
            let r = widgets::secondary(ui, if m.paused { "Resume" } else { "Pause" }, live(m));
            tag(&r, Role::Button, "pause");
            if r.clicked() {
                acts.push(Action::TogglePause);
            }
        });
    });
    if m.multi_user_now() {
        ui.label(theme::dim("Monitoring all users on this machine."));
    }
    procs(ui, m, acts);
}

/// Optional columns (threads, files opened, children, user).
const EXTRA: [(Column, &str); 4] = [
    (Column::Threads, "Threads"),
    (Column::Opens, "Files opened"),
    (Column::Children, "Children"),
    (Column::User, "User"),
];

fn column_picker(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let r = widgets::secondary(ui, "Columns", true);
    egui::Popup::menu(&r).show(|ui| {
        for (c, name) in EXTRA {
            let mut on = m.extra_cols.contains(&c.id());
            if ui.checkbox(&mut on, theme::body(name)).clicked() {
                acts.push(Action::ToggleColumn(c));
            }
        }
    });
}

fn procs(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let rows = m.visible();
    if rows.is_empty() {
        ui.label(theme::dim(if m.filter.is_empty() {
            "No processes yet. They appear here as soon as the daemon reports them."
        } else {
            "No processes match the search. Clear it to see them all."
        }));
        return;
    }
    let mut cols: Vec<(&str, Column)> = vec![
        ("Process", Column::Exe),
        ("CPU", Column::Cpu),
        ("Memory", Column::Mem),
        ("Connections", Column::Conns),
    ];
    for (c, name) in EXTRA {
        if m.extra_cols.contains(&c.id()) {
            cols.push((name, c));
        }
    }
    cols.push(("Score", Column::Score));
    let n = cols.len();
    let resp = ui.push_id("procs", |ui| {
        let mut t = egui_extras::TableBuilder::new(ui)
            .striped(false)
            .resizable(false)
            .vscroll(false)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .sense(egui::Sense::click())
            .column(
                egui_extras::Column::remainder()
                    .at_least(space::NAME_COL_MIN)
                    .clip(true),
            )
            .column(egui_extras::Column::exact(space::CPU_COL_W));
        for _ in 2..n {
            t = t.column(egui_extras::Column::exact(space::COL_W));
        }
        t.header(space::HEADER, |mut h| {
            for (i, (name, col)) in cols.iter().enumerate() {
                h.col(|ui| {
                    let arrow = if m.sort.0 == *col {
                        if m.sort.1 { "  ↓" } else { "  ↑" }
                    } else {
                        ""
                    };
                    let layout = if i + 1 == n {
                        egui::Layout::right_to_left(egui::Align::Center)
                    } else {
                        egui::Layout::left_to_right(egui::Align::Center)
                    };
                    ui.with_layout(layout, |ui| {
                        let r = ui.add(
                            egui::Button::new(theme::label(format!("{name}{arrow}"))).frame(false),
                        );
                        let id: &'static str = match col {
                            Column::Exe => "sort-process",
                            Column::Cpu => "sort-cpu",
                            Column::Mem => "sort-memory",
                            Column::Conns => "sort-connections",
                            Column::Threads => "sort-threads",
                            Column::Opens => "sort-files",
                            Column::Children => "sort-children",
                            Column::User => "sort-user",
                            Column::Score => "sort-score",
                            Column::Pid => "sort-pid",
                        };
                        tag(&r, Role::Button, id);
                        if r.clicked() {
                            acts.push(Action::Sort(*col));
                        }
                    });
                    let rect = ui.max_rect();
                    ui.painter().hline(
                        rect.x_range(),
                        rect.bottom(),
                        egui::Stroke::new(space::HAIR, color::SURFACE_RAISED),
                    );
                });
            }
        })
        .body(|body| {
            body.rows(space::ROW, rows.len(), |mut row| {
                let Some(v) = rows.get(row.index()) else {
                    return;
                };
                row.set_selected(m.selected == Some(v.row.key));
                proc_cells(&mut row, v, m, &cols, acts);
                let resp = row.response();
                if resp.clicked() {
                    acts.push(Action::Open(v.row.key));
                }
                resp.context_menu(|ui| {
                    if ui.button(theme::body("Open details")).clicked() {
                        acts.push(Action::Open(v.row.key));
                        ui.close();
                    }
                    if ui.button(theme::body("Follow this process tree")).clicked() {
                        acts.push(Action::RequestFollow(v.row.key));
                        ui.close();
                    }
                });
            });
        })
    });
    tag(&resp.response, Role::Table, "procs");
    // Rows keep their order while the pointer is over the table.
    let over = resp.response.contains_pointer();
    if over != m.hold {
        acts.push(Action::HoldOrder(over));
    }
}

fn cell_divider(ui: &Ui) {
    let rect = ui.max_rect();
    ui.painter().hline(
        rect.x_range(),
        rect.bottom(),
        egui::Stroke::new(space::HAIR, color::HAIRLINE),
    );
}

fn proc_cells(
    row: &mut egui_extras::TableRow<'_, '_>,
    v: &RowView,
    m: &Model,
    cols: &[(&str, Column)],
    acts: &mut Vec<Action>,
) {
    let r = &v.row;
    let sev = Severity::of_score(r.score);
    for (i, (_, col)) in cols.iter().enumerate() {
        row.col(|ui| {
            cell_divider(ui);
            match col {
                Column::Exe => {
                    ui.horizontal(|ui| {
                        if v.depth > 0 {
                            let x0 = ui.cursor().left();
                            let indent = space::INDENT * v.depth.min(30) as f32;
                            let y = ui.max_rect().center().y;
                            let stroke = egui::Stroke::new(space::HAIR, color::EDGE);
                            let xl = x0 + indent - space::S;
                            ui.painter().vline(xl, (y - space::M)..=y, stroke);
                            ui.painter()
                                .hline((xl)..=(x0 + indent - space::XS), y, stroke);
                            ui.add_space(indent);
                        }
                        ui.spacing_mut().item_spacing.x = space::DOT_GAP;
                        if m.tree {
                            // The arrow opens or closes this branch; rows
                            // without children keep the slot so names align.
                            let r = widgets::disclosure(ui, v.below > 0, v.open);
                            if v.below > 0 {
                                tag(&r, Role::Button, "tree-toggle");
                                if r.clicked() {
                                    acts.push(Action::ToggleOpen(v.row.key));
                                }
                            }
                        }
                        widgets::status_dot(ui, sev);
                        let name = m.shown(&v.name);
                        let short = name.rsplit('/').next().unwrap_or(&name).to_string();
                        let mut t = theme::name(short);
                        if r.followed {
                            t = t.color(color::ACCENT);
                        }
                        if r.exited_ts.is_some() {
                            t = t.color(color::TEXT_DIM);
                        }
                        ui.label(t).on_hover_text(name);
                        ui.label(theme::mono_dim(r.key.tgid.to_string()));
                        if r.exited_ts.is_some() {
                            ui.label(theme::dim("exited"));
                        }
                        if m.tree && v.below > 0 && !v.open {
                            ui.label(theme::label(format!("{} below", v.below)));
                        }
                    });
                }
                Column::Cpu => {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = space::M;
                        let (rect, _) = ui.allocate_exact_size(
                            vec2(space::ROW_SPARK_W, space::ROW_SPARK_H),
                            egui::Sense::hover(),
                        );
                        let hist: Vec<f32> = m
                            .cpu_hist
                            .get(&r.key)
                            .map(|q| q.iter().copied().collect())
                            .unwrap_or_default();
                        widgets::sparkline(ui, rect, &hist, color::TEXT_DIM);
                        ui.label(theme::mono(format!("{:.1}%", r.cpu_pct)));
                    });
                }
                Column::Mem => {
                    ui.label(theme::mono(widgets::bytes(r.rss)));
                }
                Column::Conns => {
                    ui.label(theme::mono(r.n_conn.to_string()));
                }
                Column::Threads => {
                    ui.label(theme::mono(r.threads.to_string()));
                }
                Column::Opens => {
                    ui.label(theme::mono(r.n_open.to_string()));
                }
                Column::Children => {
                    ui.label(theme::mono(r.n_child.to_string()));
                }
                Column::User => {
                    ui.label(theme::mono(r.uid.to_string()));
                }
                Column::Pid => {
                    ui.label(theme::mono(r.key.tgid.to_string()));
                }
                Column::Score => {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if r.score > 0 {
                            ui.label(theme::score(r.score.to_string(), sev.color()))
                                .on_hover_text(format!("{} ({})", sev.words(), v.band));
                        } else if r.tree_score > 0 {
                            ui.label(theme::mono_dim(format!("tree {}", r.tree_score)))
                                .on_hover_text("The highest score among the processes it started");
                        } else {
                            ui.label(theme::mono_dim("0"));
                        }
                    });
                }
            }
            let _ = i;
        });
    }
}

// ----- Process detail (5.2) -------------------------------------------------

fn detail(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let Some(sel) = m.selected else { return };
    let row = m.rows.iter().find(|r| r.key == sel);
    let name = row.map(candor_core::display::exe_shown).unwrap_or_default();
    let shown = m.shown(&name);
    let short = shown.rsplit('/').next().unwrap_or(&shown).to_string();
    let sev = Severity::of_score(row.map(|r| r.score).unwrap_or(0));
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = space::M;
        let r =
            ui.add(egui::Button::new(theme::body("Processes").color(color::ACCENT)).frame(false));
        tag(&r, Role::Link, "back");
        if r.clicked() {
            acts.push(Action::Back);
        }
        ui.label(theme::dim("/"));
        widgets::status_dot(ui, sev);
        ui.label(theme::title(short)).on_hover_text(shown.clone());
        ui.label(theme::mono_dim(format!("pid {}", sel.tgid)));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let following_this = matches!(m.mode, Mode::Follow { follow } if follow == sel)
                || row.is_some_and(|r| r.followed);
            if matches!(m.mode, Mode::Follow { .. }) {
                if widgets::secondary(ui, "Stop", true).clicked() {
                    acts.push(Action::Unfollow);
                }
                if following_this {
                    let _ = widgets::primary(ui, "Following", false);
                }
            } else {
                let r = widgets::outlined(ui, "Follow this process")
                    .on_hover_text("Other processes will not be traced while following.");
                tag(&r, Role::Button, "follow");
                if r.clicked() {
                    acts.push(Action::RequestFollow(sel));
                }
            }
        });
    });
    if crate::model::act_enabled(m) {
        act_controls(ui, m, sel, acts);
    }
    let view = m.tab.view();
    if let Some(i) = widgets::segmented(
        ui,
        &[
            ("Overview", view == DetailView::Overview, "detail-overview"),
            ("Map", view == DetailView::Map, "detail-map"),
            ("Events", view == DetailView::Events, "detail-events"),
        ],
    ) {
        let t = match i {
            0 => Tab::Overview,
            1 => Tab::Map,
            _ => Tab::Events,
        };
        if t.view() != view {
            acts.push(Action::ShowTab(t));
        }
    }
    let Some(d @ DaemonMsg::Detail { .. }) = m.detail() else {
        ui.label(theme::dim("Waiting for details from the daemon..."));
        return;
    };
    match view {
        DetailView::Overview => detail_overview(ui, m, d, acts),
        DetailView::Map => crate::mapview::show(ui, m, acts),
        DetailView::Events => detail_events(ui, m, d, acts),
    }
}

/// Act mode (experimental, D19): shown only when the daemon enables it.
fn act_controls(ui: &mut Ui, m: &Model, sel: candor_proto::ProcKey, acts: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            widgets::status_dot(ui, Severity::Caution);
            ui.label(theme::name("Act (experimental)").color(color::CAUTION));
            let r = widgets::secondary(ui, "Pause", true);
            tag(&r, Role::Button, "act-pause");
            if r.clicked() {
                acts.push(Action::ActPause(sel));
            }
            let undo = m.act_paused == Some(sel);
            let r = widgets::secondary(ui, if undo { "Undo (resume)" } else { "Resume" }, true);
            tag(&r, Role::Button, "act-resume");
            if r.clicked() {
                acts.push(Action::ActResume(sel));
            }
            let mut t = m.act_kill_text.clone();
            let r = ui.add(
                egui::TextEdit::singleline(&mut t)
                    .hint_text(theme::dim("type the pid to kill"))
                    .desired_width(space::COL_W),
            );
            tag(&r, Role::TextInput, "act-kill-pid");
            if t != m.act_kill_text {
                acts.push(Action::ActKillText(t));
            }
            let ok = m.act_kill_text.trim() == sel.tgid.to_string();
            let r = widgets::secondary(ui, "Kill", ok);
            tag(&r, Role::Button, "act-kill");
            if r.clicked() {
                acts.push(Action::ActKill(sel));
            }
        });
    });
}

fn detail_overview(ui: &mut Ui, m: &Model, d: &DaemonMsg, acts: &mut Vec<Action>) {
    let DaemonMsg::Detail {
        series,
        syscalls,
        findings,
        files,
        conns,
        proc,
        ..
    } = d
    else {
        return;
    };
    let cols = if ui.available_width() < space::NARROW {
        1
    } else {
        2
    };
    ui.columns(cols, |c| {
        let (a, b) = c.split_at_mut(1.min(c.len()));
        let Some(left) = a.first_mut() else { return };
        widgets::card(left, |ui| {
            let id = egui::Id::unique("chart-tab");
            let cur: u8 = ui.data(|dm| dm.get_temp(id).unwrap_or(0));
            if let Some(i) = widgets::segmented(
                ui,
                &[
                    ("CPU", cur == 0, "chart-cpu"),
                    ("Memory", cur == 1, "chart-memory"),
                    ("Syscalls", cur == 2, "chart-syscalls"),
                ],
            ) {
                ui.data_mut(|dm| dm.insert_temp(id, i as u8));
            }
            match cur {
                0 => widgets::line_chart(
                    ui,
                    &series.cpu,
                    &|v| format!("{v:.1}%"),
                    "CPU use of this process over time",
                ),
                1 => {
                    let v: Vec<f32> = series.rss.iter().map(|b| *b as f32).collect();
                    widgets::line_chart(
                        ui,
                        &v,
                        &|v| widgets::bytes(v as u64),
                        "Memory use of this process over time",
                    );
                }
                _ => {
                    let mut s = syscalls.clone();
                    s.sort_by_key(|x| std::cmp::Reverse(x.count));
                    if s.is_empty() {
                        ui.label(theme::dim("No system calls counted for this process yet."));
                    }
                    for x in s.iter().take(8) {
                        ui.horizontal(|ui| {
                            ui.label(theme::mono(safe_str(&x.name)));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(theme::mono(x.count.to_string()));
                                },
                            );
                        });
                    }
                }
            }
        });
        let target = if let Some(right) = b.first_mut() {
            right
        } else {
            left
        };
        widgets::card(target, |ui| {
            what_it_did(ui, m, *proc, findings, files, conns, acts);
        });
    });
    // Findings.
    let r = ui.add(
        egui::Button::new(theme::section(if findings.is_empty() {
            "No findings for this process".to_string()
        } else {
            format!("Findings ({})", findings.len())
        }))
        .frame(false),
    );
    tag(&r, Role::Tab, "detail-findings");
    if r.clicked() {
        acts.push(Action::ShowTab(Tab::Findings));
    }
    if m.tab == Tab::Findings {
        r.scroll_to_me(Some(egui::Align::TOP));
    }
    for f in findings {
        finding_card(ui, m, f, false, acts);
    }
}

/// "What it did": parent, the process, flagged actions first, then the
/// busiest actions; at most 6 steps.
fn what_it_did(
    ui: &mut Ui,
    m: &Model,
    k: candor_proto::ProcKey,
    findings: &[Finding],
    files: &[candor_proto::FileStat],
    conns: &[candor_proto::ConnStat],
    acts: &mut Vec<Action>,
) {
    ui.label(theme::section("What it did"));
    let row = m.rows.iter().find(|r| r.key == k);
    let parent = row
        .and_then(|r| r.parent)
        .and_then(|p| m.rows.iter().find(|x| x.key == p));
    let name_of = |r: &candor_proto::ProcRow| {
        let n = m.shown(&candor_core::display::exe_shown(r));
        n.rsplit('/').next().unwrap_or(&n).to_string()
    };
    let mut steps: Vec<(String, String, Severity)> = Vec::new();
    if let Some(p) = parent {
        steps.push((name_of(p), "started".into(), Severity::None));
    }
    if let Some(r) = row {
        steps.push((name_of(r), "which ran".into(), Severity::None));
    }
    let mut seen = std::collections::BTreeSet::new();
    for f in findings {
        for e in f.evidence_events.iter().take(1) {
            let text = step_text(m, e);
            if seen.insert(text.clone()) {
                steps.push((text, safe_str(&f.title), Severity::Finding));
            }
        }
    }
    let mut busy: Vec<(u64, String)> = files
        .iter()
        .map(|f| {
            let verb = if f.write { "write" } else { "read" };
            (f.opens, format!("{verb} {}", m.shown(&safe(&f.path))))
        })
        .chain(
            conns
                .iter()
                .map(|c| (c.count, format!("connect {}:{}", safe_str(&c.addr), c.port))),
        )
        .collect();
    busy.sort_by_key(|b| std::cmp::Reverse(b.0));
    for (n, text) in busy {
        if steps.len() >= 6 {
            break;
        }
        if seen.insert(text.clone()) {
            steps.push((
                text,
                if n > 1 {
                    format!("{n} times")
                } else {
                    String::new()
                },
                Severity::None,
            ));
        }
    }
    if row.is_some_and(|r| r.exited_ts.is_some())
        && let Some(last) = steps.last_mut()
        && last.1.is_empty()
    {
        last.1 = "then exited".into();
    }
    steps.truncate(6);
    ui.spacing_mut().item_spacing.y = 0.0;
    for (i, (text, words, sev)) in steps.iter().enumerate() {
        if i > 0 {
            let (rect, _) =
                ui.allocate_exact_size(vec2(space::XL, space::L + space::XS), egui::Sense::hover());
            let x = rect.left() + space::XL;
            ui.painter().vline(
                x,
                rect.y_range(),
                egui::Stroke::new(space::HAIR, color::EDGE),
            );
        }
        ui.horizontal(|ui| {
            let border = if i == 1 && parent.is_some() || i == 0 && parent.is_none() {
                color::ACCENT
            } else {
                color::SURFACE_RAISED
            };
            egui::Frame::new()
                .fill(color::BG)
                .stroke(egui::Stroke::new(space::HAIR, border))
                .corner_radius(egui::CornerRadius::same(theme::radius::CONTROL))
                .inner_margin(egui::Margin::symmetric(
                    space::M as i8,
                    space::DOT_GAP as i8,
                ))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if *sev != Severity::None {
                            widgets::status_dot(ui, *sev);
                        }
                        ui.label(theme::mono(text.clone()).color(color::TEXT_STRONG));
                    });
                });
            if !words.is_empty() {
                let c = if *sev == Severity::Finding {
                    color::ALERT
                } else {
                    color::TEXT_DIM
                };
                ui.label(theme::label(words.clone()).color(c));
            }
        });
    }
    if steps.is_empty() {
        ui.label(theme::dim("Nothing recorded for this process yet."));
    }
    ui.add_space(space::M);
    if widgets::text_button(ui, "See everything in the map").clicked() {
        acts.push(Action::ShowTab(Tab::Map));
    }
}

fn step_text(m: &Model, e: &Event) -> String {
    match &e.kind {
        EventKind::Open { path, write, .. } => {
            format!(
                "{} {}",
                if *write { "write" } else { "read" },
                m.shown(&safe(path))
            )
        }
        EventKind::Exec { exe, .. } => format!("run {}", m.shown(&safe(exe))),
        EventKind::Connect { addr, port, .. } => format!("connect {}:{port}", safe_str(addr)),
        EventKind::Rename { old, new, .. } => {
            format!("rename {} -> {}", m.shown(&safe(old)), m.shown(&safe(new)))
        }
        EventKind::Unlink { path, .. } => format!("delete {}", m.shown(&safe(path))),
        _ => safe_str(&candor_core::explain::describe(e)),
    }
}

/// One finding: dot, title, three short columns, evidence on demand.
/// `collapsed` shows only the first line of each column (Findings page).
pub fn finding_card(ui: &mut Ui, m: &Model, f: &Finding, collapsed: bool, acts: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = space::M;
        ui.horizontal(|ui| {
            widgets::status_dot(ui, Severity::Finding);
            ui.label(theme::section(safe_str(&f.title)));
            ui.label(theme::mono_dim(safe_str(&f.rule)));
        });
        // Each reason is its own sentence: capitalised and ended with a full
        // stop, so several of them never read as one run-on line.
        let sentence = |s: &str| {
            let s = safe_str(s);
            let mut c = s.chars();
            let mut out: String = c
                .next()
                .map(|f| f.to_uppercase().collect())
                .unwrap_or_default();
            out.push_str(c.as_str());
            if !out.ends_with('.') {
                out.push('.');
            }
            out
        };
        let first = |v: &[String]| v.first().map(|s| sentence(s)).unwrap_or_default();
        let all = |v: &[String]| v.iter().map(|s| sentence(s)).collect::<Vec<_>>().join(" ");
        let cols3 = [
            ("What happened", sentence(&m.shown(&safe_str(&f.summary)))),
            (
                "Why it is flagged",
                if collapsed {
                    first(&f.why)
                } else {
                    all(&f.why)
                },
            ),
            (
                "Harmless explanation",
                if collapsed {
                    first(&f.benign)
                } else {
                    all(&f.benign)
                },
            ),
        ];
        let n = if ui.available_width() < space::NARROW {
            1
        } else {
            3
        };
        ui.columns(n, |c| {
            for (i, (label, text)) in cols3.iter().enumerate() {
                if let Some(col) = c.get_mut(i % n) {
                    // Not justified: a justified column stretches the words.
                    col.with_layout(egui::Layout::top_down(egui::Align::Min), |col| {
                        col.spacing_mut().item_spacing.y = space::LABEL_GAP;
                        col.label(theme::label(*label));
                        col.add(egui::Label::new(theme::body(text.clone())).wrap());
                    });
                }
            }
        });
        let open = m.expanded.contains(&f.id);
        let n = f.evidence.len().max(f.evidence_events.len());
        let text = if open {
            "Hide the events".to_string()
        } else if n == 1 {
            "Show 1 event behind this".to_string()
        } else {
            format!("Show {n} events behind this")
        };
        if widgets::text_button(ui, &text).clicked() {
            acts.push(Action::ToggleEvidence(f.id));
        }
        if open {
            for e in &f.evidence_events {
                ui.label(theme::mono(
                    m.shown(&safe_str(&candor_core::explain::describe(e))),
                ));
            }
            if f.evidence.len() > f.evidence_events.len() {
                ui.label(theme::dim(format!(
                    "{} more events are listed in the export.",
                    f.evidence.len() - f.evidence_events.len()
                )));
            }
            let mut meta = format!(
                "Rule {} · confidence {:.1}",
                safe_str(&f.rule),
                f.confidence
            );
            if let Some(a) = &f.attack {
                meta.push_str(&format!(" · ATT&CK {}", safe_str(a)));
            }
            ui.label(theme::label(meta));
        }
    });
}

fn kind_of(e: &Event) -> EventKindFilter {
    match e.kind {
        EventKind::Exec { .. } | EventKind::Fork { .. } | EventKind::Exit {} => {
            EventKindFilter::Exec
        }
        EventKind::Open { .. } | EventKind::Rename { .. } | EventKind::Unlink { .. } => {
            EventKindFilter::File
        }
        EventKind::Connect { .. } | EventKind::Listen { .. } => EventKindFilter::Network,
        EventKind::Ptrace { .. } => EventKindFilter::Other,
    }
}

fn detail_events(ui: &mut Ui, m: &Model, d: &DaemonMsg, acts: &mut Vec<Action>) {
    let DaemonMsg::Detail {
        recent,
        files,
        conns,
        syscalls,
        children,
        maps,
        ..
    } = d
    else {
        return;
    };
    let lists: [(&str, Tab, &'static str); 6] = [
        ("Event list", Tab::Events, "detail-list"),
        ("Files", Tab::Files, "detail-files"),
        ("Connections", Tab::Network, "detail-network"),
        ("Syscalls", Tab::Syscalls, "detail-syscalls"),
        ("Children", Tab::Children, "detail-children"),
        ("Memory maps", Tab::Maps, "detail-maps"),
    ];
    let items: Vec<(&str, bool, &'static str)> = lists
        .iter()
        .map(|(n, t, id)| (*n, m.tab == *t, *id))
        .collect();
    if let Some(i) = widgets::segmented(ui, &items)
        && let Some((_, t, _)) = lists.get(i)
    {
        acts.push(Action::ShowTab(*t));
    }
    let line = |ui: &mut Ui, text: String| {
        ui.label(theme::mono(text));
        widgets::hairline(ui);
    };
    widgets::card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = space::S;
        match m.tab {
            Tab::Files => {
                for f in files.iter().take(500) {
                    line(
                        ui,
                        format!(
                            "{}  {}{}  opened {} times",
                            m.shown(&safe(&f.path)),
                            if f.read { "r" } else { "-" },
                            if f.write { "w" } else { "-" },
                            f.opens
                        ),
                    );
                }
                if files.is_empty() {
                    ui.label(theme::dim("No files opened while traced. Files appear here when this process opens them."));
                }
            }
            Tab::Network => {
                for c in conns.iter().take(1000) {
                    line(
                        ui,
                        format!("{}:{}  x{}", safe_str(&c.addr), c.port, c.count),
                    );
                }
                if conns.is_empty() {
                    ui.label(theme::dim("No outbound connections seen. They appear here when this process connects somewhere."));
                }
            }
            Tab::Syscalls => {
                if matches!(m.mode, Mode::Follow { .. }) {
                    ui.label(theme::dim(
                        "Following: syscalls are counted only while this list is open, so other programs are not slowed down.",
                    ));
                }
                let mut s = syscalls.clone();
                s.sort_by_key(|x| std::cmp::Reverse(x.count));
                for x in s.iter().take(100) {
                    line(ui, format!("{:<24} {}", safe_str(&x.name), x.count));
                }
                if s.is_empty() {
                    ui.label(theme::dim("No system calls counted yet."));
                }
            }
            Tab::Children => {
                let names: std::collections::BTreeMap<_, _> =
                    m.rows.iter().map(|r| (r.key, &r.exe)).collect();
                for c in children.iter().take(1000) {
                    let n = names.get(c).map(|e| m.shown(&safe(e))).unwrap_or_default();
                    line(ui, format!("{:>7}  {n}", c.tgid));
                }
                if children.is_empty() {
                    ui.label(theme::dim("It has not started any programs."));
                }
            }
            Tab::Maps => match maps {
                Some(rows) => {
                    ui.label(theme::dim(
                        "The memory regions this process has mapped: its program, the libraries it loaded, its stack and heap, and memory it allocated. Each line is an address range, the access rights (r read, w write, x execute, p private) and the file behind it, if any.",
                    ));
                    for r in rows.iter().take(1000) {
                        line(
                            ui,
                            format!(
                                "{:012x}-{:012x} {} {}",
                                r.start,
                                r.end,
                                safe_str(&r.perms),
                                m.shown(&safe(&r.path))
                            ),
                        );
                    }
                }
                None => {
                    // The daemon sends memory maps only for your own
                    // processes (or to root): the rule the kernel applies to
                    // /proc/PID/maps. Anything else is refused, not slow.
                    let mine = m
                        .rows
                        .iter()
                        .find(|r| Some(r.key) == m.selected)
                        .is_some_and(|r| Some(r.uid) == crate::model::my_uid());
                    if mine {
                        ui.label(theme::dim("Loading memory maps..."));
                    } else {
                        ui.label(theme::body(
                            "Memory maps are shown only for your own processes.",
                        ));
                        ui.label(theme::dim(
                            "This process belongs to another user. The kernel lets only that user and root read its memory layout (/proc/PID/maps), and Candor keeps the same rule.",
                        ));
                    }
                }
            },
            _ => {
                ui.horizontal_wrapped(|ui| {
                    for (name, k) in [
                        ("All", EventKindFilter::All),
                        ("Programs", EventKindFilter::Exec),
                        ("Files", EventKindFilter::File),
                        ("Network", EventKindFilter::Network),
                        ("Other", EventKindFilter::Other),
                    ] {
                        let n = recent
                            .iter()
                            .filter(|e| k == EventKindFilter::All || kind_of(e) == k)
                            .count();
                        if widgets::chip(ui, name, Some(n), m.event_kinds == k).clicked() {
                            acts.push(Action::EventKinds(k));
                        }
                    }
                });
                let shown: Vec<&Event> = recent
                    .iter()
                    .rev()
                    .filter(|e| {
                        m.event_kinds == EventKindFilter::All || kind_of(e) == m.event_kinds
                    })
                    .collect();
                for e in shown.iter().take(1000) {
                    line(
                        ui,
                        format!(
                            "event #{:<7} pid {:<7} {}",
                            e.id,
                            e.proc.tgid,
                            m.shown(&safe_str(&candor_core::explain::describe(e)))
                        ),
                    );
                }
                if shown.is_empty() {
                    ui.label(theme::dim(
                        "No events of this kind are kept for this process.",
                    ));
                }
            }
        }
    });
}

// ----- Findings page (8) ----------------------------------------------------

fn findings_page(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    ui.label(theme::title("Findings"));
    let mut rules: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in &m.alerts {
        *rules.entry(safe_str(&f.rule)).or_insert(0) += 1;
    }
    ui.horizontal_wrapped(|ui| {
        if widgets::chip(ui, "All", Some(m.alerts.len()), m.findings_rule.is_none()).clicked() {
            acts.push(Action::FindingsRule(None));
        }
        for (rule, n) in &rules {
            let on = m.findings_rule.as_deref() == Some(rule.as_str());
            if widgets::chip(ui, rule, Some(*n), on).clicked() {
                acts.push(Action::FindingsRule(Some(rule.clone())));
            }
        }
    });
    let shown = m.findings_shown();
    if shown.is_empty() {
        widgets::card(ui, |ui| {
            ui.label(theme::section("Nothing flagged so far."));
            ui.label(theme::dim(
                "Findings appear here when a program does something worth a second look, such as reading an SSH key or running from a temp folder.",
            ));
        });
        return;
    }
    let wall = match &m.conn {
        ConnState::Connected {
            boot_to_wall_ns, ..
        } => *boot_to_wall_ns,
        _ => 0,
    };
    for f in shown {
        let idx = m
            .alerts
            .iter()
            .position(|x| std::ptr::eq(x, f))
            .unwrap_or(0);
        ui.horizontal(|ui| {
            let who = m.shown(&safe(&f.exe));
            let short = who.rsplit('/').next().unwrap_or(&who).to_string();
            let label = format!(
                "{} {} - {} (pid {}): {}",
                safe_str(&f.rule),
                safe_str(&f.title),
                who,
                f.proc.tgid,
                safe_str(&f.summary)
            );
            let r = ui.add(egui::Button::new(theme::name(short).color(color::ACCENT)).frame(false));
            r.widget_info(|| egui::WidgetInfo::labeled(Role::Link, true, label.clone()));
            if r.clicked() {
                acts.push(Action::ClickAlert(idx));
            }
            ui.label(theme::mono_dim(format!("pid {}", f.proc.tgid)));
            if wall > 0 {
                let secs = (wall.saturating_add(f.ts_ns) / 1_000_000_000) % 86_400;
                ui.label(theme::mono_dim(format!(
                    "{:02}:{:02}:{:02} UTC",
                    secs / 3600,
                    secs / 60 % 60,
                    secs % 60
                )));
            }
        });
        finding_card(ui, m, f, true, acts);
    }
}
