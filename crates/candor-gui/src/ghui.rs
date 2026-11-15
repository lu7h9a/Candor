//! The Glasshouse page (spec section 7): one page in three states (start,
//! running, report), plus the unavailable state. The limitation stays
//! visible in every state and cannot be dismissed (I13).
//!
//! Labels for tests: `gh-path`, `gh-browse`, `gh-args`, `gh-timeout`,
//! `gh-example`, `gh-run`, `gh-cancel`, `gh-status`, `gh-decoys`,
//! `gh-report`, `gh-timeline`, `gh-export`, `gh-run-again`, `gh-map`.
//! Everything from the sandbox is escaped (I10).

use crate::model::{Action, ConnState, GH_TIMEOUTS, GhStage, GhView, Model};
use crate::theme::{self, color, space};
use crate::widgets::{self, Severity, tag};
use candor_core::display::{safe, safe_str};
use candor_core::ghreport::{
    LIMITATION, changed_count, counts, is_secret, states_text, summary_sentence,
};
use candor_proto::{DecoyState, GhReport, GhState};
use egui::{Role, Ui};

/// Timeline lines shown (the export has them all).
const TIMELINE_SHOWN: usize = 500;

/// The short caution from the spec; the full limitation follows it.
const CAUTION: &str = "Glasshouse shows behaviour. It does not contain malware. The program shares this computer's kernel, so only run things you would accept losing this machine to. For real samples, use a separate virtual machine.";

/// Draws the page; returns this frame's actions.
pub fn page(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let g = &m.gh;
    let stage = g.stage();
    if stage == GhStage::Report && m.gh_map {
        ui.horizontal(|ui| {
            if widgets::text_button(ui, "Back to the report").clicked() {
                acts.push(Action::GhMap(false));
            }
        });
        ui.label(theme::title("What the program touched"));
        crate::mapview::show(ui, m, acts);
        return;
    }
    match stage {
        GhStage::Report => report(ui, m, acts),
        GhStage::Running => running(ui, g, acts),
        GhStage::Start => start(ui, m, acts),
    }
}

fn caution_card(ui: &mut Ui) {
    widgets::card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = space::S;
        widgets::caution_line(ui, CAUTION);
        // The full statement (plan 6.4), verbatim: the accessible label too.
        ui.add(egui::Label::new(theme::dim(LIMITATION)).wrap());
    });
}

fn start(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let g = &m.gh;
    ui.label(theme::title("Glasshouse"));
    ui.label(theme::body(
        "Run a program in a room full of fake files and see exactly what it touches.",
    ));
    // Three numbered steps.
    let steps = [
        (
            "1",
            "Choose a program",
            "A script or binary on this computer.",
        ),
        (
            "2",
            "Candor runs it",
            "With a fake home folder and no network.",
        ),
        (
            "3",
            "Read the report",
            "What it read, changed, deleted and tried to reach.",
        ),
    ];
    let cols = if ui.available_width() < space::NARROW {
        1
    } else {
        3
    };
    ui.columns(cols, |c| {
        for (i, (n, title, text)) in steps.iter().enumerate() {
            if let Some(col) = c.get_mut(i % cols) {
                widgets::card(col, |ui| {
                    ui.spacing_mut().item_spacing.y = space::LABEL_GAP;
                    ui.label(theme::mono_dim(*n));
                    ui.label(theme::name(*title));
                    ui.label(theme::dim(*text));
                });
            }
        }
    });
    let live = matches!(m.conn, ConnState::Connected { .. });
    let available = live && g.offered;
    if !available {
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::status_dot(ui, Severity::Caution);
                ui.label(theme::section("Glasshouse cannot run here"));
            });
            let why = if !live {
                "Glasshouse needs a running daemon. Start it with: sudo systemctl enable --now candord"
                    .to_string()
            } else {
                m.gh_unavailable.clone().unwrap_or_else(|| {
                    "the daemon does not offer it (run `candor-glasshouse availability` to see why)."
                        .into()
                })
            };
            let r = ui.add(egui::Label::new(theme::body(why.clone())).wrap());
            // Read out with the reason itself (the test looks for it too).
            r.widget_info(|| {
                egui::WidgetInfo::labeled(Role::Label, true, format!("gh-unavailable: {why}"))
            });
            ui.label(theme::dim(
                "Candor does not change system settings to make it work.",
            ));
        });
    }
    // The form.
    widgets::card(ui, |ui| {
        ui.add_enabled_ui(available, |ui| form(ui, g, acts));
        ui.add_space(space::S);
        let can_run = available && !g.running() && !g.path.trim().is_empty();
        ui.horizontal(|ui| {
            let r = widgets::primary(ui, "Run in Glasshouse", can_run);
            tag(&r, Role::Button, "gh-run");
            if r.clicked() {
                acts.push(Action::GhRun);
            }
            let r = widgets::text_button(ui, "Try an example");
            tag(&r, Role::Button, "gh-example");
            if r.clicked() {
                acts.push(Action::GhExample);
            }
        });
        if g.state == Some(GhState::Failed) {
            let r = ui.label(
                theme::body(format!("The last run failed: {}", g.message)).color(color::CAUTION),
            );
            tag(&r, Role::Label, "gh-status");
        } else {
            let r = ui.label(theme::dim(if g.path.trim().is_empty() {
                "Choose a program to enable Run."
            } else if !available {
                "Running is not possible on this system."
            } else {
                "Ready."
            }));
            tag(&r, Role::Label, "gh-status");
        }
    });
    if let Some(b) = &g.browse {
        picker(ui, b, acts);
    }
    caution_card(ui);
    // Earlier runs.
    ui.label(theme::section("Earlier runs"));
    if g.history.is_empty() {
        ui.label(theme::dim(
            "Runs from this window appear here. Saved reports stay in /var/lib/candor/reports.",
        ));
    }
    for (i, h) in g.history.iter().enumerate() {
        let c = counts(&h.report);
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(theme::name(h.name.clone()).color(color::ACCENT))
                            .frame(false),
                    )
                    .clicked()
                {
                    acts.push(Action::GhOpenRun(i));
                }
                ui.label(theme::mono_dim(safe_str(&h.report.run_id)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(theme::dim(format!(
                        "{} read · {} changed · {} deleted · {} connections",
                        c.read,
                        changed_count(&h.report),
                        c.deleted,
                        c.connects
                    )));
                });
            });
        });
    }
}

fn form(ui: &mut Ui, g: &GhView, acts: &mut Vec<Action>) {
    ui.spacing_mut().item_spacing.y = space::S;
    ui.label(theme::label("Program to run"));
    ui.horizontal(|ui| {
        let mut p = g.path.clone();
        let r = ui.add(
            egui::TextEdit::singleline(&mut p)
                .hint_text(theme::dim(
                    "/path/to/a/script, or drop a file on the window",
                ))
                .desired_width(space::FIELD_W)
                .min_size(egui::vec2(0.0, space::CONTROL)),
        );
        tag(&r, Role::TextInput, "gh-path");
        if p != g.path {
            acts.push(Action::GhSetPath(p));
        }
        let r = widgets::secondary(ui, "Browse", true);
        tag(&r, Role::Button, "gh-browse");
        if r.clicked() {
            let start = std::path::Path::new(&g.path)
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .map(|d| d.to_path_buf())
                .unwrap_or_else(|| std::env::var("HOME").unwrap_or_else(|_| "/".into()).into());
            acts.push(Action::GhBrowse(start));
        }
    });
    if g.example {
        ui.label(theme::dim(
            "The example reads the decoy SSH key and writes a note in Documents: cat ~/.ssh/id_ed25519; echo hi > ~/Documents/note.txt",
        ));
    }
    ui.label(theme::label("Arguments (optional)"));
    let mut a = g.args.clone();
    let r = ui.add(
        egui::TextEdit::singleline(&mut a)
            .hint_text(theme::dim("separated by spaces"))
            .desired_width(space::FIELD_W)
            .min_size(egui::vec2(0.0, space::CONTROL)),
    );
    tag(&r, Role::TextInput, "gh-args");
    if a != g.args {
        acts.push(Action::GhSetArgs(a));
    }
    ui.label(theme::label("Stop after"));
    let ids: [&'static str; 3] = ["gh-timeout", "gh-timeout-120", "gh-timeout-600"];
    let names = ["30 seconds", "2 minutes", "10 minutes"];
    let items: Vec<(&str, bool, &'static str)> = GH_TIMEOUTS
        .iter()
        .zip(names)
        .zip(ids)
        .map(|((t, n), id)| (n, g.timeout_s == *t, id))
        .collect();
    if let Some(i) = widgets::segmented(ui, &items)
        && let Some(t) = GH_TIMEOUTS.get(i)
    {
        acts.push(Action::GhSetStop(*t));
    }
    ui.label(theme::label("Decoys placed in the fake home"));
    ui.horizontal(|ui| {
        for d in ["SSH keys", "Documents", "Photos"] {
            widgets::chip(ui, d, None, true)
                .on_hover_text("Glasshouse always places its full set of decoys.");
        }
    });
}

fn picker(ui: &mut Ui, b: &crate::model::Browse, acts: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(theme::mono(safe_str(&b.dir.display().to_string())).color(color::TEXT_STRONG));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::secondary(ui, "Close", true).clicked() {
                    acts.push(Action::GhCloseBrowse);
                }
                if let Some(parent) = b.dir.parent()
                    && widgets::secondary(ui, "Up", true).clicked()
                {
                    acts.push(Action::GhBrowse(parent.to_path_buf()));
                }
            });
        });
        if let Some(n) = &b.note {
            ui.label(theme::dim(n.clone()));
        }
        egui::ScrollArea::vertical()
            .id_salt("gh-picker")
            .max_height(space::PICKER_H)
            .show(ui, |ui| {
                for (name, is_dir) in &b.entries {
                    let shown = if *is_dir {
                        format!("{name}/")
                    } else {
                        name.clone()
                    };
                    let t = if *is_dir {
                        theme::mono(shown).color(color::TEXT_DIM)
                    } else {
                        theme::mono(shown)
                    };
                    if ui.add(egui::Button::new(t).frame(false)).clicked() {
                        let p = b.dir.join(name);
                        if *is_dir {
                            acts.push(Action::GhBrowse(p));
                        } else {
                            acts.push(Action::GhPick(p.display().to_string()));
                        }
                    }
                }
            });
    });
}

fn running(ui: &mut Ui, g: &GhView, acts: &mut Vec<Action>) {
    let name = if g.example {
        crate::model::GH_EXAMPLE_NAME.to_string()
    } else {
        g.path.rsplit('/').next().unwrap_or(&g.path).to_string()
    };
    ui.horizontal(|ui| {
        ui.label(theme::title(format!("Running {}", safe_str(&name))));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let r = widgets::secondary(ui, "Stop", true);
            tag(&r, Role::Button, "gh-cancel");
            if r.clicked() {
                acts.push(Action::GhCancel);
            }
        });
    });
    let state = match g.state {
        Some(GhState::Uploading) => "Sending the program to the daemon",
        Some(GhState::Starting) => "Preparing the fake home",
        _ => "Running",
    };
    let elapsed = g
        .run_started
        .map(|t| format!(" · {:.0} s", t.elapsed().as_secs_f32()))
        .unwrap_or_default();
    let r = ui.label(theme::dim(format!("{state}{elapsed}. {}", g.message)));
    tag(&r, Role::Label, "gh-status");
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(500));
    let has = |s| g.decoys.iter().filter(|d| d.states.contains(&s)).count();
    let counts = [
        ("Read", has(DecoyState::Read)),
        (
            "Changed",
            has(DecoyState::Modified) + has(DecoyState::Renamed),
        ),
        ("Deleted", has(DecoyState::Deleted)),
    ];
    let cols = if ui.available_width() < space::NARROW {
        1
    } else {
        4
    };
    ui.columns(cols, |c| {
        for (i, (label, n)) in counts.iter().enumerate() {
            if let Some(col) = c.get_mut(i % cols) {
                widgets::card_compact(col, |ui| {
                    ui.label(theme::dim(*label));
                    ui.label(theme::stat(n.to_string()));
                });
            }
        }
        if let Some(col) = c.get_mut(3 % cols) {
            widgets::card_compact(col, |ui| {
                ui.label(theme::dim("Connection attempts"));
                ui.label(theme::stat("-").color(color::TEXT_DIM));
                ui.label(theme::label("counted in the report"));
            });
        }
    });
    let touched: Vec<_> = g
        .decoys
        .iter()
        .filter(|d| d.states != vec![DecoyState::Untouched])
        .collect();
    let r = ui.label(theme::section(format!(
        "Decoys touched so far: {} of {}",
        touched.len(),
        g.decoys.len()
    )));
    tag(&r, Role::Label, "gh-decoys");
    widgets::card(ui, |ui| {
        if touched.is_empty() {
            ui.label(theme::dim(
                "Nothing touched yet. Touched decoys appear here as it runs.",
            ));
        }
        for d in touched.iter().rev().take(8) {
            ui.horizontal(|ui| {
                ui.label(theme::mono(safe(&d.path)));
                ui.label(theme::label(states_text(d)));
            });
        }
    });
    caution_card(ui);
}

fn report(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let g = &m.gh;
    let Some(r) = g.shown_report() else { return };
    let c = counts(r);
    let secs = r.ended_ts.saturating_sub(r.started_ts) as f64 / 1e9;
    let end = if r.timed_out {
        format!("stopped at the {} s limit", r.timeout_s)
    } else {
        match r.exit_code {
            Some(code) => format!("exit {code}"),
            None => "ended by a signal or was stopped".into(),
        }
    };
    ui.horizontal(|ui| {
        if ui
            .add(egui::Button::new(theme::body("Glasshouse").color(color::ACCENT)).frame(false))
            .clicked()
        {
            acts.push(Action::Back);
        }
        ui.label(theme::dim("/"));
        let h = ui.label(theme::title(safe(&r.sample)));
        tag(&h, Role::Label, "gh-report");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let b = widgets::primary(ui, "Run again", true);
            tag(&b, Role::Button, "gh-run-again");
            if b.clicked() {
                acts.push(Action::GhRunAgain);
            }
            let b = widgets::secondary(ui, "Export", true);
            tag(&b, Role::Button, "gh-export");
            if b.clicked() {
                acts.push(Action::GhExport);
            }
            let b = widgets::secondary(ui, "Open map", !r.timeline.is_empty());
            tag(&b, Role::Button, "gh-map");
            if b.clicked() {
                acts.push(Action::GhMap(true));
            }
        });
    });
    let r2 = ui.label(theme::mono_dim(format!(
        "ran {secs:.1} s · {end} · run {}",
        safe_str(&r.run_id)
    )));
    tag(&r2, Role::Label, "gh-status");
    caution_card(ui);
    ui.add(egui::Label::new(theme::section(summary_sentence(r))).wrap());
    // The report's own counts, in the words the CLI and export use.
    ui.label(theme::dim(format!(
        "{} decoys read, {} modified, {} renamed, {} deleted; {} new file(s); {} connection attempt(s); {} finding(s)",
        c.read,
        c.modified,
        c.renamed,
        c.deleted,
        c.created,
        c.connects,
        r.findings.len()
    )));
    // Four count cards.
    let read_secret = r
        .decoys
        .iter()
        .any(|d| d.states.contains(&DecoyState::Read) && is_secret(&safe(&d.path)));
    let changed_secret = r.decoys.iter().any(|d| {
        (d.states.contains(&DecoyState::Modified) || d.states.contains(&DecoyState::Renamed))
            && is_secret(&safe(&d.path))
    });
    let deleted_secret = r
        .decoys
        .iter()
        .any(|d| d.states.contains(&DecoyState::Deleted) && is_secret(&safe(&d.path)));
    let cards = [
        ("Read", c.read as u64, read_secret),
        (
            "Changed",
            (c.modified + c.renamed + c.created) as u64,
            changed_secret,
        ),
        ("Deleted", c.deleted as u64, deleted_secret),
        ("Connection attempts", c.connects, false),
    ];
    let cols = if ui.available_width() < space::NARROW {
        2
    } else {
        4
    };
    ui.columns(cols, |cc| {
        for (i, (label, n, secret)) in cards.iter().enumerate() {
            if let Some(col) = cc.get_mut(i % cols) {
                widgets::card_compact(col, |ui| {
                    ui.label(theme::dim(*label));
                    let colr = if *secret {
                        color::ALERT
                    } else if *n > 0 {
                        color::TEXT_STRONG
                    } else {
                        color::TEXT_DIM
                    };
                    ui.label(theme::stat(n.to_string()).color(colr));
                    if *secret {
                        ui.label(theme::label("includes a decoy secret").color(color::ALERT));
                    }
                });
            }
        }
    });
    before_after(ui, r);
    if !r.connections.is_empty() {
        ui.label(theme::section("Connection attempts"));
        widgets::card(ui, |ui| {
            for cn in &r.connections {
                ui.horizontal(|ui| {
                    ui.label(theme::mono(format!("{}:{}", safe_str(&cn.addr), cn.port)));
                    ui.label(theme::label(format!("x{}", cn.count)));
                });
            }
            ui.label(theme::dim(
                "The sandbox has no network: these were observed, not delivered.",
            ));
        });
    }
    ui.label(theme::section(if r.findings.is_empty() {
        "No findings during the run".to_string()
    } else {
        format!("Findings during the run ({})", r.findings.len())
    }));
    for f in &r.findings {
        crate::ui::finding_card(ui, m, f, false, acts);
    }
    let l = &r.loss;
    let lost = l.ringbuf + l.budget + l.scratch + l.decode + l.untracked + l.missed;
    let r3 = ui.label(
        theme::body(format!(
            "Events not recorded during the run: {lost} (ring buffer {}, budget {}, scratch {}, undecodable {}, untracked {}, skipped by the kernel {})",
            l.ringbuf, l.budget, l.scratch, l.decode, l.untracked, l.missed
        ))
        .color(if lost > 0 { color::CAUTION } else { color::TEXT_DIM }),
    );
    tag(&r3, Role::Label, "gh-loss");
    for n in &r.notes {
        ui.label(theme::dim(format!("Note: {}", safe_str(n))));
    }
    let t = egui::CollapsingHeader::new(theme::section(format!(
        "Timeline ({} events)",
        r.timeline.len()
    )))
    .id_salt("gh-timeline")
    .show(ui, |ui| {
        for e in r.timeline.iter().take(TIMELINE_SHOWN) {
            ui.label(theme::mono(format!(
                "#{} pid {} {}",
                e.id,
                e.proc.tgid,
                safe_str(&candor_core::explain::describe(e))
            )));
        }
        if r.timeline.len() > TIMELINE_SHOWN {
            ui.label(theme::dim(format!(
                "... {} more in the exported report",
                r.timeline.len() - TIMELINE_SHOWN
            )));
        }
    });
    tag(&t.header_response, Role::Button, "gh-timeline");
    ui.label(theme::dim(
        "The program could tell it was in a sandbox and may behave differently outside it.",
    ));
    caution_card(ui);
}

/// Before / After: the fake home on the left; on the right the same files
/// marked read, changed, deleted or new. Unchanged files collapse.
fn before_after(ui: &mut Ui, r: &GhReport) {
    let label = ui.label(theme::section("Before / After"));
    tag(&label, Role::Label, "gh-decoys");
    widgets::card(ui, |ui| {
        let touched: Vec<_> = r
            .decoys
            .iter()
            .filter(|d| d.states != vec![DecoyState::Untouched])
            .collect();
        let unchanged = r.decoys.len() - touched.len();
        egui::Grid::new("gh-before-after")
            .num_columns(2)
            .spacing([space::XXL, space::S])
            .show(ui, |ui| {
                ui.label(theme::label("Before"));
                ui.label(theme::label("After"));
                ui.end_row();
                for d in &touched {
                    ui.label(theme::mono(safe(&d.path)));
                    let after = match (&d.new_path, d.states.contains(&DecoyState::Deleted)) {
                        (_, true) => "(gone)".to_string(),
                        (Some(n), _) => safe(n),
                        (None, _) => safe(&d.path),
                    };
                    ui.horizontal(|ui| {
                        ui.label(theme::mono(after).color(color::TEXT_STRONG));
                        // Red only for a decoy secret; amber only for the
                        // encryption warning; the rest is plain words.
                        let secret = is_secret(&safe(&d.path));
                        let c = if secret {
                            color::ALERT
                        } else {
                            color::TEXT_DIM
                        };
                        let mut marks = states_text(d);
                        if let (Some(a), b) = (d.size_after, d.size_before)
                            && a != b
                        {
                            marks.push_str(&format!(" · {b} -> {a} bytes"));
                        }
                        ui.label(theme::label(marks).color(c));
                        if let (Some(a), b) = (d.entropy_after, d.entropy_before)
                            && candor_core::ghreport::entropy_sentence(b, a).is_some()
                        {
                            ui.label(
                                theme::label("now looks encrypted or compressed")
                                    .color(color::CAUTION),
                            );
                        }
                    });
                    ui.end_row();
                }
                for f in &r.created {
                    ui.label(theme::mono_dim(""));
                    ui.horizontal(|ui| {
                        ui.label(theme::mono(safe(&f.path)).color(color::TEXT_STRONG));
                        ui.label(
                            theme::label(format!("new · {} · {} bytes", safe_str(&f.kind), f.size))
                                .color(color::TEXT_DIM),
                        );
                    });
                    ui.end_row();
                }
            });
        if unchanged > 0 {
            egui::CollapsingHeader::new(theme::dim(format!("{unchanged} unchanged")))
                .id_salt("gh-unchanged")
                .show(ui, |ui| {
                    for d in r
                        .decoys
                        .iter()
                        .filter(|d| d.states == vec![DecoyState::Untouched])
                    {
                        ui.label(theme::mono(safe(&d.path)));
                    }
                });
        }
    });
}
