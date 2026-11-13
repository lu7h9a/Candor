//! The Glasshouse page (WP24): the plan 6.4 text (always visible), program
//! picker, arguments, timeout, run/cancel, a live decoy grid, the final
//! report with a before/after table, the timeline and export.
//!
//! Labels for tests: `gh-path`, `gh-browse`, `gh-args`,
//! `gh-timeout`, `gh-run`, `gh-cancel`, `gh-status`, `gh-decoys`,
//! `gh-report`, `gh-timeline`, `gh-export`. Every state is shown as a word
//! as well as a colour. Everything from the sandbox is escaped (I10).

use crate::model::{Action, ConnState, GhView, Model};
use egui::{Color32, Response, RichText, Role, Ui, WidgetInfo};
use sysscope_core::display::{safe, safe_str};
use sysscope_core::ghreport::{LIMITATION, counts, entropy_sentence, states_text};
use sysscope_proto::{DecoyState, DecoyStatus, GhState};

/// Timeline lines shown (the export has them all).
const TIMELINE_SHOWN: usize = 500;

fn tag(r: &Response, role: Role, name: &'static str) {
    r.widget_info(|| WidgetInfo::labeled(role, true, name));
}

fn state_color(d: &DecoyStatus) -> Color32 {
    let has = |s| d.states.contains(&s);
    if has(DecoyState::Deleted) {
        Color32::from_rgb(0x8a, 0x1c, 0x1c)
    } else if has(DecoyState::Modified) || has(DecoyState::Renamed) {
        Color32::from_rgb(0xa0, 0x40, 0x10)
    } else if has(DecoyState::Read) {
        Color32::from_rgb(0x8a, 0x6a, 0x10)
    } else if d.states.is_empty() {
        Color32::from_rgb(0x50, 0x50, 0x50)
    } else {
        Color32::from_rgb(0x2a, 0x4a, 0x2a)
    }
}

fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Draws the page; returns this frame's actions.
pub fn page(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let g = &m.gh;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.heading("Glasshouse");
            ui.label("Runs a program in a sandbox full of decoy files and reports what it touched.");
            egui::Frame::new()
                .fill(Color32::from_rgb(0x4a, 0x36, 0x10))
                .inner_margin(8.0)
                .show(ui, |ui| {
                    // Untagged on purpose: the text itself is the accessible
                    // label, so tests find the plan 6.4 wording verbatim.
                    ui.label(RichText::new(LIMITATION).strong().color(Color32::WHITE));
                });
            ui.add_space(6.0);
            let live = matches!(m.conn, ConnState::Connected { .. });
            if !g.offered {
                ui.label(RichText::new(if live {
                    "Glasshouse is not available on this system: the daemon does not offer it (run `sysscope-glasshouse availability` to see why)."
                } else {
                    "Glasshouse needs a running daemon."
                }).italics());
            }
            controls(ui, g, live, acts);
            if let Some(b) = &g.browse {
                picker(ui, b, acts);
            }
            if !g.decoys.is_empty() {
                ui.separator();
                decoy_grid(ui, g);
            }
            if g.report.is_some() {
                ui.separator();
                report(ui, g, acts);
            }
        });
}

fn controls(ui: &mut Ui, g: &GhView, live: bool, acts: &mut Vec<Action>) {
    egui::Grid::new("gh-form").num_columns(2).show(ui, |ui| {
        ui.label("Program file");
        ui.horizontal(|ui| {
            let mut p = g.path.clone();
            let r = ui.add(
                egui::TextEdit::singleline(&mut p)
                    .hint_text("/path/to/your/test-script")
                    .desired_width(420.0),
            );
            tag(&r, Role::TextInput, "gh-path");
            if p != g.path {
                acts.push(Action::GhSetPath(p));
            }
            let r = ui.button("Browse...");
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
        ui.end_row();
        ui.label("Arguments");
        let mut a = g.args.clone();
        let r = ui.add(
            egui::TextEdit::singleline(&mut a)
                .hint_text("separated by spaces")
                .desired_width(420.0),
        );
        tag(&r, Role::TextInput, "gh-args");
        if a != g.args {
            acts.push(Action::GhSetArgs(a));
        }
        ui.end_row();
        ui.label("Timeout (seconds)");
        let mut t = g.timeout_s;
        let r = ui.add(egui::DragValue::new(&mut t).range(1..=600));
        tag(&r, Role::SpinButton, "gh-timeout");
        if t != g.timeout_s {
            acts.push(Action::GhSetTimeout(t));
        }
        ui.end_row();
    });
    ui.horizontal(|ui| {
        let can_run = live && g.offered && !g.running() && !g.path.trim().is_empty();
        let r = ui.add_enabled(can_run, egui::Button::new("Run in Glasshouse"));
        tag(&r, Role::Button, "gh-run");
        if r.clicked() {
            acts.push(Action::GhRun);
        }
        let r = ui.add_enabled(g.running(), egui::Button::new("Cancel"));
        tag(&r, Role::Button, "gh-cancel");
        if r.clicked() {
            acts.push(Action::GhCancel);
        }
        let state = match g.state {
            None => "no run yet",
            Some(GhState::Uploading) => "uploading",
            Some(GhState::Starting) => "starting",
            Some(GhState::Running) => "running",
            Some(GhState::Finished) => "finished",
            Some(GhState::Failed) => "failed",
        };
        let text = if g.run_id.is_empty() {
            state.to_string()
        } else {
            format!("run {}: {state}. {}", g.run_id, g.message)
        };
        let color = if g.state == Some(GhState::Failed) {
            Color32::from_rgb(0xe0, 0x50, 0x40)
        } else {
            ui.visuals().text_color()
        };
        let r = ui.label(RichText::new(text).color(color));
        tag(&r, Role::Label, "gh-status");
    });
}

fn picker(ui: &mut Ui, b: &crate::model::Browse, acts: &mut Vec<Action>) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(safe_str(&b.dir.display().to_string())).strong());
            if let Some(parent) = b.dir.parent()
                && ui.button("Up").clicked()
            {
                acts.push(Action::GhBrowse(parent.to_path_buf()));
            }
            if ui.button("Close").clicked() {
                acts.push(Action::GhCloseBrowse);
            }
        });
        if let Some(n) = &b.note {
            ui.label(RichText::new(n).italics());
        }
        egui::ScrollArea::vertical()
            .id_salt("gh-picker")
            .max_height(220.0)
            .show(ui, |ui| {
                for (name, is_dir) in &b.entries {
                    let shown = if *is_dir {
                        format!("{name}/")
                    } else {
                        name.clone()
                    };
                    if ui.selectable_label(false, shown).clicked() {
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

fn decoy_grid(ui: &mut Ui, g: &GhView) {
    let touched = g
        .decoys
        .iter()
        .filter(|d| d.states != vec![DecoyState::Untouched])
        .count();
    let r = ui.label(
        RichText::new(format!(
            "Decoys: {touched} of {} touched{}",
            g.decoys.len(),
            if g.running() {
                " (live, from the trace)"
            } else {
                ""
            }
        ))
        .strong(),
    );
    tag(&r, Role::Label, "gh-decoys");
    egui::Grid::new("gh-tiles")
        .spacing([6.0, 6.0])
        .show(ui, |ui| {
            for (i, d) in g.decoys.iter().enumerate() {
                let path = safe(&d.path);
                egui::Frame::new()
                    .fill(state_color(d))
                    .inner_margin(4.0)
                    .show(ui, |ui| {
                        ui.set_width(150.0);
                        ui.label(RichText::new(leaf(&path)).color(Color32::WHITE).small())
                            .on_hover_text(path.clone());
                        ui.label(
                            RichText::new(states_text(d))
                                .color(Color32::WHITE)
                                .strong()
                                .small(),
                        );
                    });
                if i % 7 == 6 {
                    ui.end_row();
                }
            }
        });
}

fn report(ui: &mut Ui, g: &GhView, acts: &mut Vec<Action>) {
    let Some(r) = g.report.as_deref() else { return };
    let c = counts(r);
    let end = if r.timed_out {
        format!("killed at the {} s timeout", r.timeout_s)
    } else {
        match r.exit_code {
            Some(code) => format!("exited with code {code}"),
            None => "ended by a signal or was cancelled".into(),
        }
    };
    let h = ui.heading(format!("Report: {} ({end})", safe(&r.sample)));
    tag(&h, Role::Label, "gh-report");
    ui.label(format!(
        "{} decoys read, {} modified, {} renamed, {} deleted; {} new file(s); {} connection attempt(s); {} finding(s)",
        c.read,
        c.modified,
        c.renamed,
        c.deleted,
        c.created,
        c.connects,
        r.findings.len()
    ));
    ui.label(RichText::new("Before / after").strong());
    egui::Grid::new("gh-before-after")
        .striped(true)
        .num_columns(4)
        .show(ui, |ui| {
            ui.label(RichText::new("Decoy").strong());
            ui.label(RichText::new("What happened").strong());
            ui.label(RichText::new("Size before -> after").strong());
            ui.label(RichText::new("Entropy before -> after (bits/byte)").strong());
            ui.end_row();
            for d in r
                .decoys
                .iter()
                .filter(|d| d.states != vec![DecoyState::Untouched])
            {
                let name = match &d.new_path {
                    Some(n) => format!("{} -> {}", safe(&d.path), leaf(&safe(n))),
                    None => safe(&d.path),
                };
                ui.label(name);
                ui.label(states_text(d));
                ui.label(match d.size_after {
                    Some(a) => format!("{} -> {}", d.size_before, a),
                    None => format!("{} -> gone", d.size_before),
                });
                let e = match d.entropy_after {
                    Some(a) => {
                        let s = format!("{:.1} -> {:.1}", d.entropy_before, a);
                        match entropy_sentence(d.entropy_before, a) {
                            Some(_) => format!("{s}  (consistent with encryption or compression)"),
                            None => s,
                        }
                    }
                    None => format!("{:.1} -> -", d.entropy_before),
                };
                ui.label(e);
                ui.end_row();
            }
        });
    if !r.created.is_empty() {
        ui.label(RichText::new("New files").strong());
        for f in &r.created {
            ui.label(format!(
                "{} ({}, {} bytes, entropy {:.1})",
                safe(&f.path),
                safe_str(&f.kind),
                f.size,
                f.entropy
            ));
            if let Some(p) = &f.preview {
                ui.label(RichText::new(safe(p)).monospace().small());
            }
        }
    }
    ui.label(RichText::new("Connection attempts").strong());
    if r.connections.is_empty() {
        ui.label("none");
    }
    for cn in &r.connections {
        ui.label(format!(
            "{}:{} x{} (the box has no network: observed, not delivered)",
            safe_str(&cn.addr),
            cn.port,
            cn.count
        ));
    }
    ui.label(RichText::new("Findings").strong());
    if r.findings.is_empty() {
        ui.label("none");
    }
    for f in &r.findings {
        ui.label(format!(
            "{} {} - {}",
            safe_str(&f.rule),
            safe_str(&f.title),
            safe_str(&f.summary)
        ));
    }
    let l = &r.loss;
    ui.label(format!(
        "Lost events during the run: ring buffer {}, budget {}, scratch {}, undecodable {}",
        l.ringbuf, l.budget, l.scratch, l.decode
    ));
    for n in &r.notes {
        ui.label(RichText::new(format!("Note: {}", safe_str(n))).italics());
    }
    let t = egui::CollapsingHeader::new(format!("Timeline ({} events)", r.timeline.len()))
        .id_salt("gh-timeline")
        .show(ui, |ui| {
            for e in r.timeline.iter().take(TIMELINE_SHOWN) {
                ui.label(
                    RichText::new(format!(
                        "#{} pid {} {}",
                        e.id,
                        e.proc.tgid,
                        safe_str(&sysscope_core::explain::describe(e))
                    ))
                    .monospace()
                    .small(),
                );
            }
            if r.timeline.len() > TIMELINE_SHOWN {
                ui.label(format!(
                    "... {} more in the exported report",
                    r.timeline.len() - TIMELINE_SHOWN
                ));
            }
        });
    tag(&t.header_response, Role::Button, "gh-timeline");
    let b = ui.button("Export report");
    tag(&b, Role::Button, "gh-export");
    if b.clicked() {
        acts.push(Action::GhExport);
    }
    ui.label(RichText::new(LIMITATION).small().italics());
}
