//! Draws the access map (spec 6) from `model.map`, and turns pointer and
//! keyboard input into `MapAction`s. The layout itself runs in
//! `Model::map_tick`, a bounded number of steps per frame, so drawing never
//! waits for it.

use crate::map::{Kind, LABEL_ZOOM, MapAction, Node, NodeId, P};
use crate::model::{Action, Model, Tab};
use crate::theme::{self, color, space};
use crate::widgets::{self, Severity, tag};
use egui::{Align2, Color32, Key, Pos2, Rect, Role, Sense, Stroke, Ui, vec2};

/// Zoom change per scroll pixel (interaction, not style).
const ZOOM_PER_SCROLL: f32 = 0.0015;

fn radius(n: &Node) -> f32 {
    (space::NODE_R_MIN + space::NODE_R_GROWTH * ((1 + n.count) as f32).ln()).min(space::NODE_R_MAX)
}

fn act(a: MapAction) -> Action {
    Action::Map(a)
}

/// The map card: controls, canvas with side panel, time window, legend.
pub fn show(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let mp = &m.map;
    let g = &mp.graph;
    // Controls.
    ui.horizontal_wrapped(|ui| {
        for (name, k) in [
            ("Files", Kind::File),
            ("Processes", Kind::Process),
            ("Network", Kind::Network),
        ] {
            let on = mp.opts.kinds.contains(&k);
            if widgets::chip(ui, name, Some(g.count(k)), on).clicked() {
                acts.push(act(MapAction::ToggleKind(k)));
            }
        }
        let flagged = g.nodes.iter().filter(|n| n.flagged).count();
        if widgets::chip(ui, "Flagged only", Some(flagged), mp.opts.flagged_only).clicked() {
            acts.push(act(MapAction::FlaggedOnly));
        }
        if widgets::chip(ui, "Hide common system files", None, mp.opts.hide_system).clicked() {
            acts.push(act(MapAction::HideSystem));
        }
        let mut q = mp.search.clone();
        let r = ui.add(
            egui::TextEdit::singleline(&mut q)
                .hint_text(theme::dim("Find in map"))
                .desired_width(space::SEARCH_W),
        );
        tag(&r, Role::TextInput, "map-search");
        if q != mp.search {
            acts.push(act(MapAction::Search(q)));
        }
    });
    let real = g.nodes.iter().filter(|n| n.kind != Kind::Process).count();
    if real == 0 && g.nodes.len() <= 3 {
        widgets::card(ui, |ui| {
            ui.label(theme::section(
                "This process has not opened any files or connections yet.",
            ));
            ui.label(theme::dim(
                "Files, connections and the programs it starts appear here as the daemon records them.",
            ));
        });
    }
    let narrow = ui.available_width() < space::NARROW;
    if narrow {
        canvas(ui, m, acts);
        side_panel(ui, m, acts);
    } else {
        ui.horizontal_top(|ui| {
            let w = ui.available_width() - space::SIDE_PANEL - space::L;
            let down = egui::Layout::top_down(egui::Align::Min);
            ui.allocate_ui_with_layout(vec2(w, space::MAP_H), down, |ui| canvas(ui, m, acts));
            ui.allocate_ui_with_layout(vec2(space::SIDE_PANEL, space::MAP_H), down, |ui| {
                side_panel(ui, m, acts)
            });
        });
    }
    // Time window.
    if let Some((a, b)) = mp.span()
        && b > a
    {
        ui.horizontal(|ui| {
            ui.label(theme::label("Time"));
            let mut t = mp.time;
            let r = ui.add(
                egui::Slider::new(&mut t, 0.0..=1.0)
                    .show_value(false)
                    .trailing_fill(true),
            );
            tag(&r, Role::Slider, "map-time");
            if (t - mp.time).abs() > f32::EPSILON {
                acts.push(act(MapAction::Time(t)));
            }
            let secs = (b - a) as f64 * f64::from(mp.time) / 1e9;
            ui.label(theme::mono_dim(if mp.time >= 1.0 {
                "everything".to_string()
            } else {
                format!("first {secs:.1} s")
            }));
        });
    }
    // Notes and legend.
    if g.capped > 0 {
        ui.label(theme::dim(format!(
            "Showing at most {} nodes: {} less active objects are grouped into \"+N more\".",
            crate::map::CAP,
            g.capped
        )));
    }
    if g.without_detail > 0 {
        ui.label(theme::dim(format!(
            "{} of its processes are drawn without their files: the window keeps details for {} processes at a time.",
            g.without_detail,
            crate::model::MAX_DETAILS
        )));
    }
    legend(ui);
}

fn legend(ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = space::M;
        let item = |ui: &mut Ui, fill: Color32, ring: Option<Color32>, text: &str| {
            let (rect, _) = ui.allocate_exact_size(vec2(space::M, space::M), Sense::hover());
            ui.painter().circle_filled(rect.center(), space::LEGEND_R, fill);
            if let Some(c) = ring {
                ui.painter()
                    .circle_stroke(rect.center(), space::LEGEND_R, Stroke::new(space::LINE, c));
            }
            ui.label(theme::label(text));
        };
        item(ui, color::NODE_PROCESS, None, "Process");
        item(ui, color::NODE_FILE, None, "File or folder");
        item(ui, color::BG, Some(color::ACCENT), "Network");
        item(ui, color::NODE_MINOR, None, "Little activity");
        item(ui, color::ALERT, Some(color::ALERT), "Tied to a finding");
        ui.label(theme::label("·  Bigger dot = more activity  ·  drag to pan, scroll to zoom, double-click a process to centre it"));
    });
}

fn canvas(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let mp = &m.map;
    let g = &mp.graph;
    let w = ui.available_width().max(space::SIDE_PANEL);
    let (rect, resp) = ui.allocate_exact_size(vec2(w, space::MAP_H), Sense::click_and_drag());
    tag(&resp, Role::Image, "access-map");
    let p = ui.painter_at(rect);
    p.rect_filled(
        rect,
        egui::CornerRadius::same(theme::radius::CARD),
        color::SURFACE,
    );
    // Fit the drawing into the canvas; the user's zoom multiplies that.
    let fit = {
        let pts: Vec<P> = g.nodes.iter().filter_map(|n| mp.pos(&n.id)).collect();
        let ext = pts
            .iter()
            .fold(0.0_f32, |a, q| a.max(q.x.abs()).max(q.y.abs()))
            .max(1.0);
        let half = rect.width().min(rect.height()) / 2.0 - space::XXXL;
        (half / ext).min(1.5)
    };
    let zoom = fit * if mp.zoom > 0.0 { mp.zoom } else { 1.0 };
    let origin = rect.center() + vec2(mp.pan.x, mp.pan.y);
    let to_screen = |q: P| origin + vec2(q.x, q.y) * zoom;
    // Hit test.
    let pointer = resp.hover_pos();
    let hit = |pos: Pos2| -> Option<&NodeId> {
        g.nodes
            .iter()
            .filter_map(|n| {
                let c = to_screen(mp.pos(&n.id)?);
                let d = c.distance(pos);
                (d <= radius(n) * zoom.max(0.6) + space::XS).then_some((d, &n.id))
            })
            .min_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(_, id)| id)
    };
    let hovered = pointer.and_then(hit).cloned();
    if hovered != mp.hover {
        acts.push(act(MapAction::Hover(hovered.clone())));
    }
    // Pointer input.
    let drag_id = egui::Id::unique("map-drag-node");
    if resp.drag_started() {
        let start = resp.interact_pointer_pos().and_then(hit).cloned();
        ui.data_mut(|d| d.insert_temp(drag_id, start));
    }
    if resp.dragged() {
        let d = resp.drag_delta();
        let node: Option<NodeId> = ui.data(|dm| dm.get_temp(drag_id)).flatten();
        match node {
            Some(id) => acts.push(act(MapAction::Drag(
                id,
                P {
                    x: d.x / zoom,
                    y: d.y / zoom,
                },
            ))),
            None => acts.push(act(MapAction::Pan(P { x: d.x, y: d.y }))),
        }
    }
    if resp.drag_stopped() {
        ui.data_mut(|d| d.remove::<Option<NodeId>>(drag_id));
    }
    if resp.double_clicked() {
        match &hovered {
            Some(id) => acts.push(act(MapAction::DoubleClick(id.clone()))),
            None => acts.push(act(MapAction::ResetView)),
        }
    } else if resp.clicked() {
        match &hovered {
            Some(id) => acts.push(act(MapAction::Click(id.clone()))),
            None => acts.push(act(MapAction::ClickEmpty)),
        }
    }
    if resp.hovered() {
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll.abs() > 0.0 {
            acts.push(act(MapAction::Zoom((scroll * ZOOM_PER_SCROLL).exp())));
        }
        let (tab, enter, plus, minus) = ui.input(|i| {
            (
                i.key_pressed(Key::Tab),
                i.key_pressed(Key::Enter),
                i.key_pressed(Key::Plus) || i.key_pressed(Key::Equals),
                i.key_pressed(Key::Minus),
            )
        });
        if tab {
            acts.push(act(MapAction::FocusNext));
        }
        if enter {
            acts.push(act(MapAction::SelectFocused));
        }
        if plus {
            acts.push(act(MapAction::Zoom(1.2)));
        }
        if minus {
            acts.push(act(MapAction::Zoom(1.0 / 1.2)));
        }
    }
    // What stays bright.
    let bright = mp.hover.as_ref().map(|h| mp.neighbourhood(h));
    let alpha = |n: &Node| -> f32 {
        let mut a = mp.fade_in(&n.id);
        if let Some(b) = &bright
            && !b.contains(&n.id)
        {
            a *= color::DIM_ALPHA;
        }
        if !mp.in_window(n) {
            a *= color::OUT_OF_WINDOW_ALPHA;
        }
        if !mp.matches(n) {
            a *= color::DIM_ALPHA;
        }
        a
    };
    let by_id: std::collections::BTreeMap<&NodeId, &Node> =
        g.nodes.iter().map(|n| (&n.id, n)).collect();
    // Edges.
    for e in &g.edges {
        let (Some(a), Some(b), Some(na), Some(nb)) = (
            mp.pos(&e.from),
            mp.pos(&e.to),
            by_id.get(&e.from),
            by_id.get(&e.to),
        ) else {
            continue;
        };
        let al = alpha(na).min(alpha(nb));
        let c = if e.flagged { color::ALERT } else { color::EDGE };
        let (sa, sb) = (to_screen(a), to_screen(b));
        p.line_segment([sa, sb], Stroke::new(space::HAIR, color::faded(c, al)));
        let near = mp
            .hover
            .as_ref()
            .is_some_and(|h| *h == e.from || *h == e.to)
            || mp
                .selected
                .as_ref()
                .is_some_and(|s| *s == e.from || *s == e.to);
        if near || mp.zoom >= 1.6 {
            let mid = sa + (sb - sa) * 0.5;
            p.text(
                mid,
                Align2::CENTER_CENTER,
                e.act.word(),
                theme::axis_font(),
                color::faded(
                    if e.flagged {
                        color::ALERT
                    } else {
                        color::TEXT_DIM
                    },
                    al,
                ),
            );
        }
    }
    // Nodes.
    let centre = mp.center.map(NodeId::Proc);
    for n in &g.nodes {
        let Some(q) = mp.pos(&n.id) else { continue };
        let c = to_screen(q);
        if !rect.expand(space::XXXL).contains(c) {
            continue;
        }
        let a = alpha(n);
        let r = radius(n) * zoom.clamp(0.6, 2.0);
        let minor = n.kind != Kind::Process && n.count <= 1 && !n.flagged;
        let fill = if n.flagged {
            color::ALERT
        } else if minor {
            color::NODE_MINOR
        } else {
            match n.kind {
                Kind::Process => color::NODE_PROCESS,
                Kind::File => color::NODE_FILE,
                Kind::Network => color::BG,
            }
        };
        p.circle_filled(c, r, color::faded(fill, a));
        if n.kind == Kind::Network && !n.flagged {
            p.circle_stroke(
                c,
                r,
                Stroke::new(space::LINE, color::faded(color::ACCENT, a)),
            );
        }
        if matches!(n.id, NodeId::Dir(_) | NodeId::System | NodeId::More(_)) {
            p.circle_stroke(
                c,
                r + space::GROUP_RING,
                Stroke::new(space::HAIR, color::faded(color::EDGE, a)),
            );
        }
        if n.flagged {
            p.circle_stroke(
                c,
                r + space::XS,
                Stroke::new(space::HAIR, color::faded(color::ALERT, a)),
            );
        }
        if Some(&n.id) == centre.as_ref() {
            p.circle_stroke(
                c,
                r + space::XS,
                Stroke::new(space::CHART_LINE, color::faded(color::ACCENT, a)),
            );
        }
        if mp.selected.as_ref() == Some(&n.id) {
            p.circle_stroke(c, r + space::S, Stroke::new(space::LINE, color::ACCENT));
        } else if mp.focus.as_ref() == Some(&n.id) {
            p.circle_stroke(c, r + space::S, Stroke::new(space::HAIR, color::TEXT_DIM));
        }
        let important = Some(&n.id) == centre.as_ref()
            || n.flagged
            || mp.hover.as_ref() == Some(&n.id)
            || mp.selected.as_ref() == Some(&n.id)
            || (!mp.search.trim().is_empty() && mp.matches(n));
        if important || mp.zoom.max(0.01) * fit.min(1.0) >= LABEL_ZOOM {
            let strong = important;
            p.text(
                c + vec2(0.0, r + space::XS),
                Align2::CENTER_TOP,
                &n.label,
                theme::label_font(),
                color::faded(
                    if strong {
                        color::TEXT_STRONG
                    } else {
                        color::TEXT
                    },
                    a,
                ),
            );
        }
    }
    if resp.hovered() && hovered.is_some() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if mp.moving() {
        ui.ctx().request_repaint();
    }
    let _ = Rect::NOTHING;
}

fn fmt_time(m: &Model, ts: u64) -> String {
    if ts == 0 {
        return "unknown".into();
    }
    let wall = m.boot_to_wall();
    if wall == 0 {
        return format!("{:.1} s after boot", ts as f64 / 1e9);
    }
    let secs = (wall.saturating_add(ts) / 1_000_000_000) % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

fn side_panel(ui: &mut Ui, m: &Model, acts: &mut Vec<Action>) {
    let mp = &m.map;
    let g = &mp.graph;
    widgets::card(ui, |ui| {
        ui.set_min_height(space::SIDE_MIN_H);
        ui.spacing_mut().item_spacing.y = space::S;
        let Some(sel) = mp
            .selected
            .as_ref()
            .and_then(|s| g.index(s))
            .and_then(|i| g.nodes.get(i))
        else {
            // Summary.
            ui.label(theme::section("Summary"));
            for (name, k) in [
                ("Processes", Kind::Process),
                ("Files and folders", Kind::File),
                ("Network", Kind::Network),
            ] {
                ui.horizontal(|ui| {
                    ui.label(theme::body(name));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(theme::mono(g.count(k).to_string()));
                    });
                });
            }
            widgets::hairline(ui);
            ui.label(theme::label("Most active"));
            let mut top: Vec<&Node> = g.nodes.iter().collect();
            top.sort_by_key(|n| std::cmp::Reverse(n.count));
            for n in top.into_iter().take(5) {
                ui.horizontal(|ui| {
                    widgets::status_dot(
                        ui,
                        if n.flagged {
                            Severity::Finding
                        } else {
                            Severity::None
                        },
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                theme::mono(n.label.clone()).color(color::TEXT_STRONG),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        acts.push(act(MapAction::Click(n.id.clone())));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(theme::mono_dim(n.count.to_string()));
                    });
                });
            }
            ui.label(theme::dim(
                "Click a dot to see what it is and who touched it.",
            ));
            return;
        };
        ui.horizontal(|ui| {
            widgets::status_dot(
                ui,
                if sel.flagged {
                    Severity::Finding
                } else {
                    Severity::None
                },
            );
            ui.label(theme::section(sel.label.clone()));
        });
        ui.add(egui::Label::new(theme::mono(sel.full.clone())).wrap());
        let kind = match &sel.id {
            NodeId::Proc(_) => "Process",
            NodeId::File(_) => "File",
            NodeId::Dir(_) => "Folder (grouped)",
            NodeId::System => "Common system files (grouped)",
            NodeId::Net(_) => "Outbound connection",
            NodeId::Listen(_) => "Listening socket",
            NodeId::More(_) => "Less active objects (grouped)",
        };
        ui.label(theme::label("Kind"));
        ui.label(theme::body(kind));
        if sel.members > 1 {
            ui.label(theme::dim(format!("{} objects", sel.members)));
        }
        if !sel.by.is_empty() {
            ui.label(theme::label("Touched by"));
            for (k, acts_by) in &sel.by {
                let who = m
                    .rows
                    .iter()
                    .find(|r| r.key == *k)
                    .map(|r| {
                        let n = m.shown(&candor_core::display::exe_shown(r));
                        n.rsplit('/').next().unwrap_or(&n).to_string()
                    })
                    .unwrap_or_else(|| "process".into());
                let what: Vec<String> = acts_by
                    .iter()
                    .map(|(a, n)| format!("{} x{n}", a.word()))
                    .collect();
                ui.label(theme::mono(format!(
                    "{who} ({})  {}",
                    k.tgid,
                    what.join(", ")
                )));
            }
        }
        ui.label(theme::label("First and last time"));
        ui.label(theme::mono(format!(
            "{}  ->  {}",
            sel.first
                .map(|t| fmt_time(m, t))
                .unwrap_or_else(|| "unknown".into()),
            fmt_time(m, sel.last)
        )));
        if let Some((title, why, _)) = &sel.finding {
            widgets::hairline(ui);
            ui.horizontal(|ui| {
                widgets::status_dot(ui, Severity::Finding);
                ui.label(theme::name(title.clone()));
            });
            ui.add(egui::Label::new(theme::dim(why.clone())).wrap());
            if widgets::text_button(ui, "Open finding").clicked() {
                acts.push(Action::ShowTab(Tab::Findings));
            }
        }
        if matches!(sel.id, NodeId::Dir(_) | NodeId::System)
            && widgets::text_button(ui, "Show every file").clicked()
        {
            acts.push(act(MapAction::DoubleClick(sel.id.clone())));
        }
        if let NodeId::Proc(k) = sel.id
            && Some(k) != mp.center
            && widgets::text_button(ui, "Centre the map here").clicked()
        {
            acts.push(act(MapAction::DoubleClick(sel.id.clone())));
        }
        let ids: std::collections::BTreeSet<u64> = sel.events.iter().copied().collect();
        if !ids.is_empty() {
            widgets::hairline(ui);
            ui.label(theme::label("Last events"));
            let mut evs: Vec<&candor_proto::Event> = m
                .map_events()
                .into_iter()
                .filter(|e| ids.contains(&e.id))
                .collect();
            evs.sort_by_key(|e| std::cmp::Reverse(e.id));
            for e in evs.iter().take(20) {
                ui.label(theme::mono(m.shown(&candor_core::display::safe_str(
                    &candor_core::explain::describe(e),
                ))));
            }
            if m.page == crate::model::Page::Processes
                && widgets::text_button(ui, "Open in Events").clicked()
            {
                acts.push(Action::ShowTab(Tab::Events));
            }
        }
    });
}
