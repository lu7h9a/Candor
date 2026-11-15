//! Shared components (spec section 3): status dot, card, stat card,
//! sparkline, line chart, segmented switch, chip and the three button
//! kinds. They take every colour and size from `theme`.

use crate::theme::{self, color, radius, size, space};
use egui::{
    Color32, CornerRadius, Margin, Pos2, Rect, Response, RichText, Role, Sense, Stroke, Ui, Vec2,
    WidgetInfo, vec2,
};

/// Gives a widget a stable accessibility label (the UI tests use these).
pub fn tag(r: &Response, role: Role, name: &'static str) {
    r.widget_info(|| WidgetInfo::labeled(role, true, name));
}

/// Severity of a row or finding, shown as dot colour plus words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A finding (red).
    Finding,
    /// Worth a look (amber).
    Caution,
    /// Nothing to flag.
    None,
}

impl Severity {
    /// From a 0-100 score: 60+ is a finding, 30+ worth a look (the bands
    /// the rest of Candor uses: high and suspicious).
    pub fn of_score(score: u8) -> Severity {
        match score {
            60.. => Severity::Finding,
            30..=59 => Severity::Caution,
            _ => Severity::None,
        }
    }
    /// The colour for this severity (dim for none).
    pub fn color(self) -> Color32 {
        match self {
            Severity::Finding => color::ALERT,
            Severity::Caution => color::CAUTION,
            Severity::None => color::TEXT_DIM,
        }
    }
    /// The words read out with the dot (never colour alone).
    pub fn words(self) -> &'static str {
        match self {
            Severity::Finding => "Flagged",
            Severity::Caution => "Worth a look",
            Severity::None => "",
        }
    }
}

/// An 8 px status dot; `None` keeps the slot empty so names stay aligned.
pub fn status_dot(ui: &mut Ui, sev: Severity) -> Response {
    let (rect, r) = ui.allocate_exact_size(Vec2::splat(space::DOT), Sense::hover());
    if sev != Severity::None {
        ui.painter()
            .circle_filled(rect.center(), space::DOT_R, sev.color());
        let words = sev.words();
        r.widget_info(|| WidgetInfo::labeled(Role::Image, true, words));
    }
    r
}

/// A card: `SURFACE` fill, radius 12, no border.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(color::SURFACE)
        .corner_radius(CornerRadius::same(radius::CARD))
        .inner_margin(Margin::same(space::XL as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A card with a tighter margin (stat cards).
pub fn card_compact<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(color::SURFACE)
        .corner_radius(CornerRadius::same(radius::CARD))
        .inner_margin(Margin::symmetric(
            space::XL as i8,
            (space::L + space::XS) as i8,
        ))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A 1.5 px sparkline of `values` in `rect`, no axes, no fill.
pub fn sparkline(ui: &Ui, rect: Rect, values: &[f32], c: Color32) {
    if values.len() < 2 {
        ui.painter().line_segment(
            [rect.left_center(), rect.right_center()],
            Stroke::new(space::LINE, c),
        );
        return;
    }
    let max = values.iter().copied().fold(f32::MIN, f32::max);
    let min = values.iter().copied().fold(f32::MAX, f32::min);
    let span = (max - min).max(f32::EPSILON);
    let n = (values.len() - 1) as f32;
    let pts: Vec<Pos2> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = rect.left() + rect.width() * i as f32 / n;
            // Flat series sit in the middle; others use the full height.
            let y = if (max - min).abs() < f32::EPSILON {
                rect.center().y
            } else {
                rect.bottom() - rect.height() * (v - min) / span
            };
            Pos2::new(x, y)
        })
        .collect();
    ui.painter().line(pts, Stroke::new(space::LINE, c));
}

/// Stat card: dim label, 32 px mono number, optional line under it, and a
/// 120x40 sparkline on the right.
pub fn stat_card(
    ui: &mut Ui,
    label: &str,
    value: &str,
    sub: Option<(String, Color32, &'static str)>,
    series: &[f32],
) {
    card_compact(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = space::S;
                ui.label(theme::dim(label));
                ui.label(theme::stat(value));
                if let Some((text, c, id)) = sub {
                    let r = ui.label(RichText::new(text).size(size::LABEL).color(c));
                    tag(&r, Role::Label, id);
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Max), |ui| {
                let (rect, _) =
                    ui.allocate_exact_size(vec2(space::SPARK_W, space::SPARK_H), Sense::hover());
                sparkline(ui, rect, series, color::ACCENT);
            });
        });
    });
}

/// A line chart: one series, 2 px accent line, three faint gridlines, mono
/// axis labels, the value under the pointer on hover.
pub fn line_chart(ui: &mut Ui, values: &[f32], fmt: &dyn Fn(f32) -> String, aria: &str) {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(w, space::CHART_H), Sense::hover());
    let aria = aria.to_string();
    resp.widget_info(|| WidgetInfo::labeled(Role::Image, true, aria.clone()));
    let p = ui.painter_at(rect);
    let plot = Rect::from_min_max(
        rect.min + vec2(space::XXXL, space::S),
        rect.max - vec2(0.0, space::XL),
    );
    let max = values
        .iter()
        .copied()
        .fold(0.0_f32, f32::max)
        .max(f32::EPSILON);
    for frac in [0.0_f32, 0.5, 1.0] {
        let y = plot.bottom() - plot.height() * frac;
        p.line_segment(
            [Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)],
            Stroke::new(space::HAIR, color::SURFACE_RAISED),
        );
        p.text(
            Pos2::new(rect.left(), y),
            egui::Align2::LEFT_CENTER,
            fmt(max * frac),
            theme::axis_font(),
            color::TEXT_DIM,
        );
    }
    p.text(
        Pos2::new(plot.left(), rect.bottom()),
        egui::Align2::LEFT_BOTTOM,
        "earlier",
        theme::axis_font(),
        color::TEXT_DIM,
    );
    p.text(
        rect.right_bottom(),
        egui::Align2::RIGHT_BOTTOM,
        "now",
        theme::axis_font(),
        color::TEXT_DIM,
    );
    if values.len() < 2 {
        p.text(
            plot.center(),
            egui::Align2::CENTER_CENTER,
            "Collecting data...",
            theme::label_font(),
            color::TEXT_DIM,
        );
        return;
    }
    let n = (values.len() - 1) as f32;
    let at = |i: usize, v: f32| {
        Pos2::new(
            plot.left() + plot.width() * i as f32 / n,
            plot.bottom() - plot.height() * (v / max).clamp(0.0, 1.0),
        )
    };
    let pts: Vec<Pos2> = values.iter().enumerate().map(|(i, v)| at(i, *v)).collect();
    p.line(pts, Stroke::new(space::CHART_LINE, color::ACCENT));
    if let Some(pos) = resp.hover_pos()
        && plot.x_range().contains(pos.x)
    {
        let i = (((pos.x - plot.left()) / plot.width()) * n).round() as usize;
        if let Some(v) = values.get(i) {
            let pt = at(i, *v);
            p.circle_filled(pt, space::XS, color::ACCENT);
            p.text(
                pt - vec2(0.0, space::M),
                egui::Align2::CENTER_BOTTOM,
                fmt(*v),
                theme::axis_font(),
                color::TEXT_STRONG,
            );
        }
    }
}

/// A segmented switch: `SURFACE` track, `SURFACE_RAISED` selected segment.
/// Returns the index clicked this frame, if any.
pub fn segmented(ui: &mut Ui, items: &[(&str, bool, &'static str)]) -> Option<usize> {
    let mut clicked = None;
    // In a right-to-left row the items are added in reverse so they still
    // read left to right.
    let rtl = ui.layout().main_dir() == egui::Direction::RightToLeft;
    let order: Vec<usize> = if rtl {
        (0..items.len()).rev().collect()
    } else {
        (0..items.len()).collect()
    };
    egui::Frame::new()
        .fill(color::SURFACE)
        .corner_radius(CornerRadius::same(radius::CONTROL))
        .inner_margin(Margin::same(space::XS as i8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = space::XS;
                for i in order {
                    let Some((text, on, id)) = items.get(i) else {
                        continue;
                    };
                    let (fill, fg) = if *on {
                        (color::SURFACE_RAISED, color::TEXT_STRONG)
                    } else {
                        (color::NONE, color::TEXT_DIM)
                    };
                    let b = egui::Button::new(
                        RichText::new(*text)
                            .size(size::SMALL)
                            .family(theme::font::medium())
                            .color(fg),
                    )
                    .fill(fill)
                    .stroke(Stroke::NONE)
                    .corner_radius(CornerRadius::same(radius::SEGMENT))
                    .min_size(vec2(0.0, space::CONTROL_SMALL - space::S));
                    let r = ui.add(b);
                    tag(&r, Role::Tab, id);
                    if r.clicked() {
                        clicked = Some(i);
                    }
                }
            });
        });
    clicked
}

/// A top-level navigation tab: `ACCENT_BG` + `ACCENT` when active.
pub fn nav_tab(ui: &mut Ui, text: &str, active: bool) -> Response {
    let (fill, fg) = if active {
        (color::ACCENT_BG, color::ACCENT)
    } else {
        (color::NONE, color::TEXT_DIM)
    };
    ui.add(
        egui::Button::new(
            RichText::new(text)
                .size(size::BODY)
                .family(theme::font::medium())
                .color(fg),
        )
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(radius::CONTROL))
        .min_size(vec2(0.0, space::CONTROL)),
    )
}

/// A round filter chip with a count; `ACCENT_BG` + `ACCENT` when on.
pub fn chip(ui: &mut Ui, text: &str, count: Option<usize>, on: bool) -> Response {
    let (fill, fg) = if on {
        (color::ACCENT_BG, color::ACCENT)
    } else {
        (color::SURFACE, color::TEXT_DIM)
    };
    let label = match count {
        Some(n) => format!("{text}  {n}"),
        None => text.to_string(),
    };
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .size(size::SMALL)
                .family(theme::font::medium())
                .color(fg),
        )
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(radius::CHIP))
        .min_size(vec2(0.0, space::CONTROL_SMALL)),
    )
}

/// Primary button: `ACCENT` fill, `BG` text. One per screen at most.
pub fn primary(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(
            RichText::new(text)
                .size(size::BODY)
                .family(theme::font::medium())
                .color(color::BG),
        )
        .fill(color::ACCENT)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(radius::CONTROL))
        .min_size(vec2(0.0, space::CONTROL)),
    )
}

/// Secondary button: `SURFACE_RAISED` fill, white text.
pub fn secondary(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(
            RichText::new(text)
                .size(size::BODY)
                .family(theme::font::medium())
                .color(color::TEXT_STRONG),
        )
        .fill(color::SURFACE_RAISED)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(radius::CONTROL))
        .min_size(vec2(0.0, space::CONTROL)),
    )
}

/// Outlined accent button ("Follow this process").
pub fn outlined(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(
            RichText::new(text)
                .size(size::BODY)
                .family(theme::font::medium())
                .color(color::ACCENT),
        )
        .fill(color::NONE)
        .stroke(Stroke::new(space::HAIR, color::ACCENT))
        .corner_radius(CornerRadius::same(radius::CONTROL))
        .min_size(vec2(0.0, space::CONTROL)),
    )
}

/// Text button: `ACCENT` text, no background.
pub fn text_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(
            RichText::new(text)
                .size(size::SMALL)
                .family(theme::font::medium())
                .color(color::ACCENT),
        )
        .frame(false)
        .min_size(vec2(0.0, space::CONTROL)),
    )
}

/// A dot and a line of text in the caution colour scheme (warnings that
/// must stay visible, such as the Glasshouse limitation).
pub fn caution_line(ui: &mut Ui, text: &str) -> Response {
    ui.horizontal_top(|ui| {
        ui.add_space(space::XS);
        status_dot(ui, Severity::Caution);
        ui.add(egui::Label::new(theme::body(text)).wrap())
    })
    .inner
}

/// A hairline divider.
pub fn hairline(ui: &mut Ui) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(w, space::HAIR), Sense::hover());
    ui.painter().rect_filled(rect, 0.0, color::HAIRLINE);
}

/// Human-readable bytes (decimal units, as the mockups show: "12 MB").
pub fn bytes(b: u64) -> String {
    let mut v = b as f64;
    let mut u = 0;
    let units = ["B", "KB", "MB", "GB", "TB"];
    while v >= 1000.0 && u + 1 < units.len() {
        v /= 1000.0;
        u += 1;
    }
    let unit = units.get(u).copied().unwrap_or("B");
    if u == 0 || v >= 100.0 {
        format!("{v:.0} {unit}")
    } else {
        format!("{v:.1} {unit}")
    }
}

/// A small magnifier icon (search fields).
pub fn search_icon(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(space::L), Sense::hover());
    let c = rect.center() - vec2(space::ICON_SHIFT, space::ICON_SHIFT);
    let stroke = Stroke::new(space::LINE, color::TEXT_DIM);
    ui.painter().circle_stroke(c, space::ICON_R, stroke);
    ui.painter().line_segment(
        [c + vec2(space::XS, space::XS), c + vec2(space::S, space::S)],
        stroke,
    );
}

/// A disclosure triangle (tree rows): pointing right when closed, down
/// when open. `active` false keeps an empty slot of the same size.
pub fn disclosure(ui: &mut Ui, active: bool, open: bool) -> Response {
    let sense = if active {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, r) = ui.allocate_exact_size(Vec2::splat(space::L), sense);
    if active {
        let c = rect.center();
        let h = space::XS;
        let pts = if open {
            vec![
                c + vec2(-h, -h / 2.0),
                c + vec2(h, -h / 2.0),
                c + vec2(0.0, h),
            ]
        } else {
            vec![
                c + vec2(-h / 2.0, -h),
                c + vec2(h, 0.0),
                c + vec2(-h / 2.0, h),
            ]
        };
        let col = if r.hovered() {
            color::TEXT_STRONG
        } else {
            color::TEXT_DIM
        };
        ui.painter()
            .add(egui::Shape::convex_polygon(pts, col, Stroke::NONE));
    }
    r
}
