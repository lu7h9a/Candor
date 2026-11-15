//! The visual system (docs/design/GUI_REDESIGN_SPEC.md section 3): every
//! colour, font, size, spacing value and radius the GUI uses. Nothing
//! outside this module writes a colour or a size literal
//! (`scripts/check-theme.sh` enforces it). There is one dark theme; a light
//! theme would be a second set of these tokens.
//!
//! Colour rules: teal (`ACCENT`) means selected or active, red (`ALERT`)
//! means a finding, amber (`CAUTION`) means "worth a look" or a warning.
//! Nothing else is coloured, and colour is never the only signal.

use egui::{Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, RichText, Stroke};
use std::sync::Arc;

/// Colour tokens.
pub mod color {
    use egui::Color32;
    /// Window background, input fields.
    pub const BG: Color32 = Color32::from_rgb(0x0E, 0x11, 0x13);
    /// Cards and panels.
    pub const SURFACE: Color32 = Color32::from_rgb(0x15, 0x1A, 0x1D);
    /// Selected segment, secondary buttons, borders.
    pub const SURFACE_RAISED: Color32 = Color32::from_rgb(0x22, 0x2A, 0x2E);
    /// Row dividers.
    pub const HAIRLINE: Color32 = Color32::from_rgb(0x1A, 0x20, 0x23);
    /// Body text.
    pub const TEXT: Color32 = Color32::from_rgb(0xC9, 0xD1, 0xD5);
    /// Names, headings, the value in focus.
    pub const TEXT_STRONG: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
    /// Labels, column headers, hints.
    pub const TEXT_DIM: Color32 = Color32::from_rgb(0x9A, 0xA5, 0xAB);
    /// Active tab, selection, follow mode, primary button, chart line.
    pub const ACCENT: Color32 = Color32::from_rgb(0x2D, 0xD4, 0xBF);
    /// Background of an active tab or chip.
    pub const ACCENT_BG: Color32 = Color32::from_rgb(0x17, 0x20, 0x1F);
    /// Findings only.
    pub const ALERT: Color32 = Color32::from_rgb(0xF4, 0x7C, 0x7C);
    /// "Worth a look" and warnings only.
    pub const CAUTION: Color32 = Color32::from_rgb(0xE8, 0xB4, 0x5A);
    /// Process dots in the map.
    pub const NODE_PROCESS: Color32 = Color32::from_rgb(0xE6, 0xEC, 0xEF);
    /// File dots in the map.
    pub const NODE_FILE: Color32 = Color32::from_rgb(0x7C, 0x8A, 0x91);
    /// Low-activity dots.
    pub const NODE_MINOR: Color32 = Color32::from_rgb(0x56, 0x63, 0x6A);
    /// Map lines, flow connectors.
    pub const EDGE: Color32 = Color32::from_rgb(0x3A, 0x46, 0x4C);
    /// Nothing drawn (used for hit areas and empty slots).
    pub const NONE: Color32 = Color32::TRANSPARENT;

    /// `c` at `alpha` (0..=1) opacity: dimming in the map.
    pub fn faded(c: Color32, alpha: f32) -> Color32 {
        c.gamma_multiply(alpha.clamp(0.0, 1.0))
    }
}

/// Font sizes (points).
pub mod size {
    /// Labels and column headers.
    pub const LABEL: f32 = 12.0;
    /// Table numbers and secondary text.
    pub const SMALL: f32 = 13.0;
    /// Body.
    pub const BODY: f32 = 14.0;
    /// Section titles.
    pub const SECTION: f32 = 15.0;
    /// The word "candor" in the top bar.
    pub const BRAND: f32 = 16.0;
    /// Page title.
    pub const TITLE: f32 = 20.0;
    /// Big stat numbers.
    pub const STAT: f32 = 32.0;
    /// Axis labels and map labels.
    pub const AXIS: f32 = 11.0;
}

/// Spacing scale and fixed dimensions.
pub mod space {
    /// 4.
    pub const XS: f32 = 4.0;
    /// 8.
    pub const S: f32 = 8.0;
    /// 12.
    pub const M: f32 = 12.0;
    /// 16.
    pub const L: f32 = 16.0;
    /// 24.
    pub const XL: f32 = 24.0;
    /// 32.
    pub const XXL: f32 = 32.0;
    /// 40.
    pub const XXXL: f32 = 40.0;
    /// Page padding, left and right.
    pub const PAGE_X: f32 = 40.0;
    /// Page padding, top.
    pub const PAGE_TOP: f32 = 28.0;
    /// Widest the content grows.
    pub const CONTENT_MAX: f32 = 1200.0;
    /// Table row height.
    pub const ROW: f32 = 52.0;
    /// Table header height.
    pub const HEADER: f32 = 36.0;
    /// Buttons and inputs.
    pub const CONTROL: f32 = 44.0;
    /// Segmented switch and chips.
    pub const CONTROL_SMALL: f32 = 36.0;
    /// Status dot diameter.
    pub const DOT: f32 = 8.0;
    /// Stat card sparkline.
    pub const SPARK_W: f32 = 120.0;
    /// Stat card sparkline.
    pub const SPARK_H: f32 = 40.0;
    /// Table row sparkline.
    pub const ROW_SPARK_W: f32 = 64.0;
    /// Table row sparkline.
    pub const ROW_SPARK_H: f32 = 20.0;
    /// Chart height in the detail page.
    pub const CHART_H: f32 = 200.0;
    /// Search field width.
    pub const SEARCH_W: f32 = 200.0;
    /// Tree indentation per level.
    pub const INDENT: f32 = 18.0;
    /// Side panel of the map.
    pub const SIDE_PANEL: f32 = 320.0;
    /// Map canvas height.
    pub const MAP_H: f32 = 520.0;
    /// Thin line (sparklines, connectors).
    pub const LINE: f32 = 1.5;
    /// Chart line.
    pub const CHART_LINE: f32 = 2.0;
    /// Hairline.
    pub const HAIR: f32 = 1.0;
    /// Width of form fields in Glasshouse.
    pub const FIELD_W: f32 = 520.0;
    /// Width at which cards wrap to one column.
    pub const NARROW: f32 = 900.0;
}

/// Corner radii.
pub mod radius {
    /// Cards.
    pub const CARD: u8 = 12;
    /// Buttons and inputs.
    pub const CONTROL: u8 = 8;
    /// Segments inside a switch.
    pub const SEGMENT: u8 = 6;
    /// Chips (fully round).
    pub const CHIP: u8 = 255;
}

/// Font families: Inter for words, JetBrains Mono for numbers, PIDs, paths,
/// commands and syscalls.
pub mod font {
    use egui::FontFamily;
    /// Inter 500.
    pub fn medium() -> FontFamily {
        FontFamily::Name("inter-medium".into())
    }
    /// Inter 600.
    pub fn semibold() -> FontFamily {
        FontFamily::Name("inter-semibold".into())
    }
    /// JetBrains Mono 500.
    pub fn mono_medium() -> FontFamily {
        FontFamily::Name("mono-medium".into())
    }
}

const INTER_400: &[u8] = include_bytes!("../fonts/Inter-Regular.ttf");
const INTER_500: &[u8] = include_bytes!("../fonts/Inter-Medium.ttf");
const INTER_600: &[u8] = include_bytes!("../fonts/Inter-SemiBold.ttf");
const MONO_400: &[u8] = include_bytes!("../fonts/JetBrainsMono-Regular.ttf");
const MONO_500: &[u8] = include_bytes!("../fonts/JetBrainsMono-Medium.ttf");

/// The bundled fonts, with egui's built-in fonts as fallbacks for
/// characters outside the Latin subset.
pub fn fonts() -> FontDefinitions {
    let mut d = FontDefinitions::default();
    let fallback_prop = d
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let fallback_mono = d
        .families
        .get(&FontFamily::Monospace)
        .cloned()
        .unwrap_or_default();
    for (name, bytes) in [
        ("inter-400", INTER_400),
        ("inter-500", INTER_500),
        ("inter-600", INTER_600),
        ("mono-400", MONO_400),
        ("mono-500", MONO_500),
    ] {
        d.font_data
            .insert(name.into(), Arc::new(FontData::from_static(bytes)));
    }
    let chain = |first: &str, rest: &[String]| {
        std::iter::once(first.to_string())
            .chain(rest.iter().cloned())
            .collect::<Vec<_>>()
    };
    d.families
        .insert(FontFamily::Proportional, chain("inter-400", &fallback_prop));
    d.families
        .insert(font::medium(), chain("inter-500", &fallback_prop));
    d.families
        .insert(font::semibold(), chain("inter-600", &fallback_prop));
    d.families
        .insert(FontFamily::Monospace, chain("mono-400", &fallback_mono));
    d.families
        .insert(font::mono_medium(), chain("mono-500", &fallback_mono));
    d
}

/// Installs fonts and the dark visuals into a context.
pub fn install(ctx: &egui::Context) {
    ctx.set_fonts(fonts());
    ctx.all_styles_mut(apply);
}

fn apply(s: &mut egui::Style) {
    use egui::{TextStyle, vec2};
    s.text_styles = [
        (TextStyle::Small, FontId::proportional(size::LABEL)),
        (TextStyle::Body, FontId::proportional(size::BODY)),
        (TextStyle::Button, FontId::new(size::BODY, font::medium())),
        (TextStyle::Heading, FontId::new(size::TITLE, font::semibold())),
        (TextStyle::Monospace, FontId::monospace(size::SMALL)),
    ]
    .into();
    s.spacing.item_spacing = vec2(space::S, space::S);
    s.spacing.button_padding = vec2(space::L, space::M);
    s.spacing.interact_size = vec2(space::CONTROL, space::CONTROL_SMALL);
    s.spacing.window_margin = egui::Margin::same(space::XL as i8);
    s.spacing.menu_margin = egui::Margin::same(space::S as i8);
    let v = &mut s.visuals;
    v.dark_mode = true;
    v.override_text_color = None;
    v.panel_fill = color::BG;
    v.window_fill = color::SURFACE;
    v.window_stroke = Stroke::NONE;
    v.window_shadow = egui::Shadow::NONE;
    v.popup_shadow = egui::Shadow::NONE;
    v.window_corner_radius = CornerRadius::same(radius::CARD);
    v.menu_corner_radius = CornerRadius::same(radius::CONTROL);
    v.extreme_bg_color = color::BG;
    v.text_edit_bg_color = Some(color::BG);
    v.faint_bg_color = color::SURFACE;
    v.code_bg_color = color::BG;
    v.hyperlink_color = color::ACCENT;
    v.warn_fg_color = color::CAUTION;
    v.error_fg_color = color::ALERT;
    v.striped = false;
    v.indent_has_left_vline = false;
    v.selection.bg_fill = color::ACCENT_BG;
    v.selection.stroke = Stroke::new(space::HAIR, color::ACCENT);
    v.text_cursor.stroke = Stroke::new(space::HAIR, color::ACCENT);
    let w = &mut v.widgets;
    let control = CornerRadius::same(radius::CONTROL);
    w.noninteractive.bg_fill = color::SURFACE;
    w.noninteractive.weak_bg_fill = color::SURFACE;
    w.noninteractive.bg_stroke = Stroke::new(space::HAIR, color::HAIRLINE);
    w.noninteractive.fg_stroke = Stroke::new(space::HAIR, color::TEXT);
    w.noninteractive.corner_radius = control;
    w.inactive.bg_fill = color::SURFACE_RAISED;
    w.inactive.weak_bg_fill = color::SURFACE_RAISED;
    w.inactive.bg_stroke = Stroke::NONE;
    w.inactive.fg_stroke = Stroke::new(space::HAIR, color::TEXT_STRONG);
    w.inactive.corner_radius = control;
    w.hovered.bg_fill = color::SURFACE_RAISED;
    w.hovered.weak_bg_fill = color::SURFACE_RAISED;
    w.hovered.bg_stroke = Stroke::new(space::HAIR, color::EDGE);
    w.hovered.fg_stroke = Stroke::new(space::HAIR, color::TEXT_STRONG);
    w.hovered.corner_radius = control;
    w.hovered.expansion = 0.0;
    w.active.bg_fill = color::ACCENT_BG;
    w.active.weak_bg_fill = color::ACCENT_BG;
    w.active.bg_stroke = Stroke::new(space::HAIR, color::ACCENT);
    w.active.fg_stroke = Stroke::new(space::HAIR, color::ACCENT);
    w.active.corner_radius = control;
    w.active.expansion = 0.0;
    w.open = w.active;
}

// Text helpers: every piece of text in the GUI is made with one of these.

/// Body text (Inter 400, 14, `TEXT`).
pub fn body(s: impl Into<String>) -> RichText {
    RichText::new(s).size(size::BODY).color(color::TEXT)
}
/// A label or column header (Inter 400, 12, `TEXT_DIM`).
pub fn label(s: impl Into<String>) -> RichText {
    RichText::new(s).size(size::LABEL).color(color::TEXT_DIM)
}
/// Secondary text (Inter 400, 13, `TEXT_DIM`).
pub fn dim(s: impl Into<String>) -> RichText {
    RichText::new(s).size(size::SMALL).color(color::TEXT_DIM)
}
/// A name (Inter 500, 14, `TEXT_STRONG`).
pub fn name(s: impl Into<String>) -> RichText {
    RichText::new(s)
        .size(size::BODY)
        .family(font::medium())
        .color(color::TEXT_STRONG)
}
/// A section title (Inter 500, 15, `TEXT_STRONG`).
pub fn section(s: impl Into<String>) -> RichText {
    RichText::new(s)
        .size(size::SECTION)
        .family(font::medium())
        .color(color::TEXT_STRONG)
}
/// A page title (Inter 600, 20, `TEXT_STRONG`).
pub fn title(s: impl Into<String>) -> RichText {
    RichText::new(s)
        .size(size::TITLE)
        .family(font::semibold())
        .color(color::TEXT_STRONG)
}
/// The brand word (Inter 600, 16).
pub fn brand(s: impl Into<String>) -> RichText {
    RichText::new(s)
        .size(size::BRAND)
        .family(font::semibold())
        .color(color::TEXT_STRONG)
}
/// A number, PID, path, command or syscall (JetBrains Mono 400, 13).
pub fn mono(s: impl Into<String>) -> RichText {
    RichText::new(s)
        .size(size::SMALL)
        .family(FontFamily::Monospace)
        .color(color::TEXT)
}
/// A dim small mono value (PID next to a name).
pub fn mono_dim(s: impl Into<String>) -> RichText {
    RichText::new(s)
        .size(size::LABEL)
        .family(FontFamily::Monospace)
        .color(color::TEXT_DIM)
}
/// A big stat number (JetBrains Mono 500, 32, `TEXT_STRONG`).
pub fn stat(s: impl Into<String>) -> RichText {
    RichText::new(s)
        .size(size::STAT)
        .family(font::mono_medium())
        .color(color::TEXT_STRONG)
}
/// A score (JetBrains Mono 500, 13) in its band colour.
pub fn score(s: impl Into<String>, c: Color32) -> RichText {
    RichText::new(s)
        .size(size::SMALL)
        .family(font::mono_medium())
        .color(c)
}

/// Font for painter-drawn text (map labels, chart axes).
pub fn axis_font() -> FontId {
    FontId::monospace(size::AXIS)
}
/// Font for painter-drawn proportional labels.
pub fn label_font() -> FontId {
    FontId::proportional(size::LABEL)
}
