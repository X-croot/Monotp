use egui::{Color32, Rounding, Stroke, Visuals};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ThemeKind {
    System,
    Dark,
    Light,
    Sakura,
    Monochrome,
}

impl Default for ThemeKind {
    fn default() -> Self {
        ThemeKind::System
    }
}

impl ThemeKind {
    pub const ALL: [ThemeKind; 5] = [
        ThemeKind::System,
        ThemeKind::Dark,
        ThemeKind::Light,
        ThemeKind::Sakura,
        ThemeKind::Monochrome,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ThemeKind::System => "System",
            ThemeKind::Dark => "Dark",
            ThemeKind::Light => "Light",
            ThemeKind::Sakura => "Sakura",
            ThemeKind::Monochrome => "Monochrome",
        }
    }
}

/// Detect the OS preference. egui exposes it through the context.
pub fn resolve_system(ctx: &egui::Context) -> ThemeKind {
    match ctx.style().visuals.dark_mode {
        true => ThemeKind::Dark,
        false => ThemeKind::Light,
    }
}

/// Apply a theme's visuals to the egui context.
pub fn apply(ctx: &egui::Context, kind: ThemeKind) {
    let effective = match kind {
        ThemeKind::System => {
            // Follow whatever the platform reported at startup.
            if ctx.style().visuals.dark_mode {
                ThemeKind::Dark
            } else {
                ThemeKind::Light
            }
        }
        other => other,
    };

    let visuals = match effective {
        ThemeKind::Dark => dark(),
        ThemeKind::Light => light(),
        ThemeKind::Sakura => sakura(),
        ThemeKind::Monochrome => monochrome(),
        ThemeKind::System => dark(),
    };

    ctx.set_visuals(visuals);
}

fn base(mut v: Visuals) -> Visuals {
    let r = Rounding::same(8.0);
    v.window_rounding = r;
    v.menu_rounding = r;
    v.widgets.noninteractive.rounding = r;
    v.widgets.inactive.rounding = r;
    v.widgets.hovered.rounding = r;
    v.widgets.active.rounding = r;
    v.widgets.open.rounding = r;
    v
}

fn dark() -> Visuals {
    let mut v = Visuals::dark();
    v.panel_fill = Color32::from_rgb(15, 15, 17);
    v.window_fill = Color32::from_rgb(20, 20, 23);
    v.extreme_bg_color = Color32::from_rgb(10, 10, 12);
    v.override_text_color = Some(Color32::from_rgb(235, 235, 238));
    v.selection.bg_fill = Color32::from_rgb(70, 70, 80);
    v.widgets.hovered.bg_fill = Color32::from_rgb(45, 45, 52);
    base(v)
}

fn light() -> Visuals {
    let mut v = Visuals::light();
    v.panel_fill = Color32::from_rgb(250, 250, 250);
    v.window_fill = Color32::from_rgb(255, 255, 255);
    v.extreme_bg_color = Color32::from_rgb(240, 240, 242);
    v.override_text_color = Some(Color32::from_rgb(20, 20, 24));
    base(v)
}

/// Soft pink "Sakura" theme.
fn sakura() -> Visuals {
    let mut v = Visuals::light();
    let bg = Color32::from_rgb(255, 244, 248);
    let panel = Color32::from_rgb(255, 236, 243);
    let accent = Color32::from_rgb(233, 143, 178);
    v.panel_fill = panel;
    v.window_fill = bg;
    v.extreme_bg_color = Color32::from_rgb(255, 228, 238);
    v.override_text_color = Some(Color32::from_rgb(90, 45, 62));
    v.selection.bg_fill = accent.linear_multiply(0.5);
    v.selection.stroke = Stroke::new(1.0, accent);
    v.widgets.hovered.bg_fill = Color32::from_rgb(255, 214, 228);
    v.widgets.active.bg_fill = accent;
    v.hyperlink_color = Color32::from_rgb(198, 92, 133);
    base(v)
}

/// Pure black & white high-contrast theme.
fn monochrome() -> Visuals {
    let mut v = Visuals::dark();
    let black = Color32::from_rgb(0, 0, 0);
    let white = Color32::from_rgb(255, 255, 255);
    v.panel_fill = black;
    v.window_fill = black;
    v.extreme_bg_color = Color32::from_rgb(12, 12, 12);
    v.override_text_color = Some(white);
    v.faint_bg_color = Color32::from_rgb(20, 20, 20);
    v.selection.bg_fill = Color32::from_rgb(60, 60, 60);
    v.selection.stroke = Stroke::new(1.0, white);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, white);
    v.widgets.inactive.bg_fill = Color32::from_rgb(24, 24, 24);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, white);
    v.widgets.hovered.bg_fill = Color32::from_rgb(40, 40, 40);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, white);
    v.widgets.active.bg_fill = white;
    v.widgets.active.fg_stroke = Stroke::new(1.0, black);
    v.window_stroke = Stroke::new(1.0, white);
    base(v)
}
