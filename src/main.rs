// monotp — minimal, fully-encrypted, cross-platform TOTP authenticator.
// Author: X-croot  (https://github.com/X-croot)
//
// Hide the console window on Windows release builds.
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod autostart;
mod crypto;
mod storage;
mod theme;
mod totp;

use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    let icon = load_icon();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([460.0, 620.0])
            .with_min_inner_size([380.0, 480.0])
            .with_title("monotp")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "monotp",
        native_options,
        Box::new(|cc| Box::new(app::App::new(cc))),
    )
}

/// Loads the embedded black & white TOTP icon (PNG) for the window/taskbar.
/// The same icon is compiled into the Windows .exe via `build.rs`.
fn load_icon() -> egui::IconData {
    let bytes = include_bytes!("../assets/icon.png");
    match image::load_from_memory(bytes) {
        Ok(img) => {
            let img = img.into_rgba8();
            let (width, height) = img.dimensions();
            egui::IconData {
                rgba: img.into_raw(),
                width,
                height,
            }
        }
        Err(_) => egui::IconData {
            rgba: vec![0, 0, 0, 255],
            width: 1,
            height: 1,
        },
    }
}
