use crate::crypto::MasterKey;
use crate::storage::{self, Config, Entry, Paths, Vault};
use crate::theme::{self, ThemeKind};
use crate::totp::{self, Algorithm};
use crate::{autostart, crypto};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use egui::{Align, Color32, Layout, RichText, Vec2};
use std::time::Instant;

enum Screen {
    Setup,
    Unlock,
    Vault,
}

#[derive(PartialEq)]
enum Dialog {
    None,
    Add,
    Edit(usize),
    ChangePw,
    Forgot,
}

pub struct App {
    paths: Paths,
    config: Config,
    screen: Screen,
    icon_tex: egui::TextureHandle,

    key: Option<MasterKey>,
    vault: Vault,

    pw_input: String,
    pw_confirm: String,
    status: String,

    dialog: Dialog,
    search: String,

    // add / edit form
    f_issuer: String,
    f_account: String,
    f_secret: String,
    f_digits: u32,
    f_period: u64,
    f_algo: Algorithm,
    f_smart: String,
    f_status: String,

    // change password
    cp_new: String,
    cp_confirm: String,

    // forgot password confirm
    forgot_confirm: String,

    reveal: Option<usize>,
    copied_at: Option<(usize, Instant)>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let paths = Paths::resolve().expect("cannot resolve storage paths");
        let config = storage::load_config(&paths);
        theme::apply(&cc.egui_ctx, config.theme);

        // slightly roomier default spacing for a premium feel
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(10.0, 6.0);
        cc.egui_ctx.set_style(style);

        let icon_tex = load_texture(&cc.egui_ctx);

        let screen = if storage::vault_exists(&paths) && config.initialized {
            Screen::Unlock
        } else {
            Screen::Setup
        };

        Self {
            paths,
            config,
            screen,
            icon_tex,
            key: None,
            vault: Vault::default(),
            pw_input: String::new(),
            pw_confirm: String::new(),
            status: String::new(),
            dialog: Dialog::None,
            search: String::new(),
            f_issuer: String::new(),
            f_account: String::new(),
            f_secret: String::new(),
            f_digits: 6,
            f_period: 30,
            f_algo: Algorithm::Sha1,
            f_smart: String::new(),
            f_status: String::new(),
            cp_new: String::new(),
            cp_confirm: String::new(),
            forgot_confirm: String::new(),
            reveal: None,
            copied_at: None,
        }
    }

    fn persist_vault(&mut self) {
        if let Some(key) = &self.key {
            if let Err(e) = storage::save_vault(&self.paths, key, &self.vault) {
                self.status = format!("Save error: {e}");
            }
        }
    }

    fn brand(&self, ui: &mut egui::Ui, subtitle: &str) {
        ui.horizontal(|ui| {
            ui.add(egui::Image::new(&self.icon_tex).fit_to_exact_size(Vec2::splat(34.0)));
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("monotp").size(22.0).strong());
                ui.label(RichText::new(subtitle).size(11.0).weak());
            });
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(400));
        egui::CentralPanel::default().show(ctx, |ui| match self.screen {
            Screen::Setup => self.ui_setup(ui),
            Screen::Unlock => self.ui_unlock(ui),
            Screen::Vault => self.ui_vault(ui),
        });
    }
}

impl App {
    // ---------- Setup ----------
    fn ui_setup(&mut self, ui: &mut egui::Ui) {
        ui.add_space(34.0);
        ui.vertical_centered(|ui| {
            ui.add(egui::Image::new(&self.icon_tex).fit_to_exact_size(Vec2::splat(72.0)));
            ui.add_space(10.0);
            ui.heading("Create your master password");
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Protected with Argon2id. It is never stored and cannot be recovered.",
                )
                .weak(),
            );
        });
        ui.add_space(22.0);
        centered_form(ui, 320.0, |ui, w| {
            ui.label("Master password");
            ui.add(egui::TextEdit::singleline(&mut self.pw_input).password(true).desired_width(w));
            ui.add_space(8.0);
            ui.label("Confirm password");
            ui.add(egui::TextEdit::singleline(&mut self.pw_confirm).password(true).desired_width(w));
            ui.add_space(14.0);
            if ui.add_sized(Vec2::new(w, 36.0), egui::Button::new(RichText::new("Create vault").strong())).clicked() {
                self.do_create();
            }
            status_line(ui, &self.status);
        });
    }

    fn do_create(&mut self) {
        if self.pw_input.len() < 8 {
            self.status = "Password must be at least 8 characters.".into();
            return;
        }
        if self.pw_input != self.pw_confirm {
            self.status = "Passwords do not match.".into();
            return;
        }
        let salt = crypto::random_salt();
        let key = match crypto::derive_key(&self.pw_input, &salt, self.config.kdf) {
            Ok(k) => k,
            Err(e) => {
                self.status = format!("Key derivation failed: {e}");
                return;
            }
        };
        self.config.salt_b64 = B64.encode(salt);
        self.config.initialized = true;
        self.vault = Vault::default();
        if let Err(e) = storage::save_vault(&self.paths, &key, &self.vault) {
            self.status = format!("Could not create vault: {e}");
            return;
        }
        let _ = storage::save_config(&self.paths, &self.config);
        self.key = Some(key);
        self.pw_input.clear();
        self.pw_confirm.clear();
        self.status.clear();
        self.screen = Screen::Vault;
    }

    // ---------- Unlock ----------
    fn ui_unlock(&mut self, ui: &mut egui::Ui) {
        ui.add_space(50.0);
        ui.vertical_centered(|ui| {
            ui.add(egui::Image::new(&self.icon_tex).fit_to_exact_size(Vec2::splat(72.0)));
            ui.add_space(10.0);
            ui.heading("Unlock vault");
        });
        ui.add_space(18.0);
        let mut submit = false;
        centered_form(ui, 320.0, |ui, w| {
            ui.label("Master password");
            let resp = ui.add(egui::TextEdit::singleline(&mut self.pw_input).password(true).desired_width(w));
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.add_space(12.0);
            if ui.add_sized(Vec2::new(w, 36.0), egui::Button::new(RichText::new("Unlock").strong())).clicked() || enter {
                submit = true;
            }
            ui.add_space(6.0);
            if ui.add(egui::Button::new(RichText::new("Forgot password?").size(12.0)).frame(false)).clicked() {
                self.dialog = Dialog::Forgot;
            }
            status_line(ui, &self.status);
        });
        if submit {
            self.do_unlock();
        }
        if self.dialog == Dialog::Forgot {
            self.ui_forgot(ui.ctx());
        }
    }

    fn do_unlock(&mut self) {
        let salt = match storage::salt_from_config(&self.config) {
            Ok(s) => s,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        let key = match crypto::derive_key(&self.pw_input, &salt, self.config.kdf) {
            Ok(k) => k,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        match storage::load_vault(&self.paths, &key) {
            Ok(v) => {
                self.vault = v;
                self.key = Some(key);
                self.pw_input.clear();
                self.status.clear();
                self.screen = Screen::Vault;
            }
            Err(_) => {
                self.status = "Wrong master password.".into();
                self.pw_input.clear();
            }
        }
    }

    // ---------- Vault ----------
    fn ui_vault(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            self.brand(ui, &format!("{} account(s)", self.vault.entries.len()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                egui::ComboBox::from_id_source("theme_combo")
                    .selected_text(self.config.theme.label())
                    .show_ui(ui, |ui| {
                        for t in ThemeKind::ALL {
                            if ui.selectable_label(self.config.theme == t, t.label()).clicked() {
                                self.config.theme = t;
                                theme::apply(ui.ctx(), t);
                                let _ = storage::save_config(&self.paths, &self.config);
                            }
                        }
                    });
            });
        });
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);

        // toolbar
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(RichText::new("+  Add account").strong())).clicked() {
                self.open_add();
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search…")
                    .desired_width(180.0),
            );
            if !self.search.is_empty() && ui.button("×").clicked() {
                self.search.clear();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button("Menu", |ui| {
                    if ui.button("Change master password").clicked() {
                        self.open_change_pw();
                        ui.close_menu();
                    }
                    let mut auto = self.config.autostart;
                    if ui.checkbox(&mut auto, "Start on login").changed() {
                        self.config.autostart = auto;
                        let _ = autostart::set_autostart(auto);
                        let _ = storage::save_config(&self.paths, &self.config);
                    }
                    ui.separator();
                    if ui.button("Lock vault").clicked() {
                        self.lock();
                        ui.close_menu();
                    }
                });
            });
        });
        ui.add_space(6.0);

        let now = totp::now_unix();
        let needle = self.search.to_lowercase();
        let mut to_delete: Option<usize> = None;

        let indices: Vec<usize> = (0..self.vault.entries.len())
            .filter(|&i| {
                if needle.is_empty() {
                    return true;
                }
                let e = &self.vault.entries[i];
                e.issuer.to_lowercase().contains(&needle)
                    || e.account.to_lowercase().contains(&needle)
            })
            .collect();

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if self.vault.entries.is_empty() {
                ui.add_space(50.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("No accounts yet").size(16.0).strong());
                    ui.add_space(4.0);
                    ui.label(RichText::new("Click \"+ Add account\" and paste an otpauth:// link\nor type a secret manually.").weak());
                });
            } else if indices.is_empty() {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("No matches").weak());
                });
            }

            for &idx in &indices {
                self.entry_card(ui, idx, now, &mut to_delete);
                ui.add_space(8.0);
            }
        });

        if let Some(idx) = to_delete {
            self.vault.entries.remove(idx);
            self.reveal = None;
            self.copied_at = None;
            self.persist_vault();
        }

        match self.dialog {
            Dialog::Add => self.ui_add(ui.ctx()),
            Dialog::Edit(i) => self.ui_edit(ui.ctx(), i),
            Dialog::ChangePw => self.ui_change_pw(ui.ctx()),
            _ => {}
        }
    }

    fn entry_card(&mut self, ui: &mut egui::Ui, idx: usize, now: u64, to_delete: &mut Option<usize>) {
        let (issuer, account, secret_str, code, remaining, period, valid) = {
            let e = &self.vault.entries[idx];
            let (code, valid) = match totp::decode_secret(&e.secret) {
                Some(k) => (totp::generate(&k, e.period, e.digits, e.algorithm, now), true),
                None => ("------".to_string(), false),
            };
            (
                e.issuer.clone(),
                e.account.clone(),
                e.secret.clone(),
                code,
                totp::seconds_remaining(e.period, now),
                e.period,
                valid,
            )
        };

        let revealed = self.reveal == Some(idx);
        let copied = matches!(self.copied_at, Some((i, t)) if i == idx && t.elapsed().as_secs_f32() < 1.6);

        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::symmetric(14.0, 12.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        let head = if issuer.is_empty() { account.clone() } else { issuer.clone() };
                        ui.label(RichText::new(head).size(15.0).strong());
                        if !issuer.is_empty() && !account.is_empty() {
                            ui.label(RichText::new(&account).size(12.0).weak());
                        }
                        ui.add_space(4.0);
                        ui.label(RichText::new(spaced_code(&code)).size(30.0).monospace().strong());
                        if revealed {
                            ui.label(RichText::new(&secret_str).size(11.0).monospace().weak());
                        }
                        if !valid {
                            ui.colored_label(Color32::from_rgb(210, 90, 90), "Invalid secret");
                        }
                    });

                    ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                        ui.add(countdown_ring(remaining, period));
                    });
                });

                // progress bar
                let frac = remaining as f32 / period.max(1) as f32;
                let bar_col = if remaining <= 5 {
                    Color32::from_rgb(210, 90, 90)
                } else {
                    ui.visuals().selection.stroke.color
                };
                ui.add(egui::ProgressBar::new(frac).desired_height(4.0).fill(bar_col));
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    let copy_label = if copied { "Copied!" } else { "Copy" };
                    if ui.button(copy_label).clicked() && valid {
                        let c = code.clone();
                        ui.output_mut(|o| o.copied_text = c);
                        self.copied_at = Some((idx, Instant::now()));
                    }
                    if ui.button(if revealed { "Hide" } else { "Reveal" }).clicked() {
                        self.reveal = if revealed { None } else { Some(idx) };
                    }
                    if ui.button("Edit").clicked() {
                        self.open_edit(idx);
                    }
                    if ui.button("Delete").clicked() {
                        *to_delete = Some(idx);
                    }
                });
            });
    }

    fn lock(&mut self) {
        self.key = None;
        self.vault = Vault::default();
        self.pw_input.clear();
        self.status.clear();
        self.dialog = Dialog::None;
        self.reveal = None;
        self.screen = Screen::Unlock;
    }

    // ---------- Add ----------
    fn open_add(&mut self) {
        self.reset_form();
        self.dialog = Dialog::Add;
    }

    fn ui_add(&mut self, ctx: &egui::Context) {
        let mut open = true;
        egui::Window::new("Add account")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_width(360.0);
                ui.label(RichText::new("Smart paste").strong());
                ui.label(RichText::new("Paste an otpauth:// link or a raw base32 secret — the rest is filled automatically.").size(11.0).weak());
                let resp = ui.add(
                    egui::TextEdit::multiline(&mut self.f_smart)
                        .hint_text("otpauth://totp/GitHub:me@example.com?secret=...")
                        .desired_rows(2)
                        .desired_width(340.0),
                );
                if resp.changed() {
                    self.try_autofill();
                }
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);

                self.form_fields(ui);

                // live preview
                ui.add_space(6.0);
                if let Some(k) = totp::decode_secret(&self.f_secret) {
                    let code = totp::generate(&k, self.f_period, self.f_digits, self.f_algo, totp::now_unix());
                    ui.label(RichText::new(format!("Preview:  {}", spaced_code(&code))).monospace().strong());
                } else if !self.f_secret.is_empty() {
                    ui.colored_label(Color32::from_rgb(210, 90, 90), "Secret is not valid base32");
                }

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Save").strong())).clicked() {
                        self.commit_add();
                    }
                    if ui.button("Cancel").clicked() {
                        self.dialog = Dialog::None;
                    }
                });
                if !self.f_status.is_empty() {
                    ui.add_space(4.0);
                    ui.colored_label(Color32::from_rgb(210, 90, 90), &self.f_status);
                }
            });
        if !open {
            self.dialog = Dialog::None;
        }
    }

    fn try_autofill(&mut self) {
        let text = self.f_smart.trim().to_string();
        if text.starts_with("otpauth://") {
            if let Some(e) = totp::parse_otpauth(&text) {
                self.f_issuer = e.issuer.clone();
                self.f_account = e.account.clone();
                self.f_secret = e.secret.clone();
                self.f_digits = e.digits;
                self.f_period = e.period;
                self.f_algo = e.algorithm;
                self.f_status = "Imported from link.".into();
            }
        } else if totp::decode_secret(&text).is_some() {
            self.f_secret = text;
        }
    }

    fn commit_add(&mut self) {
        if let Err(e) = self.validate_form() {
            self.f_status = e;
            return;
        }
        self.vault.entries.push(self.build_entry());
        self.persist_vault();
        self.dialog = Dialog::None;
    }

    // ---------- Edit ----------
    fn open_edit(&mut self, idx: usize) {
        let e = &self.vault.entries[idx];
        self.f_issuer = e.issuer.clone();
        self.f_account = e.account.clone();
        self.f_secret = e.secret.clone();
        self.f_digits = e.digits;
        self.f_period = e.period;
        self.f_algo = e.algorithm;
        self.f_smart.clear();
        self.f_status.clear();
        self.dialog = Dialog::Edit(idx);
    }

    fn ui_edit(&mut self, ctx: &egui::Context, idx: usize) {
        let mut open = true;
        egui::Window::new("Edit account")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_width(360.0);
                self.form_fields(ui);
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Save changes").strong())).clicked() {
                        if let Err(e) = self.validate_form() {
                            self.f_status = e;
                        } else if idx < self.vault.entries.len() {
                            self.vault.entries[idx] = self.build_entry();
                            self.persist_vault();
                            self.dialog = Dialog::None;
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.dialog = Dialog::None;
                    }
                });
                if !self.f_status.is_empty() {
                    ui.add_space(4.0);
                    ui.colored_label(Color32::from_rgb(210, 90, 90), &self.f_status);
                }
            });
        if !open {
            self.dialog = Dialog::None;
        }
    }

    // shared form fields
    fn form_fields(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("form_grid").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
            ui.label("Issuer");
            ui.add(egui::TextEdit::singleline(&mut self.f_issuer).hint_text("e.g. GitHub").desired_width(230.0));
            ui.end_row();
            ui.label("Account");
            ui.add(egui::TextEdit::singleline(&mut self.f_account).hint_text("e.g. me@example.com").desired_width(230.0));
            ui.end_row();
            ui.label("Secret");
            ui.add(egui::TextEdit::singleline(&mut self.f_secret).hint_text("base32").desired_width(230.0));
            ui.end_row();
            ui.label("Digits");
            ui.add(egui::DragValue::new(&mut self.f_digits).clamp_range(6..=8));
            ui.end_row();
            ui.label("Period (s)");
            ui.add(egui::DragValue::new(&mut self.f_period).clamp_range(15..=90));
            ui.end_row();
            ui.label("Algorithm");
            egui::ComboBox::from_id_source("algo_combo")
                .selected_text(self.f_algo.label())
                .show_ui(ui, |ui| {
                    for a in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
                        ui.selectable_value(&mut self.f_algo, a, a.label());
                    }
                });
            ui.end_row();
        });
    }

    fn validate_form(&self) -> Result<(), String> {
        if totp::decode_secret(&self.f_secret).is_none() {
            return Err("Invalid base32 secret.".into());
        }
        if self.f_account.trim().is_empty() && self.f_issuer.trim().is_empty() {
            return Err("Enter an issuer or account name.".into());
        }
        Ok(())
    }

    fn build_entry(&self) -> Entry {
        Entry {
            issuer: self.f_issuer.trim().to_string(),
            account: self.f_account.trim().to_string(),
            secret: self.f_secret.trim().to_string(),
            digits: self.f_digits,
            period: self.f_period,
            algorithm: self.f_algo,
        }
    }

    fn reset_form(&mut self) {
        self.f_issuer.clear();
        self.f_account.clear();
        self.f_secret.clear();
        self.f_smart.clear();
        self.f_status.clear();
        self.f_digits = 6;
        self.f_period = 30;
        self.f_algo = Algorithm::Sha1;
    }

    // ---------- Change password ----------
    fn open_change_pw(&mut self) {
        self.cp_new.clear();
        self.cp_confirm.clear();
        self.f_status.clear();
        self.dialog = Dialog::ChangePw;
    }

    fn ui_change_pw(&mut self, ctx: &egui::Context) {
        let mut open = true;
        egui::Window::new("Change master password")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_width(340.0);
                ui.label(RichText::new("Your vault is re-encrypted and overwritten with the new password.").size(11.0).weak());
                ui.add_space(8.0);
                ui.label("New password");
                ui.add(egui::TextEdit::singleline(&mut self.cp_new).password(true).desired_width(320.0));
                ui.add_space(6.0);
                ui.label("Confirm new password");
                ui.add(egui::TextEdit::singleline(&mut self.cp_confirm).password(true).desired_width(320.0));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Update password").strong())).clicked() {
                        self.do_change_pw();
                    }
                    if ui.button("Cancel").clicked() {
                        self.dialog = Dialog::None;
                    }
                });
                if !self.f_status.is_empty() {
                    ui.add_space(4.0);
                    ui.colored_label(Color32::from_rgb(210, 90, 90), &self.f_status);
                }
            });
        if !open {
            self.dialog = Dialog::None;
        }
    }

    fn do_change_pw(&mut self) {
        if self.cp_new.len() < 8 {
            self.f_status = "Password must be at least 8 characters.".into();
            return;
        }
        if self.cp_new != self.cp_confirm {
            self.f_status = "Passwords do not match.".into();
            return;
        }
        let salt = crypto::random_salt();
        let key = match crypto::derive_key(&self.cp_new, &salt, self.config.kdf) {
            Ok(k) => k,
            Err(e) => {
                self.f_status = e.to_string();
                return;
            }
        };
        if let Err(e) = storage::save_vault(&self.paths, &key, &self.vault) {
            self.f_status = format!("Failed: {e}");
            return;
        }
        self.config.salt_b64 = B64.encode(salt);
        let _ = storage::save_config(&self.paths, &self.config);
        self.key = Some(key);
        self.cp_new.clear();
        self.cp_confirm.clear();
        self.dialog = Dialog::None;
        self.status = "Master password updated.".into();
    }

    // ---------- Forgot password (wipe) ----------
    fn ui_forgot(&mut self, ctx: &egui::Context) {
        let mut open = true;
        egui::Window::new("Forgot password")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_width(360.0);
                ui.colored_label(
                    Color32::from_rgb(210, 90, 90),
                    RichText::new("Warning: this permanently erases ALL stored accounts.").strong(),
                );
                ui.add_space(6.0);
                ui.label("There is no recovery. Type DELETE to confirm, then set up a brand-new vault.");
                ui.add_space(8.0);
                ui.add(egui::TextEdit::singleline(&mut self.forgot_confirm).hint_text("Type DELETE").desired_width(340.0));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let enabled = self.forgot_confirm.trim() == "DELETE";
                    if ui.add_enabled(enabled, egui::Button::new(RichText::new("Erase & start over").strong())).clicked() {
                        self.do_forgot();
                    }
                    if ui.button("Cancel").clicked() {
                        self.forgot_confirm.clear();
                        self.dialog = Dialog::None;
                    }
                });
            });
        if !open {
            self.forgot_confirm.clear();
            self.dialog = Dialog::None;
        }
    }

    fn do_forgot(&mut self) {
        let _ = storage::delete_vault(&self.paths);
        self.config.initialized = false;
        self.config.salt_b64.clear();
        let _ = storage::save_config(&self.paths, &self.config);
        self.key = None;
        self.vault = Vault::default();
        self.forgot_confirm.clear();
        self.pw_input.clear();
        self.status.clear();
        self.dialog = Dialog::None;
        self.screen = Screen::Setup;
    }
}

// ---------- helpers ----------
fn load_texture(ctx: &egui::Context) -> egui::TextureHandle {
    let bytes = include_bytes!("../assets/icon.png");
    let (rgba, w, h) = match image::load_from_memory(bytes) {
        Ok(img) => {
            let img = img.into_rgba8();
            let (w, h) = img.dimensions();
            (img.into_raw(), w as usize, h as usize)
        }
        Err(_) => (vec![0, 0, 0, 255], 1, 1),
    };
    let color = egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba);
    ctx.load_texture("app_icon", color, egui::TextureOptions::LINEAR)
}

fn centered_form(ui: &mut egui::Ui, w: f32, add: impl FnOnce(&mut egui::Ui, f32)) {
    ui.vertical_centered(|ui| {
        ui.allocate_ui_with_layout(Vec2::new(w, 0.0), Layout::top_down(Align::Min), |ui| {
            add(ui, w);
        });
    });
}

fn status_line(ui: &mut egui::Ui, status: &str) {
    if !status.is_empty() {
        ui.add_space(8.0);
        ui.colored_label(Color32::from_rgb(210, 90, 90), status);
    }
}

fn spaced_code(code: &str) -> String {
    if !code.bytes().all(|b| b.is_ascii_digit()) {
        return code.to_string();
    }
    let n = code.len();
    let mid = n / 2 + n % 2;
    format!("{} {}", &code[..mid], &code[mid..])
}

fn countdown_ring(remaining: u64, period: u64) -> impl egui::Widget {
    move |ui: &mut egui::Ui| {
        let size = Vec2::splat(30.0);
        let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::hover());
        let color = ui.visuals().text_color();
        let painter = ui.painter();
        let center = rect.center();
        let radius = size.x / 2.0 - 2.0;
        let frac = remaining as f32 / period.max(1) as f32;

        painter.circle_stroke(center, radius, egui::Stroke::new(2.0, color.linear_multiply(0.22)));
        let n = 40usize;
        let end = (frac * n as f32).round() as usize;
        let mut pts = Vec::with_capacity(end + 1);
        for i in 0..=end {
            let a = -std::f32::consts::FRAC_PI_2 + (i as f32 / n as f32) * std::f32::consts::TAU;
            pts.push(center + Vec2::new(a.cos(), a.sin()) * radius);
        }
        if pts.len() >= 2 {
            painter.add(egui::Shape::line(pts, egui::Stroke::new(2.6, color)));
        }
        painter.text(
            center,
            egui::Align2::CENTER_CENTER,
            remaining.to_string(),
            egui::FontId::monospace(11.0),
            color,
        );
        resp
    }
}
