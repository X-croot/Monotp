use crate::crypto::{self, KdfParams, MasterKey};
use crate::theme::ThemeKind;
use crate::totp::Algorithm;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

/// A single TOTP account. The secret is zeroized when the entry is dropped.
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

/// Persistent, non-secret settings kept in config.toml.
#[derive(Serialize, Deserialize)]
pub struct Config {
    pub theme: ThemeKind,
    pub salt_b64: String,
    pub autostart: bool,
    #[serde(default)]
    pub initialized: bool,
    // NOTE: keep table-typed fields LAST — the `toml` serializer requires
    // all scalar values to be emitted before any nested table.
    pub kdf: KdfParams,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            theme: ThemeKind::System,
            salt_b64: String::new(),
            autostart: false,
            initialized: false,
            kdf: KdfParams::default(),
        }
    }
}

/// Resolves the platform-specific config & data directories.
/// Linux:   ~/.config/monotp  &  ~/.local/share/monotp
/// Windows: %APPDATA%\X-croot\monotp\config  &  ...\data
/// macOS:   ~/Library/Application Support/com.X-croot.monotp
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        let dirs = ProjectDirs::from("com", "X-croot", "monotp")
            .ok_or_else(|| anyhow!("cannot resolve platform directories"))?;
        let config_dir = dirs.config_dir().to_path_buf();
        let data_dir = dirs.data_dir().to_path_buf();
        fs::create_dir_all(&config_dir)?;
        fs::create_dir_all(&data_dir)?;
        Ok(Paths {
            config_dir,
            data_dir,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn vault_file(&self) -> PathBuf {
        self.data_dir.join("vault.enc")
    }
}

pub fn load_config(paths: &Paths) -> Config {
    let path = paths.config_file();
    if let Ok(text) = fs::read_to_string(&path) {
        if let Ok(cfg) = toml::from_str::<Config>(&text) {
            return cfg;
        }
    }
    Config::default()
}

pub fn save_config(paths: &Paths, cfg: &Config) -> Result<()> {
    let text = toml::to_string_pretty(cfg)?;
    fs::write(paths.config_file(), text)?;
    Ok(())
}

pub fn vault_exists(paths: &Paths) -> bool {
    paths.vault_file().exists()
}

/// Permanently removes the encrypted vault (used by "Forgot password").
pub fn delete_vault(paths: &Paths) -> Result<()> {
    let p = paths.vault_file();
    if p.exists() {
        fs::remove_file(p)?;
    }
    Ok(())
}

pub fn salt_from_config(cfg: &Config) -> Result<Vec<u8>> {
    B64.decode(cfg.salt_b64.as_bytes())
        .map_err(|_| anyhow!("invalid salt in config"))
}

/// Encrypts the vault with the master key and writes it to disk.
pub fn save_vault(paths: &Paths, key: &MasterKey, vault: &Vault) -> Result<()> {
    let mut plaintext = serde_json::to_vec(vault)?;
    let encrypted = crypto::encrypt(key, &plaintext)?;
    plaintext.zeroize();
    fs::write(paths.vault_file(), encrypted)?;
    Ok(())
}

/// Reads and decrypts the vault from disk.
pub fn load_vault(paths: &Paths, key: &MasterKey) -> Result<Vault> {
    let data = fs::read(paths.vault_file())?;
    let mut plaintext = crypto::decrypt(key, &data)?;
    let vault: Vault = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(vault)
}
