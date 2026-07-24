use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub m_cost: u32, // KiB
    pub t_cost: u32, // iterations
    pub p_cost: u32, // parallelism
}

impl Default for KdfParams {
    fn default() -> Self {
        // Strong, interactive-friendly Argon2id defaults (~64 MiB).
        KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// A derived symmetric key that is automatically zeroized on drop.
pub struct MasterKey {
    bytes: [u8; KEY_LEN],
}

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// Derive a 256-bit key from the master password using Argon2id.
pub fn derive_key(password: &str, salt: &[u8], params: KdfParams) -> Result<MasterKey> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;

    Ok(MasterKey { bytes: key })
}

/// Encrypt plaintext, returning nonce || ciphertext.
pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data laid out as nonce || ciphertext.
pub fn decrypt(key: &MasterKey, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return Err(anyhow!("ciphertext too short"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decryption failed (wrong master password or corrupted vault)"))
}
