use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Sha1
    }
}

impl Algorithm {
    pub fn label(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

/// Decode a user-provided base32 secret (spaces / lowercase tolerated).
pub fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    BASE32_NOPAD.decode(cleaned.as_bytes()).ok()
}

fn hotp(key: &[u8], counter: u64, digits: u32, algo: Algorithm) -> u32 {
    let counter_bytes = counter.to_be_bytes();
    let hash = match algo {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("hmac key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("hmac key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(hash[offset]) & 0x7f) << 24)
        | ((u32::from(hash[offset + 1]) & 0xff) << 16)
        | ((u32::from(hash[offset + 2]) & 0xff) << 8)
        | (u32::from(hash[offset + 3]) & 0xff);

    binary % 10u32.pow(digits)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Generate the current TOTP code as a zero-padded string.
pub fn generate(key: &[u8], period: u64, digits: u32, algo: Algorithm, unix_time: u64) -> String {
    let counter = unix_time / period.max(1);
    let code = hotp(key, counter, digits, algo);
    format!("{:0width$}", code, width = digits as usize)
}

/// Seconds remaining until the current code rotates.
pub fn seconds_remaining(period: u64, unix_time: u64) -> u64 {
    let p = period.max(1);
    p - (unix_time % p)
}

/// Parse an otpauth:// URI (from a QR code / manual import).
pub fn parse_otpauth(uri: &str) -> Option<crate::storage::Entry> {
    let rest = uri.strip_prefix("otpauth://totp/")?;
    let (label_part, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };

    let label = url_decode(label_part);
    let (mut issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let mut secret = String::new();
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut algo = Algorithm::Sha1;

    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let v = url_decode(v);
            match k {
                "secret" => secret = v,
                "issuer" => {
                    if issuer.is_empty() {
                        issuer = v;
                    }
                }
                "digits" => digits = v.parse().unwrap_or(6),
                "period" => period = v.parse().unwrap_or(30),
                "algorithm" => {
                    algo = match v.to_ascii_uppercase().as_str() {
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => Algorithm::Sha1,
                    }
                }
                _ => {}
            }
        }
    }

    if secret.is_empty() {
        return None;
    }

    Some(crate::storage::Entry {
        issuer,
        account,
        secret,
        digits,
        period,
        algorithm: algo,
    })
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = hex_val(bytes[i + 1]);
                let l = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
