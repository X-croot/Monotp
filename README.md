<h1 align="center">monotp</h1>

<p align="center">
  <b>Minimal, fully-encrypted, cross-platform TOTP authenticator written in Rust.</b>
</p>

<p align="center">
  <img alt="language" src="https://img.shields.io/badge/language-Rust-000000?style=flat-square&logo=rust">
  <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-000000?style=flat-square">
  <img alt="ui" src="https://img.shields.io/badge/UI-egui%20(cross--platform)-000000?style=flat-square">
  <img alt="crypto" src="https://img.shields.io/badge/KDF-Argon2id-000000?style=flat-square">
  <img alt="cipher" src="https://img.shields.io/badge/cipher-XChaCha20--Poly1305-000000?style=flat-square">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-000000?style=flat-square">
</p>

---

## About

**monotp** is a clean, black-and-white TOTP (Time-based One-Time Password) authenticator.
It stores every account secret **fully encrypted** on disk, protected by a **master password**
that is stretched with **Argon2id**. Secrets live only briefly in memory and are **zeroized**
the moment they are no longer needed. One binary, no telemetry, no cloud.

Built by [**X-croot**](https://github.com/X-croot).

## Features

- **RFC 6238 TOTP** — SHA1 / SHA256 / SHA512, 6–8 digits, configurable period.
- **Full encryption at rest** — vault sealed with **XChaCha20-Poly1305** (AEAD).
- **Argon2id master key** — memory-hard key derivation (~64 MiB, tunable).
- **Zeroize everywhere** — master key and plaintext secrets are wiped from RAM on drop/lock.
- **Smart paste** — drop an `otpauth://` link *or* a raw base32 secret; issuer, account, digits, period and algorithm are auto-filled. Naming an entry anything you like never breaks code generation.
- **Live search** — instantly filter accounts by issuer or name.
- **Add / edit / delete** — full account management with a live code **preview** while adding.
- **Reveal / copy** — one-click copy with confirmation, plus per-entry secret reveal.
- **Two ways to reset your password:**
  - **Change master password** — the vault is decrypted in memory, then re-encrypted and **overwritten** with the new password. Your accounts stay intact.
  - **Forgot password** — a guarded, type-`DELETE` wipe that erases everything and lets you set up a fresh vault (there is no recovery — by design).
- **Real black & white app icon** — bundled as the window/taskbar icon *and* compiled straight into the Windows `.exe` via `build.rs`.
- **Platform-native storage** — each OS keeps data in its own conventional directory:
  - Linux: `~/.config/monotp/config.toml` + `~/.local/share/monotp/vault.enc`
  - Windows: `%APPDATA%\X-croot\monotp\config\` + `...\data\`
  - macOS: `~/Library/Application Support/com.X-croot.monotp/`
- **Themes** — `System`, `Dark`, `Light`, `Sakura`, and a pure `Monochrome` (black & white) theme.
- **Copy-to-clipboard** with a live countdown ring and a shrinking progress bar.
- **Autostart on login** — one toggle, handled per OS (Linux `.desktop`, Windows `Run` registry key).
- **Config as TOML** — human-readable, portable settings file.

## Themes

| Theme | Description |
|-------|-------------|
| System | Follows the OS light/dark preference |
| Dark | Deep neutral dark |
| Light | Clean light |
| Sakura | Soft cherry-blossom pink |
| Monochrome | Pure black & white, high contrast |

## Build

Requires the [Rust toolchain](https://rustup.rs/).

```bash
# Debug run
cargo run

# Optimized release build
cargo build --release
# Binary: target/release/monotp   (monotp.exe on Windows)
```

### Cross-compiling for Windows from Linux
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

1. On first launch, create a **master password** (min. 8 characters). This seals your vault — it is **never stored** and **cannot be recovered**.
2. Click **+ Add account**, then either paste an `otpauth://` URI or fill in the fields manually (issuer, account, base32 secret).
3. Codes refresh automatically; click **Copy** to place the current code on your clipboard.
4. Use **Lock** to wipe secrets from memory; unlock again with your master password.

## Security notes

- The master password is stretched with **Argon2id** using a random 16-byte salt (stored in `config.toml`).
- The derived 256-bit key never touches disk; only the **encrypted** vault (`vault.enc`) is persisted.
- Encryption uses **XChaCha20-Poly1305** with a fresh random 24-byte nonce per save.
- Sensitive buffers implement `Zeroize`/`Drop` so they are cleared from memory deterministically.
- There is **no backdoor and no recovery**: lose the master password and the vault is unrecoverable — by design.

## Tech stack

`Rust` · `eframe/egui` (cross-platform GUI) · `argon2` · `chacha20poly1305` · `zeroize` · `directories` · `serde`/`toml` · `hmac`/`sha1`/`sha2` · `data-encoding`

## License

MIT © [X-croot](https://github.com/X-croot)
