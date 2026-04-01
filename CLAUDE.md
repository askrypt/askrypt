# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Askrypt is a cross-platform desktop password manager written in Rust. It authenticates users via security question answers (normalized and hashed with PBKDF2) rather than a master password, using AES-256-CBC encryption for vault data.

**Warning**: The project is under active development and has not undergone extensive security testing.

## Architecture

### Source Files

- **`src/types.rs`** — Core data types: `SecretEntry`, `Params`, `QuestionsData`, `MasterData`, `AskryptFile`. Re-exported from `lib.rs`.
- **`src/lib.rs`** — Core library: encryption (AES-256-CBC), key derivation (PBKDF2/SHA-256), ZIP archive handling, and serialization. Contains 25+ unit tests. This is the heart of the security model.
- **`src/main.rs`** — Desktop GUI using the [Iced](https://github.com/iced-rs/iced) framework. Follows Iced's Elm-like architecture: `Message` enum for events, `update()` for state transitions, `view()` for rendering. Also handles auto-lock and Smart Lock logic. The Edit Questions screen includes a "Use transliteration" checkbox that enables Russian/Ukrainian transliteration for answer normalization.
- **`src/ui.rs`** — Reusable styled UI components and theming helpers.
- **`src/icon.rs`** — Bootstrap icon glyph constants for use in the UI.
- **`src/passgen.rs`** — Password generator with configurable character sets and length.
- **`src/settings.rs`** — Persistent user settings stored as JSON in platform config directories: `%APPDATA%\askrypt\` (Windows), `~/Library/Application Support/askrypt/` (macOS), `~/.config/askrypt/` (Linux).
- **`src/translit.rs`** — Russian/Ukrainian-to-English transliteration using BGN/PCGN romanization, QWERTY-only output. ё→yo, е→e, ъ/ь dropped, тс and ц both→ts. Ukrainian: ґ→g, є→ye, і→i, ї→yi.

### Security / Encryption Model

1. User provides answers to security questions.
2. Answers are normalized (lowercased, whitespace/dashes stripped, optionally transliterated from Russian/Ukrainian via `Params.translit`).
3. Each answer is used with PBKDF2 (600,000 iterations by default) to derive a key.
4. A layered encryption scheme: first answer unlocks subsequent questions, all answers together unlock the master key, the master key encrypts the actual secrets.
5. Vault files are ZIP archives containing JSON metadata and encrypted blobs. See `SPEC.md` for the full format specification.

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `iced` | Cross-platform GUI (Elm-style) |
| `aes` + `cbc` + `cipher` | AES-256-CBC encryption |
| `pbkdf2` + `sha2` | Key derivation |
| `serde` + `serde_json` | Serialization |
| `zip` | Vault file format (ZIP archive) |
| `rfd` | Native file open/save dialogs |
| `rand` | Random number generation |

### CI / Release

- `.github/workflows/ci.yml` — Builds and tests on Ubuntu for every push.
- `.github/workflows/release.yml` — Multi-platform release builds (Linux x86_64, macOS ARM64, Windows x86_64 MSVC).
- Windows builds use static C runtime linking (configured in `.cargo/config.toml`).
- `build.rs` embeds the Windows icon resource.
