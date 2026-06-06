# Askrypt Mobile — Implementation Plan

Mobile app (Android + iOS) living in this repo under `app/`, reusing the existing
Rust crypto core. **One repository covers both platforms.**

## Stack decision

- **Shared Rust core, reused on both platforms** — never reimplement the vault
  crypto in Kotlin/Swift; that would risk format incompatibilities. The core is
  already platform-agnostic (`core/`, lib name `askrypt`).
- **UI: Flutter** (single Dart codebase for Android + iOS).
- **Rust↔Dart binding: flutter_rust_bridge (FRB) v2.** All logic stays in Rust;
  Dart only renders.
- Native autofill shells (Phase 5) use platform code (Kotlin/Swift) over the
  same Rust core via JNI / xcframework.

## Target repo layout

```
askrypt/
├── Cargo.toml                 # [workspace] members = ["core", "app/rust"]
├── core/                      # askrypt-core (lib name `askrypt`): crypto, types,
│   └── src/{lib,types,translit,passgen}.rs   # translit, passgen — pure, no I/O
├── src/                       # desktop Iced app -> depends on askrypt-core
├── app/
│   ├── PLAN.md                # this file
│   ├── rust/                  # FRB bridge crate (askrypt-mobile)
│   │   └── src/{lib,api}.rs
│   ├── lib/                   # Flutter/Dart UI (Phase 2+)
│   │   ├── src/rust/          # FRB-generated Dart bindings
│   │   ├── screens/ state/ platform/
│   ├── android/  ios/         # Flutter shells (+ autofill later)
│   └── pubspec.yaml
└── SPEC.md
```

## Core/session API design (already built in `app/rust/src/api.rs`)

Mirrors the desktop flow (keep questions + all answers + decrypted entries in
memory; re-`create` the `AskryptFile` on every save). Secrets/answers/master key
never leave Rust; Dart gets only render data and must call `reveal_secret` to
see a single secret. Sensitive state is zeroized on drop.

- `create_vault(questions, answers, entries, iterations?, translit) -> bytes`
- `load_vault(bytes) -> LoadedVault`
- `LoadedVault::{question0, translit, iterations, remaining_questions(first_answer), unlock(answers)}`
- `UnlockedVault::{list_entries (no secret), reveal_secret(i), add_entry, update_entry, delete_entry, set_hidden, to_bytes}`
- `generate_password(options) -> String`

## Operations to reach feature parity (from desktop `Message` enum)

Open/create vault, edit questions (+ transliteration toggle), layered unlock,
entry CRUD, search/filter, tags, hidden entries, show/copy secret & username,
open URL, password generator, auto-lock on inactivity, Smart Lock.

Mobile additions: biometric unlock (successor to Smart Lock), auto-clearing
clipboard, **autofill** (Android Autofill Framework / iOS Credential Provider).

## Phases & status

- **Phase 0 — Extract shared core. ✅ DONE (committed `mobile-core-extraction`).**
  - `core/` crate `askrypt-core`, `[lib] name = "askrypt"` so `use askrypt::`
    and all doctests stay unchanged. `passgen` moved into core.
  - Repo is a Cargo workspace; desktop drops crypto-only deps.
  - Added `AskryptFile::to_bytes()` / `from_bytes()` (in-memory ZIP);
    `save_to_file`/`load_from_file` delegate. Round-trip + garbage-input tests.
  - Gate met: `cargo test` green (42 unit + 7 doctests), desktop builds, clippy clean.

- **Phase 1 — Rust FRB bridge crate (`app/rust`, `askrypt-mobile`). ✅ DONE (uncommitted at time of writing → being committed).**
  - `crate-type = ["cdylib", "staticlib", "lib"]`; deps `flutter_rust_bridge`,
    `zeroize`, `askrypt-core`.
  - Session API above with `#[frb(opaque)]` handles; zeroize on drop.
  - `unexpected_cfgs` check-cfg for `frb_expand` to stay warning-clean.
  - Gate met: 4 bridge tests green; workspace clippy clean.
  - NOTE: `mod frb_generated;` is intentionally commented out in `lib.rs` until
    Phase 2 codegen runs (it needs the Flutter project + matching FRB version).

- **Phase 2 — Flutter skeleton + codegen.** `flutter create app`; wire
  `flutter_rust_bridge_codegen` → `app/lib/src/rust/`; uncomment
  `mod frb_generated;`; align FRB runtime/codegen versions (`cargo update`).
  Build core for devices: Android via `cargo-ndk` (arm64-v8a, armeabi-v7a,
  x86_64 → jniLibs); iOS `aarch64-apple-ios` + sim → xcframework.
  Gate: call `generate_password` from Dart on real Android + iOS.

- **Phase 3 — Feature-parity screens (MVP).** Welcome/open/create (file picker:
  SAF / document picker), layered unlock, entries list + search/tags/hidden,
  entry view/edit CRUD, show/copy secret & username, open URL, edit questions
  (+ translit checkbox), password generator, auto-lock on inactivity/background.
  State via Riverpod. Gate: vault created on mobile opens on desktop & vice-versa.

- **Phase 4 — Mobile-native security.** Biometric unlock (`local_auth`) backed by
  Keychain/Keystore (successor to Smart Lock); auto-clearing clipboard (mark
  sensitive on Android 13+); `flutter_secure_storage`.

- **Phase 5 — Autofill (largest native piece, last).** Android Autofill Service
  (Kotlin) + iOS AutoFill Credential Provider extension (Swift), both over the
  shared Rust core.

- **Phase 6 — CI/CD.** Extend `.github/workflows`: build Rust for all mobile
  targets, Flutter build/test, signed AAB (Play) + IPA (TestFlight); macOS runner
  for iOS.

## Open decisions (not blocking)

- Bump vault `version` when the format must diverge (core currently hard-rejects
  anything `!= "0.9"`).
- Cloud sync model (iCloud/Drive vs OS document providers vs explicit sync).
- PBKDF2 600k iterations may be slow on low-end phones — measure; consider
  progress UI or adaptive count at creation time.

## Verification commands

```
cargo test --workspace      # all crates
cargo clippy --workspace --all-targets
cargo build -p askrypt      # desktop still works
```
