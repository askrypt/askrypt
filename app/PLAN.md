# Askrypt Mobile — Implementation Plan

Mobile app (Android + iOS) living in this repo under `app/`, implemented as a
**pure Flutter/Dart application** that re-implements the vault crypto in Dart.
**One repository, one Flutter codebase, covers both platforms.**

## Stack decision

- **Pure Dart crypto — no Rust on device, no native bridge.** The vault format
  uses only standard, interoperable primitives (PBKDF2-HMAC-SHA256, AES-256-CBC
  + PKCS7, SHA-256, base64, ZIP, JSON). All of it is re-implemented in Dart so
  there is **no `flutter_rust_bridge`, no cargo cross-compilation, no NDK,
  no xcframework, no native `.so`/`.a` artifacts**.
- **UI + logic: Flutter** (single Dart codebase for Android + iOS).
- **The Rust core stays the source of truth for the *format spec* and for the
  desktop app.** The Dart implementation must produce/consume byte-identical
  `vault.askrypt` files. Parity is guaranteed by a shared cross-implementation
  **test-vector suite** (see Phase 1) — not by sharing code.
- Native autofill shells (Phase 5) use platform code (Kotlin/Swift); the
  credential lookup they need is small and is bridged from Dart (platform
  channels) rather than reimplementing crypto a third time.

### Accepted trade-offs vs. the Rust-bridge approach

- **(−) Two implementations of security-critical code** (Rust desktop + Dart
  mobile) must be kept in lock-step. Mitigated by the test-vector suite run in
  both languages' CI — they cannot silently diverge.
- **(−) Secrets live in the Dart/GC heap.** Unlike the Rust core, Dart cannot
  zeroize memory or keep plaintext out of the managed heap. We minimize lifetime
  (decrypt-on-demand, clear references on lock) but cannot match Rust's
  guarantee. Documented limitation, acceptable for v1.
- **(−) Exact input-shaping parity is fiddly** — normalization + Russian/Ukrainian
  transliteration must match Rust byte-for-byte (see "Parity hazards").
- **(+) Vastly simpler build + CI** — standard Flutter toolchain only.
- **(+) Hot reload everywhere; smaller app; no Rust toolchain for contributors.**

## Target repo layout

```
askrypt/
├── Cargo.toml                 # [workspace] members = ["core"]  (desktop only)
├── core/                      # askrypt-core (lib name `askrypt`): crypto, types,
│   └── src/{lib,types,translit,passgen}.rs   # SOURCE OF TRUTH for the spec
│                              #   + exports test vectors for Dart parity tests
├── src/                       # desktop Iced app -> depends on askrypt-core
├── app/                       # Flutter project (`flutter create`)
│   ├── PLAN.md                # this file
│   ├── pubspec.yaml
│   ├── lib/
│   │   ├── main.dart
│   │   ├── crypto/            # PURE-DART CORE (mirrors core/src/*.rs)
│   │   │   ├── vault.dart         # AskryptFile: load/create/to-bytes (ZIP+JSON)
│   │   │   ├── kdf.dart           # PBKDF2-HMAC-SHA256, sha256-hex helper
│   │   │   ├── aes.dart           # AES-256-CBC + PKCS7 encrypt/decrypt
│   │   │   ├── normalize.dart     # answer normalization
│   │   │   └── translit.dart      # BGN/PCGN Russian/Ukrainian -> ASCII
│   │   ├── session/          # in-memory unlocked-vault state (Riverpod)
│   │   ├── screens/          # welcome, unlock, list, entry, questions, passgen
│   │   └── platform/         # biometrics, clipboard, file picker, autofill bridge
│   ├── test/                 # Dart unit + parity (test-vector) tests
│   ├── android/  ios/        # Flutter shells (+ autofill extensions later)
│   └── integration_test/
└── SPEC.md
```

## Dart crypto core — what to port (from `core/src/lib.rs` + `SPEC.md`)

Derivation chain per layer (must match exactly):

1. **Normalize** each answer: remove all whitespace + every dash variant
   (`-`, `–`, `—`), lowercase, then optionally transliterate
   (`normalize_answer`, `lib.rs:563`).
2. **Hash**: `sha256(normalizedAnswer + saltB64)` returned as a **64-char
   lowercase hex string** (`sha256`, `lib.rs:596`).
3. **Derive**: `PBKDF2-HMAC-SHA256(secret = that hex *string* bytes,
   salt = raw salt bytes, iterations = 600000 default, dkLen = 32)`
   (`calc_pbkdf2`, `lib.rs:530`).
4. **Encrypt** the layer: AES-256-CBC, IV = the layer's salt bytes, PKCS7.
5. **Layering** (`SPEC.md` "Algorithm"): first answer → unlocks `qs`
   (remaining questions); all answers combined → unlocks `master`
   (`masterKey` + `iv`); `masterKey`+`iv` → unlocks `data` (entry list).
6. **Container**: `vault.askrypt` is a ZIP holding `askrypt.json` (+ future
   attachments). JSON fields per `SPEC.md` File Structure.

Suggested Dart packages: **`pointycastle`** (PBKDF2 + AES-CBC + SHA256),
**`archive`** (ZIP), `dart:convert` (base64/JSON), `dart:math`
`Random.secure()` (salt/IV/masterKey generation).

### Parity hazards (the bugs that silently break interop)

- **PBKDF2 secret is the hex *string*, not the 32 raw digest bytes.** Pass the
  64-char ASCII hex string's bytes, or vaults won't open.
- **Normalization + transliteration must be byte-identical** to `normalize_answer`
  and `src/translit.rs` (ё→yo, е→e, ъ/ь dropped, тс and ц both→ts; Ukrainian
  ґ→g, є→ye, і→i, ї→yi; QWERTY-only output). Verify Dart Unicode lowercasing and
  whitespace classification match Rust's `char::is_whitespace`/`to_lowercase`.
- **IV = salt bytes** for each layer (not a separate random IV except where the
  format stores one, e.g. master `iv`).

## Operations to reach feature parity (from desktop `Message` enum)

Open/create vault, edit questions (+ transliteration toggle), layered unlock,
entry CRUD, search/filter, tags, hidden entries, show/copy secret & username,
open URL, password generator, auto-lock on inactivity, Smart Lock.

Mobile additions: biometric unlock (successor to Smart Lock), auto-clearing
clipboard, **autofill** (Android Autofill Framework / iOS Credential Provider).

## Phases & status

- **Phase 0 — Extract shared core. ✅ DONE (committed `mobile-core-extraction`).**
  - `core/` crate `askrypt-core`, `[lib] name = "askrypt"`. `passgen` in core.
  - Cargo workspace; `AskryptFile::to_bytes()`/`from_bytes()` (in-memory ZIP).
  - Still required: the Rust core remains the desktop app's engine **and** the
    spec source-of-truth + test-vector generator for the Dart port.
  - Gate met: `cargo test` green, desktop builds, clippy clean.

- **Phase 1 — Cross-impl test vectors + Dart crypto core. ✅ DONE.**
  *(supersedes the old FRB bridge phase — the `app/rust/` crate was removed and
  dropped from the workspace.)*
  - Rust golden-vector generator `core/examples/gen_vectors.rs` →
    `app/test/fixtures/vectors.json` (normalize, transliterate, sha256, pbkdf2,
    aes-cbc, + a full known-good `vault.askrypt`).
  - Dart crypto core `app/lib/crypto/{translit,normalize,kdf,aes,
    secret_entry,vault}.dart` (pointycastle + archive). Mirrors `core/src`.
    Note: `aes.dart` avoids pointycastle's `process()` (broken for empty input)
    with an explicit block loop.
  - Dart parity tests `app/test/crypto_parity_test.dart` assert byte/value
    equality per stage, open the Rust-produced vault, and round-trip a
    Dart-created vault.
  - **Interop verified both directions** via `core/examples/open_vault.rs` +
    `app/tool/make_vault.dart`: Rust opens a Dart-created vault and vice-versa.
  - Gate met: `cd app && flutter test` → 7/7 green; `flutter analyze` clean.
    (Flutter SDK installed at `/home/ruslan/Apps/flutter`.)

- **Phase 2 — Flutter skeleton. ✅ DONE.**
  - `flutter create --platforms=android,ios --org com.askrypt .` scaffolded the
    Android + iOS shells (preserving `lib/crypto` + `test/`). App ID set to
    **`com.askrypt.app`**, display name **"Askrypt"**, **`minSdk 26`** (Autofill
    Framework floor for Phase 5). The `android/`+`ios/` folders are now tracked
    in git (they carry that native config; Phase 5 adds native code there).
  - Deps added: `flutter_riverpod`, `file_picker` (alongside Phase 1
    `pointycastle` + `archive`).
  - Session/state layer wired on top of `lib/crypto`:
    - `lib/session/unlocked_vault.dart` — `UnlockedVault`: open/create, secret-
      free `EntrySummary` list, reveal-on-demand, CRUD, `toBytes()`. Mirrors the
      desktop save model exactly (every save re-creates the whole file via
      `AskryptFile.create`, rotating salts + master key).
    - `lib/session/vault_session.dart` — Riverpod `NotifierProvider` exposing a
      sealed `VaultSession` (`VaultLocked` / `VaultUnlocked`); the rest of the
      app watches this instead of touching crypto directly.
    - `lib/main.dart` — `ProviderScope` shell that reflects session state
      (real screens are Phase 3).
  - No native code, no codegen.
  - Gate met: `flutter test` → **14/14** (7 parity + 7 session: create→unlock
    →edit→save cycle entirely in Dart), `flutter analyze` clean.

- **Phase 3 — Feature-parity screens (MVP).** Welcome/open/create (file picker:
  SAF / document picker), layered unlock, entries list + search/tags/hidden,
  entry view/edit CRUD, show/copy secret & username, open URL, edit questions
  (+ translit checkbox), password generator (port `passgen` logic to Dart),
  auto-lock on inactivity/background. State via Riverpod.
  Gate: vault created on mobile opens on desktop & vice-versa (real devices).

- **Phase 4 — Mobile-native security.** Biometric unlock (`local_auth`) backed by
  Keychain/Keystore (successor to Smart Lock); auto-clearing clipboard (mark
  sensitive on Android 13+); `flutter_secure_storage` for any cached unlock
  material. Minimize plaintext lifetime in the Dart heap; clear on lock/background.

- **Phase 5 — Autofill (largest native piece, last).** Android Autofill Service
  (Kotlin) + iOS AutoFill Credential Provider extension (Swift). These run in
  separate processes from the Flutter UI; resolve crypto via a small **platform
  channel into the Dart engine** (preferred) or, if a headless Flutter engine in
  the extension proves impractical, a minimal Kotlin/Swift port limited to
  unlock+lookup. Decide during this phase.

- **Phase 6 — CI/CD.** Extend `.github/workflows`: run the **Dart parity test
  suite against committed golden vectors** (catches Rust/Dart drift), Flutter
  build/test, signed AAB (Play) + IPA (TestFlight); macOS runner for iOS.
  No Rust mobile-target builds needed.

## Open decisions (not blocking)

- Bump vault `version` when the format must diverge (core currently hard-rejects
  anything `!= "0.9"`). Any change must land in **both** Rust and Dart + vectors.
- Cloud sync model (iCloud/Drive vs OS document providers vs explicit sync).
- PBKDF2 600k iterations may be slow on low-end phones — measure the Dart
  (`pointycastle`) implementation specifically, which is slower than Rust;
  consider progress UI, isolate-based derivation, or adaptive count at creation.
- Autofill crypto strategy (Dart platform channel vs minimal native port) — see
  Phase 5.

## Verification commands

```
# Desktop / spec source-of-truth (unchanged)
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p askrypt

# Mobile (Flutter)
cd app && flutter test            # unit + parity (golden vector) tests
cd app && flutter test integration_test
cd app && flutter analyze
```
