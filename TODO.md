# TODO — Mobile prerequisites (pure-Dart Flutter app)

See `app/PLAN.md` for the full plan and phase status. The mobile app is a
**pure Flutter/Dart** application — **no Rust on device, no flutter_rust_bridge,
no NDK, no cargo-ndk, no Rust mobile targets**. The Rust core stays the desktop
engine and the spec/test-vector source of truth only.

## Phase 1 status (crypto core + parity vectors) — ✅ DONE
- ✅ Rust golden-vector generator: `core/examples/gen_vectors.rs`
      → `app/test/fixtures/vectors.json` (regenerate with
      `cargo run -p askrypt-core --example gen_vectors`).
- ✅ Dart crypto core: `app/lib/crypto/{translit,normalize,kdf,aes,
      secret_entry,vault}.dart`.
- ✅ Dart parity tests: `app/test/crypto_parity_test.dart` — **7/7 green**,
      `flutter analyze` clean.
- ✅ Interop verified both ways (`core/examples/open_vault.rs` +
      `app/tool/make_vault.dart`).

## Environment status (checked 2026-06-07)
- `rustup` ✅, Java 21 ✅, **Flutter 3.44.1 ✅ at `/home/ruslan/Apps/flutter`**
  (`fish_add_path /home/ruslan/Apps/flutter/bin` to make it permanent).
- Still missing (only needed from Phase 2 for on-device Android builds, NOT for
  tests): Android SDK/platform-tools/emulator. No NDK or Rust targets required.
- This machine is Linux → develop/run Android here. iOS needs macOS + Xcode.

## Run the Phase 1 gate again
```
cd app
flutter pub get
flutter test            # 7/7 expected
```

## Android toolchain (needed from Phase 2 for on-device builds, NOT for tests)
Easiest: **Android Studio** (bundles SDK + platform-tools + emulator).
No NDK/CMake needed (pure Dart — no native compilation). Then:
```
set -Ux ANDROID_HOME $HOME/Android/Sdk
fish_add_path $ANDROID_HOME/platform-tools
! flutter doctor --android-licenses   # interactive: run with `!` prefix
! flutter doctor
```

## 3. Decide a few values (before Phase 2 `flutter create`)
- [ ] **App ID / package**: e.g. `com.askrypt.app` (hard to change later).
- [ ] **Display name**: e.g. "Askrypt".
- [ ] **Min Android SDK**: API 26 (Android 8) — required by the Autofill
      Framework in Phase 5.

## Phase 2 entry
`flutter create --platforms=android,ios .` inside `app/` (preserves existing
`lib/` and `test/`), `flutter pub get`, then build the session/state layer on top
of `lib/crypto`. No codegen, no native build step.

## iOS (later, on macOS only)
Xcode + CocoaPods. No Rust targets / xcframework needed (pure Dart).
