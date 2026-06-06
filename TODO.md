# TODO — Prerequisites before Phase 2 (Flutter mobile app)

See `app/PLAN.md` for the full plan and phase status. Phase 0 and Phase 1 are
done and committed. This file lists what must be set up **before starting Phase 2**.

## Environment status (checked 2026-06-06)
- `rustup` ✅, Java 21 ✅
- Missing: Flutter SDK, Android SDK/NDK, `cargo-ndk`, `flutter_rust_bridge_codegen`, Rust Android targets
- **This machine is Linux → build/run Android here. iOS needs macOS + Xcode (do on a Mac or macOS CI runner).**

## 0. Decide a few values first
- [ ] **App ID / package**: e.g. `com.askrypt.app` (Android `applicationId` + iOS bundle id). Hard to change later.
- [ ] **Display name**: e.g. "Askrypt".
- [ ] **Min Android SDK**: API 26 (Android 8) recommended — required by the Autofill Framework in Phase 5.
- [ ] **Platform scope**: Android on this Linux box; iOS deferred to a Mac/CI.

## 1. Install Flutter SDK
```
git clone https://github.com/flutter/flutter.git -b stable ~/flutter
fish_add_path ~/flutter/bin        # fish; persists the PATH entry
flutter --version
```
(Or `snap install flutter --classic`.)

## 2. Install the Android toolchain
Easiest: **Android Studio** (bundles SDK + platform-tools + emulator).
Then in *Settings → SDK Manager → SDK Tools* tick **NDK (Side by side)** and **CMake**.
Set env vars (fish):
```
set -Ux ANDROID_HOME $HOME/Android/Sdk
set -Ux ANDROID_NDK_HOME $HOME/Android/Sdk/ndk/(ls $HOME/Android/Sdk/ndk | tail -1)
fish_add_path $ANDROID_HOME/platform-tools
```
CLI-only alternative: install `cmdline-tools`, then
`sdkmanager "platform-tools" "platforms;android-34" "ndk;27.1.12297006" "cmake;3.22.1"`.

## 3. Accept licenses & verify (interactive — run with `!` prefix in the prompt)
```
! flutter doctor --android-licenses
! flutter doctor
```
Resolve anything `flutter doctor` flags before continuing.

## 4. Add Rust Android targets
```
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
```

## 5. Install build/codegen tools (version-matched!)
```
cargo install cargo-ndk
cargo install flutter_rust_bridge_codegen --version 2.12.0   # MUST match the pinned runtime in app/rust/Cargo.toml
```

## 6. Set up a target to run on
- Create an emulator (Android Studio → Device Manager), **or** plug in a phone with USB debugging.
- Verify: `flutter devices`.

## Done when
- [ ] `flutter doctor` is green
- [ ] `flutter devices` lists a device/emulator
- [ ] `cargo-ndk` and `flutter_rust_bridge_codegen 2.12.0` installed
- [ ] Android Rust targets added

## Then Phase 2
`flutter create` into `app/` → wire `flutter_rust_bridge_codegen` to generate Dart bindings →
uncomment `mod frb_generated;` in `app/rust/src/lib.rs` → build core with `cargo-ndk` into `jniLibs`
→ smoke-test `generate_password` from Dart on the device.

## iOS (later, on macOS only)
Xcode + CocoaPods, `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`,
build an xcframework. Not possible on this Linux machine.
