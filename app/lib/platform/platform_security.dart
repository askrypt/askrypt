/// Platform-security seam — a thin wrapper over the native `askrypt/secure`
/// [MethodChannel] for the two things Flutter can't do from Dart alone:
///   • toggle the secure-window flag (Android `FLAG_SECURE`: blocks screenshots
///     and the recents/overview thumbnail while a vault is unlocked);
///   • copy text to the clipboard *marked sensitive* (Android 13+
///     `ClipDescription.EXTRA_IS_SENSITIVE`; iOS `UIPasteboard` expiring item).
///
/// Abstracted (like `VaultIo`) so screens depend on the interface and tests can
/// fake it. The real implementation degrades to a no-op if the platform side
/// isn't wired (e.g. unit tests on the VM, or older OS versions).
library;

import 'package:flutter/services.dart';

/// Seam over native security affordances.
abstract class PlatformSecurity {
  /// Block/allow screen capture for the app window. No-op where unsupported.
  Future<void> setSecureFlag(bool secure);

  /// Copy [text] to the system clipboard flagged as sensitive content.
  Future<void> copySensitive(String text);
}

/// Production implementation backed by the `askrypt/secure` method channel.
/// Implemented natively in `MainActivity.kt` (Android) and `AppDelegate.swift`
/// (iOS); calls are swallowed if the channel is missing so the app still runs
/// in environments without the native side (tests, desktop).
class MethodChannelPlatformSecurity implements PlatformSecurity {
  const MethodChannelPlatformSecurity();

  static const _channel = MethodChannel('askrypt/secure');

  @override
  Future<void> setSecureFlag(bool secure) async {
    try {
      await _channel.invokeMethod<void>('setSecureFlag', {'secure': secure});
    } on MissingPluginException {
      // Native side not present (tests / unsupported platform) — ignore.
    } on PlatformException {
      // Best-effort hardening; never block the UI on failure.
    }
  }

  @override
  Future<void> copySensitive(String text) async {
    try {
      await _channel.invokeMethod<void>('copySensitive', {'text': text});
    } on MissingPluginException {
      // Fall back to a plain clipboard write so copy still works everywhere.
      await Clipboard.setData(ClipboardData(text: text));
    } on PlatformException {
      await Clipboard.setData(ClipboardData(text: text));
    }
  }
}
