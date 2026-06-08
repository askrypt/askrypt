/// Auto-clearing clipboard for secrets. Copies via [PlatformSecurity] (so the
/// content is flagged sensitive on platforms that support it) and schedules a
/// best-effort wipe after [kClipboardClearTimeout]. The wipe only fires if the
/// clipboard *still holds the value we put there* — we never clobber something
/// the user copied afterwards.
///
/// Abstracted so screens depend on the interface and tests can fake it without
/// touching real platform channels.
library;

import 'dart:async';

import 'package:flutter/services.dart';

import 'platform_security.dart';

/// How long a copied secret lingers on the clipboard before auto-clearing.
const Duration kClipboardClearTimeout = Duration(seconds: 30);

abstract class SecureClipboard {
  /// Copy [text] (flagged sensitive) and arm the auto-clear timer.
  Future<void> copy(String text);

  /// Cancel the timer and clear immediately if our value is still present
  /// (called on vault lock).
  Future<void> clearNow();
}

/// Production implementation: native sensitive-copy + a Dart fallback timer that
/// guarantees uniform clearing even on OS versions without expiring clipboards.
class TimedSecureClipboard implements SecureClipboard {
  TimedSecureClipboard(this._security,
      {this.timeout = kClipboardClearTimeout});

  final PlatformSecurity _security;
  final Duration timeout;

  Timer? _timer;
  String? _pending; // the value we last placed, or null if nothing of ours.

  @override
  Future<void> copy(String text) async {
    await _security.copySensitive(text);
    _pending = text;
    _timer?.cancel();
    _timer = Timer(timeout, _clearIfOurs);
  }

  @override
  Future<void> clearNow() async {
    _timer?.cancel();
    await _clearIfOurs();
  }

  Future<void> _clearIfOurs() async {
    final pending = _pending;
    _pending = null;
    if (pending == null) return;
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text == pending) {
      await Clipboard.setData(const ClipboardData(text: ''));
    }
  }
}
