/// Unit tests for [TimedSecureClipboard]: the auto-clear timer fires only when
/// our value is still on the clipboard, and [clearNow] wipes a pending value.
///
/// Uses a short timeout and a mocked platform clipboard channel; the fake
/// [PlatformSecurity] writes copies through the same channel so the
/// "still ours?" check sees them.
library;

import 'package:askrypt/platform/platform_security.dart';
import 'package:askrypt/platform/secure_clipboard.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class ClipboardWritingSecurity implements PlatformSecurity {
  @override
  Future<void> setSecureFlag(bool secure) async {}

  @override
  Future<void> copySensitive(String text) =>
      Clipboard.setData(ClipboardData(text: text));
}

void main() {
  final binding = TestWidgetsFlutterBinding.ensureInitialized();

  String? clipboard;

  setUp(() {
    clipboard = null;
    binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      switch (call.method) {
        case 'Clipboard.setData':
          clipboard = (call.arguments as Map)['text'] as String?;
          return null;
        case 'Clipboard.getData':
          return <String, dynamic>{'text': clipboard};
      }
      return null;
    });
  });

  tearDown(() {
    binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });

  const timeout = Duration(milliseconds: 30);
  SecureClipboard make() =>
      TimedSecureClipboard(ClipboardWritingSecurity(), timeout: timeout);

  test('auto-clears our value after the timeout', () async {
    final clip = make();
    await clip.copy('s3cr3t');
    expect(clipboard, 's3cr3t');
    await Future<void>.delayed(timeout * 3);
    expect(clipboard, '');
  });

  test('does not clobber a value the user copied afterwards', () async {
    final clip = make();
    await clip.copy('s3cr3t');
    // Simulate the user copying something else before the timer fires.
    clipboard = 'user-copied-this';
    await Future<void>.delayed(timeout * 3);
    expect(clipboard, 'user-copied-this');
  });

  test('clearNow wipes a pending value immediately', () async {
    final clip = make();
    await clip.copy('s3cr3t');
    await clip.clearNow();
    expect(clipboard, '');
  });
}
