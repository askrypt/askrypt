// Global setup for all tests in this directory (Flutter discovers
// `flutter_test_config.dart` automatically and wraps every test with it).
//
// On device, `pbkdf2` (lib/crypto/kdf.dart) routes through `cryptography_flutter`
// to native platform crypto. Widget tests initialize the Flutter binding, which
// auto-registers that native path — but there's no native handler under
// `flutter_tester`, so a 600k-iteration derivation stalls on the dead platform
// channel. Force the pure-Dart `cryptography` implementation for tests instead;
// it produces byte-identical output (the golden vectors verify parity), so this
// only swaps *where* PBKDF2 runs, not its result.
import 'dart:async';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> testExecutable(FutureOr<void> Function() testMain) async {
  // Run after binding init so this wins over the plugin's auto-registration
  // (which `cryptography_flutter` performs during `ensureInitialized`).
  TestWidgetsFlutterBinding.ensureInitialized();
  Cryptography.instance = DartCryptography.defaultInstance;
  await testMain();
}
