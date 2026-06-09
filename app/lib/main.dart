/// Askrypt mobile entry point.
///
/// Pure-Dart crypto core (`lib/crypto`) → Riverpod session layer
/// (`lib/session`) → feature-parity screens (`lib/screens`). The app shell and
/// routing live in `app.dart`.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app.dart';

// PBKDF2 is routed to native, hardware-accelerated platform crypto: merely
// depending on `cryptography_flutter` auto-registers it as `Cryptography.instance`
// (see `lib/crypto/kdf.dart`), so no explicit enable call is needed here.
void main() => runApp(const ProviderScope(child: AskryptApp()));
