/// Askrypt mobile entry point.
///
/// Pure-Dart crypto core (`lib/crypto`) → Riverpod session layer
/// (`lib/session`) → feature-parity screens (`lib/screens`). The app shell and
/// routing live in `app.dart`.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app.dart';

void main() => runApp(const ProviderScope(child: AskryptApp()));
