/// Askrypt mobile entry point.
///
/// Phase 2 wires the pure-Dart crypto core (`lib/crypto`) into a Riverpod
/// session layer (`lib/session`). The feature-parity screens (welcome / unlock
/// / entry list / editors) arrive in Phase 3 — for now this is a thin shell
/// that simply reflects the session state so `flutter run` works end-to-end.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'session/vault_session.dart';

void main() => runApp(const ProviderScope(child: AskryptApp()));

class AskryptApp extends StatelessWidget {
  const AskryptApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Askrypt',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const _SessionGate(),
    );
  }
}

/// Placeholder router: locked -> welcome stub, unlocked -> entry-count stub.
/// Replaced by real screens in Phase 3.
class _SessionGate extends ConsumerWidget {
  const _SessionGate();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final session = ref.watch(vaultSessionProvider);
    final body = switch (session) {
      VaultLocked() => const Text('Locked — open or create a vault (Phase 3).'),
      VaultUnlocked(:final vault) =>
        Text('Unlocked — ${vault.entryCount} entries.'),
    };
    return Scaffold(
      appBar: AppBar(title: const Text('Askrypt')),
      body: Center(child: body),
    );
  }
}
