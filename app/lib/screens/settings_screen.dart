/// App settings: Security — the leaked-password warning (desktop Settings →
/// Security) — and Askrypt Cloud — offline copies (desktop Settings → Backup).
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../session/leak_check.dart';
import '../session/offline_copies.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    Widget heading(String text) => Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
          child: Text(text,
              style: theme.textTheme.titleSmall
                  ?.copyWith(color: theme.colorScheme.primary)),
        );
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        children: [
          heading('Security'),
          SwitchListTile(
            value: ref.watch(leakCheckEnabledProvider),
            onChanged: (v) =>
                ref.read(leakCheckEnabledProvider.notifier).set(v),
            title: const Text('Warn about leaked passwords'),
            subtitle: const Text(
                'Checks item passwords against known breaches; only '
                '5 characters of a hash leave this device.'),
          ),
          heading('Askrypt Cloud'),
          SwitchListTile(
            value: ref.watch(offlineCopiesEnabledProvider),
            onChanged: (v) => _setOfflineCopies(context, ref, v),
            title: const Text('Keep offline copies of cloud vaults'),
            subtitle: const Text(
                'Every cloud vault you open or save is kept, encrypted, on '
                'this device, so it can be opened when the server is '
                'unreachable.'),
          ),
        ],
      ),
    );
  }

  Future<void> _setOfflineCopies(
      BuildContext context, WidgetRef ref, bool value) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      await ref.read(offlineCopiesEnabledProvider.notifier).set(value);
    } catch (e) {
      messenger.showSnackBar(
          SnackBar(content: Text('Could not delete the offline copies — $e')));
    }
  }
}
