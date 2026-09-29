/// App settings. Today one section — Security — holding the switch for the
/// leaked-password warning (desktop Settings → Security has the same one).
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../session/leak_check.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: Text('Security',
                style: theme.textTheme.titleSmall
                    ?.copyWith(color: theme.colorScheme.primary)),
          ),
          SwitchListTile(
            value: ref.watch(leakCheckEnabledProvider),
            onChanged: (v) =>
                ref.read(leakCheckEnabledProvider.notifier).set(v),
            title: const Text('Warn about leaked passwords'),
            subtitle: const Text(
                'Checks item passwords against known breaches; only '
                '5 characters of a hash leave this device.'),
          ),
        ],
      ),
    );
  }
}
