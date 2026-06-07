/// Welcome / landing screen (locked state): open an existing vault, create a
/// new one, or use the standalone password generator.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app.dart';
import 'password_generator_screen.dart';
import 'questions_editor_screen.dart';
import 'unlock_screen.dart';

class WelcomeScreen extends ConsumerWidget {
  const WelcomeScreen({super.key});

  Future<void> _open(BuildContext context, WidgetRef ref) async {
    final io = ref.read(vaultIoProvider);
    final picked = await io.pickVault();
    if (picked == null || !context.mounted) return;
    ref.read(vaultFileNameProvider.notifier).state = picked.name;
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => UnlockScreen(bytes: picked.bytes, fileName: picked.name),
      ),
    );
  }

  void _create(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => const QuestionsEditorScreen.create(),
      ),
    );
  }

  void _passgen(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => const PasswordGeneratorScreen(),
      ),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.lock_outline,
                    size: 72, color: theme.colorScheme.primary),
                const SizedBox(height: 16),
                Text('Askrypt',
                    textAlign: TextAlign.center,
                    style: theme.textTheme.headlineMedium),
                const SizedBox(height: 4),
                Text('Security-question password manager',
                    textAlign: TextAlign.center,
                    style: theme.textTheme.bodyMedium
                        ?.copyWith(color: theme.colorScheme.outline)),
                const SizedBox(height: 32),
                FilledButton.icon(
                  onPressed: () => _open(context, ref),
                  icon: const Icon(Icons.folder_open),
                  label: const Text('Open vault'),
                ),
                const SizedBox(height: 12),
                FilledButton.tonalIcon(
                  onPressed: () => _create(context),
                  icon: const Icon(Icons.add),
                  label: const Text('Create new vault'),
                ),
                const SizedBox(height: 12),
                TextButton.icon(
                  onPressed: () => _passgen(context),
                  icon: const Icon(Icons.password),
                  label: const Text('Password generator'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
