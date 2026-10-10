/// Welcome / landing screen (locked state): reopen a recently used vault, open
/// an existing vault (on the device or in Askrypt Cloud), create a new one, or
/// use the standalone password generator.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app.dart';
import '../platform/recent_vault_store.dart';
import '../platform/vault_io.dart';
import '../session/cloud_session.dart';
import '../session/vault_home.dart';
import 'cloud_screen.dart';
import 'password_generator_screen.dart';
import 'questions_editor_screen.dart';
import 'settings_screen.dart';
import 'unlock_screen.dart';

class WelcomeScreen extends ConsumerStatefulWidget {
  const WelcomeScreen({super.key});

  @override
  ConsumerState<WelcomeScreen> createState() => _WelcomeScreenState();
}

class _WelcomeScreenState extends ConsumerState<WelcomeScreen> {
  /// A remembered cloud vault is being downloaded.
  bool _opening = false;

  Future<void> _open() async {
    final io = ref.read(vaultIoProvider);
    final picked = await io.pickVault();
    if (picked == null || !mounted) return;
    _unlock(picked);
  }

  void _unlock(PickedVault vault) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) =>
            UnlockScreen(bytes: vault.bytes, home: LocalHome(vault.name)),
      ),
    );
  }

  void _openRecent(RecentVault recent) {
    switch (recent) {
      case RecentLocal(:final vault):
        _unlock(vault);
      case RecentCloud cloud:
        _openRecentCloud(cloud);
    }
  }

  /// Download the latest version of a remembered cloud vault. Without a
  /// session for that server and account, go to the cloud screen to sign in.
  Future<void> _openRecentCloud(RecentCloud recent) async {
    if (_opening) return;
    setState(() => _opening = true);
    try {
      await ref.read(cloudProvider.notifier).ready;
      if (!mounted) return;
      final cloud = ref.read(cloudProvider);
      if (cloud is! CloudSignedIn ||
          !cloud.serves(recent.baseUrl, recent.email)) {
        _cloud(context);
        return;
      }
      final error = await openCloudVault(context, ref, cloud,
          id: recent.id, name: recent.name);
      if (error != null && mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(error)));
      }
    } finally {
      if (mounted) setState(() => _opening = false);
    }
  }

  /// Long-press on a recent vault: offer to drop it from the list. The vault
  /// itself (file or cloud copy) is untouched.
  Future<void> _confirmForget(RecentVault recent) async {
    final remove = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Remove from recent?'),
        content: Text('${recent.name} will no longer be listed here. '
            'The vault itself is not deleted.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (remove != true || !mounted) return;
    try {
      await ref.read(recentVaultStoreProvider).forget(recent);
    } catch (_) {}
    if (mounted) ref.invalidate(recentVaultProvider);
  }

  Widget _recentButton(RecentVault recent, {required bool primary}) {
    final icon =
        Icon(recent is RecentCloud ? Icons.cloud_outlined : Icons.history);
    final label = Text('Open ${recent.name}', overflow: TextOverflow.ellipsis);
    final onPressed = _opening ? null : () => _openRecent(recent);
    final button = primary
        ? FilledButton.icon(onPressed: onPressed, icon: icon, label: label)
        : OutlinedButton.icon(onPressed: onPressed, icon: icon, label: label);
    final tooltip = recent is RecentCloud ? recent.email : null;
    final pressable = GestureDetector(
      onLongPress: _opening ? null : () => _confirmForget(recent),
      child: button,
    );
    return tooltip == null
        ? pressable
        : Tooltip(message: tooltip, child: pressable);
  }

  void _cloud(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => const CloudScreen()),
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

  void _settings(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => const SettingsScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    // Recently opened vaults, newest first (empty while loading or when
    // nothing was remembered yet).
    final recent = ref.watch(recentVaultProvider).value ?? const [];
    return Scaffold(
      appBar: AppBar(
        actions: [
          IconButton(
            tooltip: 'Settings',
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => _settings(context),
          ),
        ],
      ),
      body: Center(
        child: SingleChildScrollView(
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
                  for (final (i, vault) in recent.indexed) ...[
                    _recentButton(vault, primary: i == 0),
                    SizedBox(height: i == recent.length - 1 ? 12 : 8),
                  ],
                  FilledButton.icon(
                    onPressed: _open,
                    icon: const Icon(Icons.folder_open),
                    label: const Text('Open vault (file)'),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.tonalIcon(
                    onPressed: () => _cloud(context),
                    icon: const Icon(Icons.cloud_outlined),
                    label: const Text('Askrypt Cloud'),
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
      ),
    );
  }
}
