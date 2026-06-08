/// App shell: theme, the locked/unlocked session gate, and auto-lock.
///
/// The top-level [MaterialApp.home] is driven directly by [vaultSessionProvider]:
/// locked shows the [WelcomeScreen] tree, unlocked shows the [EntriesScreen]
/// tree. Because `home` is swapped wholesale on every lock/unlock transition,
/// any pushed sub-routes (unlock, editors…) are torn down automatically when
/// the vault locks — there is no decrypted screen left mounted behind a lock.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
// StateProvider lives in the legacy export as of Riverpod 3.
import 'package:flutter_riverpod/legacy.dart';

import 'platform/biometric_store.dart';
import 'platform/platform_security.dart';
import 'platform/secure_clipboard.dart';
import 'platform/vault_io.dart';
import 'screens/auto_lock.dart';
import 'screens/entries_screen.dart';
import 'screens/welcome_screen.dart';
import 'session/vault_session.dart';

/// Storage backend for picking/saving vault files. Overridden in tests.
final vaultIoProvider = Provider<VaultIo>((ref) => const FilePickerVaultIo());

/// Native security affordances (FLAG_SECURE, sensitive clipboard). Overridden
/// in tests.
final platformSecurityProvider =
    Provider<PlatformSecurity>((ref) => const MethodChannelPlatformSecurity());

/// Auto-clearing clipboard for secrets. Overridden in tests.
final secureClipboardProvider = Provider<SecureClipboard>(
    (ref) => TimedSecureClipboard(ref.watch(platformSecurityProvider)));

/// Biometric quick-unlock store (answers-only). Overridden in tests.
final biometricStoreProvider =
    Provider<BiometricStore>((ref) => LocalAuthBiometricStore());

/// Suggested file name for the next save, set when a vault is opened/created.
final vaultFileNameProvider = StateProvider<String>((ref) => 'vault.askrypt');

/// The first question (plaintext) of the currently-open vault, used as the
/// biometric-credential key. Set on unlock; null when no vault tracked.
final currentQuestion0Provider = StateProvider<String?>((ref) => null);

class AskryptApp extends StatelessWidget {
  const AskryptApp({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(seedColor: Colors.indigo);
    return MaterialApp(
      title: 'Askrypt',
      theme: ThemeData(colorScheme: scheme, useMaterial3: true),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.indigo,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const AutoLock(child: _SessionGate()),
    );
  }
}

/// Routes the app between the locked and unlocked trees. Each tree gets its own
/// nested [Navigator] keyed by session state: when the vault locks or unlocks,
/// the whole subtree (including any pushed sub-routes — editors, unlock, …) is
/// torn down and rebuilt from its root. This is why a `lock()` from deep inside
/// the unlocked tree lands cleanly back on the welcome screen, and why
/// `createNew`/`open` from the locked tree drops straight onto the entries list.
class _SessionGate extends ConsumerWidget {
  const _SessionGate();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final session = ref.watch(vaultSessionProvider);
    return switch (session) {
      VaultLocked() => _tree(const ValueKey('locked'), const WelcomeScreen()),
      VaultUnlocked() =>
        _tree(const ValueKey('unlocked'), const EntriesScreen()),
    };
  }

  Widget _tree(Key key, Widget root) => Navigator(
        key: key,
        onGenerateRoute: (_) =>
            MaterialPageRoute<void>(builder: (_) => root),
      );
}
