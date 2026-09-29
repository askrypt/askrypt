/// The leak-check preference and the lookup client (Riverpod), the mobile twin
/// of desktop's `check_leaks` setting and `src/leak.rs`.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../platform/preferences_store.dart';
import '../platform/pwned_client.dart';
import 'cloud_session.dart';

/// Device preferences. Overridden in tests.
final preferencesStoreProvider =
    Provider<PreferencesStore>((ref) => SecurePreferencesStore());

/// The breach lookup, over the shared HTTP transport (so tests fake both).
final pwnedClientProvider =
    Provider<PwnedClient>((ref) => PwnedClient(ref.watch(httpClientProvider)));

/// Whether the entry editor's Secret field warns about leaked passwords. On
/// until the stored preference says otherwise.
class LeakCheckNotifier extends Notifier<bool> {
  @override
  bool build() {
    _load();
    return true;
  }

  Future<void> _load() async {
    try {
      final stored = await ref.read(preferencesStoreProvider).loadCheckLeaks();
      if (stored != null && ref.mounted) state = stored;
    } catch (e) {
      // Unreadable storage keeps the default rather than failing the screen.
      debugPrint('Could not read the leak-check preference: $e');
    }
  }

  Future<void> set(bool value) async {
    state = value;
    try {
      await ref.read(preferencesStoreProvider).saveCheckLeaks(value);
    } catch (e) {
      debugPrint('Could not save the leak-check preference: $e');
    }
  }
}

final leakCheckEnabledProvider =
    NotifierProvider<LeakCheckNotifier, bool>(LeakCheckNotifier.new);
