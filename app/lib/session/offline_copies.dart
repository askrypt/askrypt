/// The offline-copies preference and store (Riverpod), the mobile twin of
/// desktop's `offline_copies` setting and `src/offline.rs`.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../platform/offline_copy_store.dart';
import 'leak_check.dart';
import 'vault_home.dart';

/// Where copies live. Overridden in tests.
final offlineCopyStoreProvider =
    Provider<OfflineCopyStore>((ref) => FileOfflineCopyStore());

/// Whether cloud vaults are kept for offline use. On until the stored
/// preference says otherwise.
class OfflineCopiesNotifier extends Notifier<bool> {
  /// Completes once the stored preference (if any) has been read back, so a
  /// copy is never written in the moment before "off" is known.
  late Future<void> ready;

  @override
  bool build() {
    ready = _load();
    return true;
  }

  Future<void> _load() async {
    try {
      final stored =
          await ref.read(preferencesStoreProvider).loadOfflineCopies();
      if (stored != null && ref.mounted) state = stored;
    } catch (e) {
      debugPrint('Could not read the offline-copies preference: $e');
    }
  }

  /// Switch copies on or off. Off deletes the ones already kept: nothing
  /// would offer them, and they are copies of the user's vaults. Throws when
  /// they could not be deleted (the preference is still saved).
  Future<void> set(bool value) async {
    state = value;
    try {
      await ref.read(preferencesStoreProvider).saveOfflineCopies(value);
    } catch (e) {
      debugPrint('Could not save the offline-copies preference: $e');
    }
    if (!value) await ref.read(offlineCopyStoreProvider).clearAll();
  }

  /// Whether copies are on, once the preference is known.
  Future<bool> enabled() async {
    await ready;
    return state;
  }
}

final offlineCopiesEnabledProvider =
    NotifierProvider<OfflineCopiesNotifier, bool>(OfflineCopiesNotifier.new);

OfflineLocation offlineLocationOf(CloudHome home) =>
    OfflineLocation(baseUrl: home.baseUrl, email: home.email, id: home.id);

/// Keep [bytes] — exactly what the server holds at `home.etag` — as the
/// offline copy of [home]. Fire-and-forget: a failure is only logged.
void keepOfflineCopy(WidgetRef ref, CloudHome home, Uint8List bytes) {
  if (home.etag.isEmpty) return; // A copy no save could be checked against.
  final notifier = ref.read(offlineCopiesEnabledProvider.notifier);
  final store = ref.read(offlineCopyStoreProvider);
  unawaited(() async {
    try {
      if (!await notifier.enabled()) return;
      await store.keep(offlineLocationOf(home), home.name, bytes, home.etag);
    } catch (e) {
      debugPrint('Could not keep an offline copy: $e');
    }
  }());
}

/// The copy kept for [home], when copies are on.
Future<OfflineCopy?> loadOfflineCopy(WidgetRef ref, CloudHome home) async {
  try {
    if (!await ref.read(offlineCopiesEnabledProvider.notifier).enabled()) {
      return null;
    }
    return await ref.read(offlineCopyStoreProvider).load(offlineLocationOf(home));
  } catch (e) {
    debugPrint('Could not read an offline copy: $e');
    return null;
  }
}

/// Forget the copy of a vault the server says is gone. Best effort.
void removeOfflineCopy(WidgetRef ref, CloudHome home) {
  unawaited(ref
      .read(offlineCopyStoreProvider)
      .remove(offlineLocationOf(home))
      .catchError((Object e) => debugPrint('Could not remove a copy: $e')));
}
