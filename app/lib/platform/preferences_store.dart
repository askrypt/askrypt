/// App preferences that are not secrets but still belong to this device —
/// today only whether item passwords are checked against known breaches
/// (desktop's `check_leaks`).
///
/// Kept in [FlutterSecureStorage] beside the server address, so the app needs
/// no second storage plugin. A seam (like `ServerSessionStore`) so tests fake
/// it instead of touching platform storage.
library;

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

abstract class PreferencesStore {
  /// Whether the leak check is on, or `null` when never set (default: on).
  Future<bool?> loadCheckLeaks();

  Future<void> saveCheckLeaks(bool value);
}

class SecurePreferencesStore implements PreferencesStore {
  SecurePreferencesStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  static const _checkLeaksKey = 'check_leaks';

  @override
  Future<bool?> loadCheckLeaks() async {
    final raw = await _storage.read(key: _checkLeaksKey);
    return switch (raw) {
      'true' => true,
      'false' => false,
      _ => null,
    };
  }

  @override
  Future<void> saveCheckLeaks(bool value) =>
      _storage.write(key: _checkLeaksKey, value: '$value');
}
