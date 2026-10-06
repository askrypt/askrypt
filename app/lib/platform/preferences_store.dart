/// App preferences that are not secrets but still belong to this device —
/// whether item passwords are checked against known breaches (desktop's
/// `check_leaks`) and whether cloud vaults are kept for offline use (desktop's
/// `offline_copies`).
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

  /// Whether offline copies of cloud vaults are kept, or `null` when never
  /// set (default: on).
  Future<bool?> loadOfflineCopies();

  Future<void> saveOfflineCopies(bool value);
}

class SecurePreferencesStore implements PreferencesStore {
  SecurePreferencesStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  static const _checkLeaksKey = 'check_leaks';
  static const _offlineCopiesKey = 'offline_copies';

  Future<bool?> _loadBool(String key) async {
    final raw = await _storage.read(key: key);
    return switch (raw) {
      'true' => true,
      'false' => false,
      _ => null,
    };
  }

  @override
  Future<bool?> loadCheckLeaks() => _loadBool(_checkLeaksKey);

  @override
  Future<void> saveCheckLeaks(bool value) =>
      _storage.write(key: _checkLeaksKey, value: '$value');

  @override
  Future<bool?> loadOfflineCopies() => _loadBool(_offlineCopiesKey);

  @override
  Future<void> saveOfflineCopies(bool value) =>
      _storage.write(key: _offlineCopiesKey, value: '$value');
}
