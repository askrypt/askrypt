/// Biometric quick-unlock store (PLAN Phase 4, "answers-only" decision).
///
/// Persists the *security answers* for a vault behind a biometric prompt, so a
/// returning user re-picks the file (always fresh bytes — no stale vault, no
/// stored copy of the encrypted vault) and unlocks with a fingerprint/Face ID
/// instead of re-typing. We store the raw answers, not a derived key, because
/// every save rotates the vault's salts + master key — only the answers survive.
///
/// Answers are written to OS-keystore/Keychain-backed [FlutterSecureStorage],
/// keyed by `sha256(question0)` so the plaintext question is never a storage
/// key, and so one device can hold credentials for more than one vault.
///
/// Abstracted (like `VaultIo`) so tests fake it instead of touching real
/// biometrics or secure storage.
library;

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

import '../crypto/kdf.dart';

abstract class BiometricStore {
  /// Whether the device can perform a biometric check at all.
  Future<bool> canUse();

  /// Whether answers are stored for the vault identified by [question0].
  Future<bool> hasCredentialFor(String question0);

  /// Prompt for biometrics, then persist [answers] for [question0].
  /// Returns `false` (and stores nothing) if the prompt is cancelled/fails.
  Future<bool> save(String question0, List<String> answers);

  /// Prompt for biometrics, then return the stored answers for [question0],
  /// or `null` if absent or the prompt is cancelled/fails.
  Future<List<String>?> reveal(String question0);

  /// Drop the stored answers for [question0] (e.g. after a stale-credential
  /// unlock failure, or when the user disables biometric unlock).
  Future<void> forget(String question0);
}

/// Production implementation backed by `local_auth` + `flutter_secure_storage`.
class LocalAuthBiometricStore implements BiometricStore {
  LocalAuthBiometricStore({
    LocalAuthentication? auth,
    FlutterSecureStorage? storage,
  })  : _auth = auth ?? LocalAuthentication(),
        _storage = storage ?? const FlutterSecureStorage();

  final LocalAuthentication _auth;
  final FlutterSecureStorage _storage;

  static const _reason = 'Unlock your Askrypt vault';

  String _key(String question0) => 'answers_${sha256Hex(question0, '')}';

  @override
  Future<bool> canUse() async {
    try {
      return await _auth.isDeviceSupported() &&
          await _auth.canCheckBiometrics;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<bool> hasCredentialFor(String question0) =>
      _storage.containsKey(key: _key(question0));

  @override
  Future<bool> save(String question0, List<String> answers) async {
    if (!await _authenticate()) return false;
    await _storage.write(key: _key(question0), value: jsonEncode(answers));
    return true;
  }

  @override
  Future<List<String>?> reveal(String question0) async {
    if (!await hasCredentialFor(question0)) return null;
    if (!await _authenticate()) return null;
    final raw = await _storage.read(key: _key(question0));
    if (raw == null) return null;
    final decoded = jsonDecode(raw) as List<dynamic>;
    return decoded.cast<String>();
  }

  @override
  Future<void> forget(String question0) =>
      _storage.delete(key: _key(question0));

  Future<bool> _authenticate() async {
    try {
      return await _auth.authenticate(
        localizedReason: _reason,
        options: const AuthenticationOptions(
          biometricOnly: true,
          stickyAuth: true,
        ),
      );
    } catch (_) {
      return false;
    }
  }
}
