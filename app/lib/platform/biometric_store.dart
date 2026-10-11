/// Biometric quick-unlock store (PLAN Phase 4, "answers-only" decision).
///
/// Persists the *security answers* for a vault behind a biometric prompt, so a
/// returning user re-picks the file (always fresh bytes — no stale vault, no
/// stored copy of the encrypted vault) and unlocks with a fingerprint/Face ID
/// instead of re-typing. We store the raw answers, not a derived key, because
/// every save rotates the vault's salts + master key — only the answers survive.
///
/// **One credential per vault.** The format has no stable vault id, so a vault
/// is identified by its full, ordered question list: the credential id is
/// `bio.<sha256(question0)>.<sha256(questions)>`. Before unlocking only the
/// first question is readable, so lookup returns every credential sharing it
/// (at most [maxCredentialsPerQuestion]); the unlock screen picks the one whose
/// remaining questions decrypt with its first answer. Two vaults with the very
/// same question list share a slot (last enrolled wins).
///
/// Answers live in OS-keystore/Keychain-backed [FlutterSecureStorage], in a
/// preferences file of their own so a credential that can no longer be
/// decrypted (e.g. restored without its Keystore key) can be wiped without
/// touching the Cloud session or settings.
///
/// Abstracted (like `VaultIo`) so tests fake it instead of touching real
/// biometrics or secure storage.
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

import '../crypto/kdf.dart';

/// How many vaults sharing one first question keep a credential; the oldest
/// is evicted beyond this.
const maxCredentialsPerQuestion = 5;

/// Storage-key prefix of every credential whose first question is [question0].
String biometricPrefixFor(String question0) =>
    'bio.${sha256Hex(question0, '')}.';

/// The credential id of a vault with this full, ordered question list.
String biometricIdFor(List<String> questions) =>
    '${biometricPrefixFor(questions.first)}${sha256Hex(jsonEncode(questions), '')}';

/// Stored answers for one vault, aligned with [questions].
class BiometricCredential {
  const BiometricCredential({
    required this.id,
    required this.questions,
    required this.answers,
  });

  final String id;
  final List<String> questions;
  final List<String> answers;
}

/// The stored credentials could not be read; the store has been cleared.
class BiometricStoreException implements Exception {
  const BiometricStoreException(this.message);
  final String message;
  @override
  String toString() => 'BiometricStoreException: $message';
}

abstract class BiometricStore {
  /// Whether the device can perform a biometric check at all.
  Future<bool> canUse();

  /// Whether any credential is stored for a vault starting with [question0].
  Future<bool> hasCredentialFor(String question0);

  /// Whether the credential [id] is stored. No prompt.
  Future<bool> contains(String id);

  /// Prompt for biometrics, then persist [answers] for the vault with these
  /// [questions]. Returns `false` (and stores nothing) if the prompt is
  /// cancelled/fails.
  Future<bool> enroll(List<String> questions, List<String> answers);

  /// Prompt for biometrics once, then return every credential whose first
  /// question is [question0]; `null` if the prompt is cancelled/fails. Throws
  /// [BiometricStoreException] when stored credentials can't be read.
  Future<List<BiometricCredential>?> reveal(String question0);

  /// Store [answers] under the id of [questions] and drop [oldId] if it
  /// differs — after this device saved a questions/answers change. No prompt:
  /// it only writes what the unlocked vault already holds.
  Future<void> replace(
      String? oldId, List<String> questions, List<String> answers);

  /// Drop the credential [id].
  Future<void> forget(String id);
}

/// Production implementation backed by `local_auth` + `flutter_secure_storage`.
class LocalAuthBiometricStore implements BiometricStore {
  LocalAuthBiometricStore({
    LocalAuthentication? auth,
    FlutterSecureStorage? storage,
  })  : _auth = auth ?? LocalAuthentication(),
        _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(sharedPreferencesName: 'askrypt_biometric'),
            );

  final LocalAuthentication _auth;
  final FlutterSecureStorage _storage;

  static const _reason = 'Unlock your Askrypt vault';

  /// Legacy credentials (`answers_<sha256(question0)>`) lived in the default
  /// preferences, shared with other settings. Dropped once per run — they
  /// can't tell vaults apart, so users re-enroll.
  Future<void>? _legacySwept;

  Future<void> _sweepLegacy() => _legacySwept ??= () async {
        try {
          const legacy = FlutterSecureStorage();
          final all = await legacy.readAll();
          for (final key in all.keys) {
            if (key.startsWith('answers_')) await legacy.delete(key: key);
          }
        } catch (e) {
          debugPrint('biometric: legacy sweep failed: $e');
        }
      }();

  @override
  Future<bool> canUse() async {
    try {
      return await _auth.isDeviceSupported() &&
          await _auth.canCheckBiometrics;
    } catch (e) {
      debugPrint('biometric: availability check failed: $e');
      return false;
    }
  }

  @override
  Future<bool> hasCredentialFor(String question0) async {
    await _sweepLegacy();
    try {
      final prefix = biometricPrefixFor(question0);
      return (await _storage.readAll()).keys.any((k) => k.startsWith(prefix));
    } catch (e) {
      // Surfaced by `reveal`; here just offer the button so it can be.
      debugPrint('biometric: listing failed: $e');
      return true;
    }
  }

  @override
  Future<bool> contains(String id) async {
    try {
      return await _storage.containsKey(key: id);
    } catch (e) {
      debugPrint('biometric: lookup failed: $e');
      return false;
    }
  }

  @override
  Future<bool> enroll(List<String> questions, List<String> answers) async {
    if (!await _authenticate()) return false;
    await _write(questions, answers);
    return true;
  }

  @override
  Future<List<BiometricCredential>?> reveal(String question0) async {
    if (!await _authenticate()) return null;
    final Map<String, String> all;
    try {
      all = await _storage.readAll();
    } catch (e) {
      await _wipe(e);
    }
    final prefix = biometricPrefixFor(question0);
    final found = <BiometricCredential>[];
    for (final MapEntry(:key, :value) in all.entries) {
      if (!key.startsWith(prefix)) continue;
      try {
        final json = jsonDecode(value) as Map<String, dynamic>;
        found.add(BiometricCredential(
          id: key,
          questions: (json['questions'] as List).cast<String>(),
          answers: (json['answers'] as List).cast<String>(),
        ));
      } catch (e) {
        debugPrint('biometric: dropping unreadable credential: $e');
        await _storage.delete(key: key);
      }
    }
    return found;
  }

  @override
  Future<void> replace(
      String? oldId, List<String> questions, List<String> answers) async {
    final id = await _write(questions, answers);
    if (oldId != null && oldId != id) await forget(oldId);
  }

  @override
  Future<void> forget(String id) => _storage.delete(key: id);

  /// Store one credential and evict the oldest beyond the per-question cap.
  Future<String> _write(List<String> questions, List<String> answers) async {
    final id = biometricIdFor(questions);
    await _storage.write(
      key: id,
      value: jsonEncode({
        'questions': questions,
        'answers': answers,
        'saved_at': DateTime.now().toUtc().toIso8601String(),
      }),
    );
    try {
      final prefix = biometricPrefixFor(questions.first);
      final siblings = <(String, String)>[];
      for (final MapEntry(:key, :value) in (await _storage.readAll()).entries) {
        if (!key.startsWith(prefix)) continue;
        String savedAt = '';
        try {
          savedAt = (jsonDecode(value) as Map)['saved_at'] as String? ?? '';
        } catch (_) {}
        siblings.add((key, savedAt));
      }
      siblings.sort((a, b) => b.$2.compareTo(a.$2)); // newest first
      for (final (key, _) in siblings.skip(maxCredentialsPerQuestion)) {
        await _storage.delete(key: key);
      }
    } catch (e) {
      debugPrint('biometric: eviction failed: $e');
    }
    return id;
  }

  /// The store can't be decrypted (typically restored without its Keystore
  /// key): clear it — it only holds re-creatable credentials — and report.
  Future<Never> _wipe(Object error) async {
    debugPrint('biometric: stored credentials unreadable, clearing: $error');
    try {
      await _storage.deleteAll();
    } catch (_) {}
    throw const BiometricStoreException('stored answers could not be read');
  }

  Future<bool> _authenticate() async {
    try {
      return await _auth.authenticate(
        localizedReason: _reason,
        options: const AuthenticationOptions(
          biometricOnly: true,
          stickyAuth: true,
        ),
      );
    } on PlatformException catch (e) {
      debugPrint('biometric: authenticate failed: ${e.code}');
      return false;
    } catch (e) {
      debugPrint('biometric: authenticate failed: $e');
      return false;
    }
  }
}
