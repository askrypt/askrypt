/// Persists the Askrypt-server sign-in and the configured server address.
///
/// The session token is a credential, not a preference — it authorizes
/// account operations that never re-ask for the password — so it lives in
/// Keystore/Keychain-backed [FlutterSecureStorage], like the desktop app keeps
/// it out of `settings.json` in its own `0600` `server_session.json`.
///
/// A seam (like `VaultIo`) so tests fake it instead of touching secure storage.
library;

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// A saved sign-in to an Askrypt server (same fields as desktop's
/// `ServerSession`).
class ServerSession {
  const ServerSession({
    required this.baseUrl,
    required this.email,
    required this.token,
  });

  final String baseUrl;
  final String email;
  final String token;

  Map<String, dynamic> toJson() =>
      {'base_url': baseUrl, 'email': email, 'token': token};

  factory ServerSession.fromJson(Map<String, dynamic> json) => ServerSession(
        baseUrl: json['base_url'] as String,
        email: json['email'] as String,
        token: json['token'] as String,
      );

  @override
  String toString() => 'ServerSession($baseUrl, $email, token: <redacted>)';
}

abstract class ServerSessionStore {
  /// The saved session, or `null` when signed out (or unreadable).
  Future<ServerSession?> load();

  Future<void> save(ServerSession session);

  Future<void> clear();

  /// The configured server address, or `null` for the default.
  Future<String?> loadServerUrl();

  Future<void> saveServerUrl(String url);
}

/// Production implementation over [FlutterSecureStorage].
class SecureServerSessionStore implements ServerSessionStore {
  SecureServerSessionStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  static const _sessionKey = 'server_session';
  static const _urlKey = 'server_url';

  @override
  Future<ServerSession?> load() async {
    final raw = await _storage.read(key: _sessionKey);
    if (raw == null) return null;
    try {
      return ServerSession.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      // Malformed means "not signed in", as on desktop.
      return null;
    }
  }

  @override
  Future<void> save(ServerSession session) =>
      _storage.write(key: _sessionKey, value: jsonEncode(session.toJson()));

  @override
  Future<void> clear() => _storage.delete(key: _sessionKey);

  @override
  Future<String?> loadServerUrl() => _storage.read(key: _urlKey);

  @override
  Future<void> saveServerUrl(String url) =>
      _storage.write(key: _urlKey, value: url);
}
