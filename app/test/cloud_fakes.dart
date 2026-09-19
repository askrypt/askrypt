/// Test doubles for Askrypt Cloud: an in-memory session store and a tiny fake
/// server behind `package:http`'s [MockClient], speaking the same `/api/v1`
/// shapes as `server/` (error envelope, quoted ETags, `If-Match`).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:askrypt/platform/server_session_store.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

class FakeServerSessionStore implements ServerSessionStore {
  ServerSession? session;
  String? url;

  @override
  Future<ServerSession?> load() async => session;

  @override
  Future<void> save(ServerSession s) async => session = s;

  @override
  Future<void> clear() async => session = null;

  @override
  Future<String?> loadServerUrl() async => url;

  @override
  Future<void> saveServerUrl(String u) async => url = u;
}

class FakeVault {
  FakeVault(this.id, this.name, Uint8List bytes) {
    this.bytes = bytes;
  }
  final String id;
  String name;
  Uint8List _bytes = Uint8List(0);
  int _version = 0;

  /// The real server hashes the bytes; a write counter is as good a version.
  String get etag => '$id-v$_version';

  Uint8List get bytes => _bytes;
  set bytes(Uint8List value) {
    _bytes = value;
    _version++;
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'size': bytes.length,
        'etag': etag,
        'updated_at': '2026-09-19T10:00:00Z',
        'host': 'linux@desk',
        'saved_at': '2026-09-19T10:00:00Z',
      };
}

/// In-memory Askrypt server. Every request is recorded in [requests].
class FakeServer {
  static const token = 'tok-123';
  static const pollToken = 'poll-secret';

  final vaults = <FakeVault>[];
  final requests = <http.Request>[];

  /// What the next device-link polls answer, in order; then `pending`.
  final pollAnswers = <Map<String, dynamic>>[];
  int _nextId = 1;

  late final MockClient client = MockClient(_handle);

  FakeVault add(String name, Uint8List bytes) {
    final v = FakeVault('id-${_nextId++}', name, bytes);
    vaults.add(v);
    return v;
  }

  http.Response _error(int status, String code, String message) =>
      http.Response(
          jsonEncode({
            'error': {'code': code, 'message': message}
          }),
          status,
          headers: {'content-type': 'application/json'});

  http.Response _ok(Object body, [int status = 200]) => http.Response(
      jsonEncode(body), status,
      headers: {'content-type': 'application/json'});

  Future<http.Response> _handle(http.Request request) async {
    requests.add(request);
    final path = request.url.path;

    switch ((request.method, path)) {
      case ('POST', '/api/v1/auth/device'):
        return _ok({
          'link_id': 'link-1',
          'poll_token': pollToken,
          'user_code': 'ABCD-EFGH',
          'verification_path': '/link/link-1',
          'expires_in': 86400,
          'interval': 1,
        }, 201);
      case ('POST', '/api/v1/auth/device/poll'):
        if (pollAnswers.isEmpty) return _ok({'status': 'pending'});
        return _ok(pollAnswers.removeAt(0));
      case ('POST', '/api/v1/auth/device/cancel'):
        return http.Response('', 204);
    }

    if (request.headers['Authorization'] != 'Bearer $token') {
      return _error(401, 'unauthorized', 'sign in first');
    }

    if (path == '/api/v1/auth/logout') return http.Response('', 204);

    if (path == '/api/v1/vaults') {
      if (request.method == 'GET') {
        return _ok([for (final v in vaults) v.toJson()]);
      }
      final name = request.url.queryParameters['name']!;
      if (vaults.any((v) => v.name == name)) {
        return _error(409, 'conflict', 'a vault with that name exists');
      }
      return _ok(add(name, request.bodyBytes).toJson(), 201);
    }

    final id = path.substring('/api/v1/vaults/'.length);
    final vault = vaults.where((v) => v.id == id).firstOrNull;
    if (vault == null) return _error(404, 'not_found', 'no such vault');
    switch (request.method) {
      case 'GET':
        return http.Response.bytes(vault.bytes, 200,
            headers: {'etag': '"${vault.etag}"'});
      case 'PUT':
        final ifMatch = request.headers['If-Match'];
        if (ifMatch == null) {
          return _error(428, 'precondition_required', 'If-Match required');
        }
        if (ifMatch != '"${vault.etag}"') {
          return _error(412, 'precondition_failed', 'vault changed');
        }
        vault.bytes = request.bodyBytes;
        return _ok(vault.toJson());
    }
    return _error(405, 'method_not_allowed', 'nope');
  }
}
