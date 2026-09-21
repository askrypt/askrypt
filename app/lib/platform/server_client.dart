/// Askrypt-server client: browser sign-in and the vault file API.
///
/// Dart port of `core/src/storage/server.rs` (`ServerClient`, `BrowserLogin`,
/// `RemoteVault`) speaking the same `/api/v1` the desktop app does. The server
/// is a zero-knowledge blob store: this moves the bytes `UnlockedVault.toBytes`
/// already produced and never sees questions, answers or keys.
///
/// The error mapping, ETag quoting and verification-URL guard mirror the Rust
/// client exactly, so both apps react to a server the same way.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io' show HandshakeException, SocketException;
import 'dart:typed_data';

import 'package:http/http.dart' as http;

/// Where a fresh install points (`AppSettings::server_url` on desktop).
const String defaultServerUrl = 'https://askrypt.com';

/// Largest vault the server accepts (`MAX_VAULT_BYTES` in `server/src/vaults.rs`).
/// Checked locally so an oversize vault fails before the upload is paid for.
const int maxVaultBytes = 10 * 1024 * 1024;

/// Ceiling on a vault transfer — generous enough for 10 MiB on a slow link.
const Duration _requestTimeout = Duration(seconds: 120);

/// Ceiling on a device-link round trip: two tiny JSON requests, one of them
/// repeated on a timer, so a wedged server must not pile them up.
const Duration _linkTimeout = Duration(seconds: 15);

/// Strip surrounding whitespace and trailing slashes so `{base}/api/v1/...`
/// never doubles up. Same rule as core's `normalize_base_url`.
String normalizeBaseUrl(String baseUrl) {
  var url = baseUrl.trim();
  while (url.endsWith('/')) {
    url = url.substring(0, url.length - 1);
  }
  return url;
}

/// Host portion of a base URL, for display (falls back to the whole URL).
String hostOf(String baseUrl) {
  final i = baseUrl.indexOf('://');
  return i < 0 ? baseUrl : baseUrl.substring(i + 3);
}

/// What went wrong, coarse on purpose: callers re-authenticate, reload, retry
/// or give up with the server's own message.
enum ServerErrorKind {
  /// 401/403 — token missing, expired, revoked or not permitted.
  auth,

  /// 404 — unknown vault (or endpoint).
  notFound,

  /// 409 name taken, 412 stale `If-Match`, 428 `If-Match` missing: the
  /// caller's view of the server is out of date.
  conflict,

  /// Any other error status, with the server's `code`.
  remote,

  /// The request never got an answer.
  network,

  /// An answer this client cannot read.
  format,
}

class ServerException implements Exception {
  const ServerException(this.kind, this.message, {this.status, this.code});

  final ServerErrorKind kind;
  final String message;
  final int? status;
  final String? code;

  /// The server asked us to slow down — not a failure of a waiting sign-in.
  bool get isRateLimited => code == 'rate_limited' || status == 429;

  /// A sentence for the user.
  String describe() => switch (kind) {
        ServerErrorKind.network =>
          'Could not reach the server. Check your connection.',
        ServerErrorKind.auth =>
          'Your sign-in is no longer valid. Sign in again.',
        ServerErrorKind.format => 'The server sent an unexpected answer.',
        ServerErrorKind.notFound => 'Not found on the server.',
        _ => message,
      };

  @override
  String toString() => 'ServerException($kind, $status, $code): $message';
}

/// One vault's metadata, as the server reports it.
class RemoteVault {
  const RemoteVault({
    required this.id,
    required this.name,
    required this.size,
    required this.etag,
    required this.updatedAt,
    this.host,
    this.savedAt,
  });

  /// Server-assigned uuid; the vault's identity in every URL.
  final String id;

  /// File name, unique within the account.
  final String name;
  final int size;

  /// SHA-256 of the stored bytes, *unquoted*.
  final String etag;

  /// RFC 3339 time of the last write, as the *server* recorded it.
  final String updatedAt;

  /// The device that wrote the file, lifted from the vault's own stamp.
  final String? host;

  /// When the file itself says it was saved.
  final String? savedAt;

  factory RemoteVault.fromJson(Map<String, dynamic> json) => RemoteVault(
        id: json['id'] as String,
        name: json['name'] as String,
        size: (json['size'] as num).toInt(),
        etag: json['etag'] as String,
        updatedAt: json['updated_at'] as String,
        host: json['host'] as String?,
        savedAt: json['saved_at'] as String?,
      );
}

/// One authenticated handle to a server's `/api/v1`.
///
/// The [token] is a credential: it authorizes account operations that never
/// re-ask for the password, so it is kept in secure storage, never logged.
class ServerClient {
  ServerClient({
    required String baseUrl,
    required this.token,
    http.Client? httpClient,
  })  : baseUrl = normalizeBaseUrl(baseUrl),
        _http = httpClient ?? http.Client();

  final String baseUrl;
  final String token;
  final http.Client _http;

  String get host => hostOf(baseUrl);

  /// Exact format — the server matches `Bearer ` case-sensitively.
  Map<String, String> get _auth => {'Authorization': 'Bearer $token'};

  Uri _uri(String path) => Uri.parse('$baseUrl/api/v1$path');

  /// All vaults in the account, as the server sorts them (by name).
  Future<List<RemoteVault>> list() async {
    final response = await _call(() => _http.get(_uri('/vaults'), headers: _auth),
        _requestTimeout);
    final body = _json(response);
    if (body is! List) throw _unexpected();
    try {
      return [
        for (final row in body) RemoteVault.fromJson(row as Map<String, dynamic>)
      ];
    } catch (_) {
      throw _unexpected();
    }
  }

  /// A vault's bytes along with its current (unquoted) ETag.
  Future<(Uint8List, String)> download(String id) async {
    final request = http.Request('GET', _uri('/vaults/${Uri.encodeComponent(id)}'))
      ..headers.addAll(_auth);
    return _guard(() async {
      final streamed = await _http.send(request).timeout(_requestTimeout);
      if (streamed.statusCode >= 400) {
        _check(await http.Response.fromStream(streamed));
      }
      // Capped so a server streaming forever cannot fill memory; +1 lets a
      // legitimately maximal vault through.
      final buffer = BytesBuilder(copy: false);
      await for (final chunk in streamed.stream.timeout(_requestTimeout)) {
        buffer.add(chunk);
        if (buffer.length > maxVaultBytes + 1) {
          throw const ServerException(
              ServerErrorKind.format, 'vault is larger than the server allows');
        }
      }
      final etag = unquoteEtag(streamed.headers['etag'] ?? '');
      return (buffer.takeBytes(), etag);
    });
  }

  /// Replace a vault's bytes, but only if it still matches [ifMatch] (the ETag
  /// last seen). A stale ETag is a [ServerErrorKind.conflict], never a silent
  /// overwrite of another device's edit.
  Future<RemoteVault> overwrite(String id, Uint8List bytes, String ifMatch) async {
    _checkSize(bytes);
    final response = await _call(
        () => _http.put(
              _uri('/vaults/${Uri.encodeComponent(id)}'),
              headers: {
                ..._auth,
                'Content-Type': 'application/octet-stream',
                'If-Match': quoteEtag(ifMatch),
              },
              body: bytes,
            ),
        _requestTimeout);
    return _vault(response);
  }

  /// Upload a new vault. A name already taken is a [ServerErrorKind.conflict].
  Future<RemoteVault> create(String name, Uint8List bytes) async {
    _checkSize(bytes);
    final response = await _call(
        () => _http.post(
              Uri.parse('$baseUrl/api/v1/vaults?name=${percentEncode(name)}'),
              headers: {..._auth, 'Content-Type': 'application/octet-stream'},
              body: bytes,
            ),
        _requestTimeout);
    return _vault(response);
  }

  /// Revoke this session's token. The client is dead afterwards.
  Future<void> logout() async {
    await _call(() => _http.post(_uri('/auth/logout'), headers: _auth),
        _linkTimeout);
  }

  RemoteVault _vault(http.Response response) {
    final body = _json(response);
    try {
      return RemoteVault.fromJson(body as Map<String, dynamic>);
    } catch (_) {
      throw _unexpected();
    }
  }
}

// ---------------------------------------------------------------------------
// Browser sign-in (device link)
// ---------------------------------------------------------------------------

/// Where a browser sign-in stands.
sealed class LoginPoll {
  const LoginPoll();
}

/// Nobody has approved it yet. Keep polling.
class LoginPending extends LoginPoll {
  const LoginPending();
}

/// Signed in — [client] holds the issued token.
class LoginApproved extends LoginPoll {
  const LoginApproved(this.client, this.email);
  final ServerClient client;
  final String email;
}

/// The user said this was not their app.
class LoginDenied extends LoginPoll {
  const LoginDenied();
}

/// Too old, already used, or never existed. Start a new one.
class LoginExpired extends LoginPoll {
  const LoginExpired();
}

/// A sign-in happening in the user's browser. Open [verificationUrl], show
/// [userCode] so the user can check the page is about *this* app, and [poll]
/// every [interval] until it stops answering [LoginPending].
///
/// The app never sees the account password, and the user can register as
/// part of the same flow.
class BrowserLogin {
  BrowserLogin._({
    required this.baseUrl,
    required String pollToken,
    required this.verificationUrl,
    required this.userCode,
    required this.interval,
    required this.expiresIn,
    required http.Client httpClient,
  })  : _pollToken = pollToken,
        _http = httpClient;

  final String baseUrl;

  /// Secret: whoever holds it collects the session the browser authorized.
  final String _pollToken;
  final String verificationUrl;
  final String userCode;

  /// The server's own cadence, so polling cannot outrun its rate limit.
  final Duration interval;
  final int expiresIn;
  final http.Client _http;

  /// Open a device link. [deviceLabel] names this phone in the account's
  /// device list (`android@host`).
  static Future<BrowserLogin> start(
    String baseUrl, {
    String? deviceLabel,
    http.Client? httpClient,
  }) async {
    final base = normalizeBaseUrl(baseUrl);
    final client = httpClient ?? http.Client();
    final response = await _call(
        () => client.post(
              Uri.parse('$base/api/v1/auth/device'),
              headers: const {'Content-Type': 'application/json'},
              body: jsonEncode({'device_label': deviceLabel}),
            ),
        _linkTimeout);
    final body = _json(response);
    try {
      final map = body as Map<String, dynamic>;
      return BrowserLogin._(
        baseUrl: base,
        pollToken: map['poll_token'] as String,
        verificationUrl:
            verificationUrlFor(base, map['verification_path'] as String),
        userCode: map['user_code'] as String,
        interval: Duration(
            seconds: (map['interval'] as num).toInt().clamp(1, 60)),
        expiresIn: (map['expires_in'] as num).toInt(),
        httpClient: client,
      );
    } on ServerException {
      rethrow;
    } catch (_) {
      throw _unexpected();
    }
  }

  /// One round trip. The caller owns the waiting.
  Future<LoginPoll> poll() async {
    final response = await _call(
        () => _http.post(
              Uri.parse('$baseUrl/api/v1/auth/device/poll'),
              headers: const {'Content-Type': 'application/json'},
              body: jsonEncode({'poll_token': _pollToken}),
            ),
        _linkTimeout);
    final body = _json(response);
    if (body is! Map<String, dynamic>) throw _unexpected();
    // Read flat, so a status this build has never heard of degrades to
    // "keep waiting" rather than a parse error.
    switch (body['status']) {
      case 'approved':
        final token = body['token'];
        final account = body['account'];
        final email = account is Map ? account['email'] : null;
        if (token is! String || email is! String) {
          throw const ServerException(ServerErrorKind.format,
              'server approved the sign-in without returning a session');
        }
        return LoginApproved(
            ServerClient(baseUrl: baseUrl, token: token, httpClient: _http),
            email);
      case 'denied':
        return const LoginDenied();
      case 'expired':
        return const LoginExpired();
      default:
        return const LoginPending();
    }
  }

  /// Tell the server this sign-in is not wanted after all, so the link stops
  /// being approvable now rather than when it expires. Best effort.
  Future<void> cancel() async {
    await _call(
        () => _http.post(
              Uri.parse('$baseUrl/api/v1/auth/device/cancel'),
              headers: const {'Content-Type': 'application/json'},
              body: jsonEncode({'poll_token': _pollToken}),
            ),
        _linkTimeout);
  }

  @override
  String toString() =>
      'BrowserLogin($verificationUrl, $userCode, poll_token: <redacted>)';
}

/// Build the browser URL from the server's answer, refusing anything that is
/// not a plain path on the server we asked. The result is handed to the OS to
/// open, so a hostile server answering `//evil.example/x` must not be able to
/// launch the browser at somebody else's site.
String verificationUrlFor(String baseUrl, String path) {
  final looksLikeAPath =
      path.startsWith('/') && !path.startsWith('//') && !path.contains(':');
  if (!looksLikeAPath) {
    throw ServerException(ServerErrorKind.format,
        'server asked us to open "$path", which is not a path on it');
  }
  return '$baseUrl$path';
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Header form of an ETag: quoted, as the server sends and expects it.
String quoteEtag(String etag) {
  var bare = etag;
  while (bare.startsWith('"')) {
    bare = bare.substring(1);
  }
  while (bare.endsWith('"')) {
    bare = bare.substring(0, bare.length - 1);
  }
  return '"$bare"';
}

/// Strip the quotes and any weak-validator prefix from a received ETag.
String unquoteEtag(String value) {
  var v = value.trim();
  if (v.startsWith('W/')) v = v.substring(2);
  final quoted = quoteEtag(v);
  return quoted.substring(1, quoted.length - 1);
}

/// Percent-encode a vault name for `?name=` — unreserved bytes pass through,
/// everything else (UTF-8) is `%XX`, like the Rust client.
String percentEncode(String value) {
  final out = StringBuffer();
  for (final byte in utf8.encode(value)) {
    final isUnreserved = (byte >= 0x41 && byte <= 0x5A) ||
        (byte >= 0x61 && byte <= 0x7A) ||
        (byte >= 0x30 && byte <= 0x39) ||
        byte == 0x2D ||
        byte == 0x5F ||
        byte == 0x2E ||
        byte == 0x7E;
    if (isUnreserved) {
      out.writeCharCode(byte);
    } else {
      out.write('%${byte.toRadixString(16).toUpperCase().padLeft(2, '0')}');
    }
  }
  return out.toString();
}

void _checkSize(Uint8List bytes) {
  if (bytes.length > maxVaultBytes) {
    throw ServerException(
      ServerErrorKind.remote,
      'The vault is ${bytes.length} bytes; the server accepts at most '
      '$maxVaultBytes.',
      status: 413,
      code: 'payload_too_large',
    );
  }
}

/// Run one request with a timeout, mapping transport failures onto
/// [ServerErrorKind.network] and error statuses via [_check].
Future<http.Response> _call(
    Future<http.Response> Function() request, Duration timeout) {
  return _guard(() async => _check(await request().timeout(timeout)));
}

Future<T> _guard<T>(Future<T> Function() body) async {
  try {
    return await body();
  } on ServerException {
    rethrow;
  } on TimeoutException {
    throw const ServerException(ServerErrorKind.network, 'request timed out');
  } on SocketException catch (e) {
    throw ServerException(ServerErrorKind.network, e.message);
  } on HandshakeException catch (e) {
    throw ServerException(ServerErrorKind.network, e.message);
  } on http.ClientException catch (e) {
    throw ServerException(ServerErrorKind.network, e.message);
  }
}

/// Turn a 4xx/5xx into the matching [ServerException]; pass the rest through.
/// Same mapping as `check_status` in the Rust client.
http.Response _check(http.Response response) {
  final status = response.statusCode;
  if (status < 400) return response;

  var code = 'unexpected_response';
  var message = 'server returned ${response.reasonPhrase ?? status}';
  try {
    final body = jsonDecode(utf8.decode(response.bodyBytes));
    final error = (body as Map<String, dynamic>)['error'] as Map<String, dynamic>;
    code = error['code'] as String;
    message = error['message'] as String;
  } catch (_) {
    // Not the envelope (a proxy's own error page, say): keep the fallback.
  }

  final kind = switch (status) {
    401 || 403 => ServerErrorKind.auth,
    404 => ServerErrorKind.notFound,
    409 || 412 || 428 => ServerErrorKind.conflict,
    _ => ServerErrorKind.remote,
  };
  throw ServerException(kind, message, status: status, code: code);
}

Object? _json(http.Response response) {
  try {
    return jsonDecode(utf8.decode(response.bodyBytes));
  } catch (_) {
    throw _unexpected();
  }
}

ServerException _unexpected() => const ServerException(
    ServerErrorKind.format, 'unexpected response from server');
