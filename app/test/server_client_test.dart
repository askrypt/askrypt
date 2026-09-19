/// `ServerClient` / `BrowserLogin` against a fake server: the same status
/// mapping, ETag quoting and verification-URL guard as the Rust client in
/// `core/src/storage/server.rs`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:askrypt/platform/server_client.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'cloud_fakes.dart';

void main() {
  final bytes = Uint8List.fromList(utf8.encode('PK vault bytes'));

  ServerClient signedIn(FakeServer server) => ServerClient(
      baseUrl: 'https://cloud.test/',
      token: FakeServer.token,
      httpClient: server.client);

  test('base URLs lose trailing slashes and whitespace', () {
    expect(normalizeBaseUrl(' https://a.test// '), 'https://a.test');
    expect(hostOf('https://a.test:8080'), 'a.test:8080');
  });

  test('ETags are sent quoted and read back bare', () {
    expect(quoteEtag('abc'), '"abc"');
    expect(quoteEtag('"abc"'), '"abc"');
    expect(unquoteEtag('W/"abc"'), 'abc');
    expect(unquoteEtag(' "abc" '), 'abc');
  });

  test('vault names are percent-encoded as UTF-8', () {
    expect(percentEncode('My Vault.askrypt'), 'My%20Vault.askrypt');
    expect(percentEncode('ключ'), '%D0%BA%D0%BB%D1%8E%D1%87');
    expect(percentEncode('a&b=c'), 'a%26b%3Dc');
  });

  test('verification path must be a plain path on the same server', () {
    expect(verificationUrlFor('https://a.test', '/link/x'),
        'https://a.test/link/x');
    for (final hostile in ['//evil.test/x', 'https://evil.test', 'link/x']) {
      expect(() => verificationUrlFor('https://a.test', hostile),
          throwsA(isA<ServerException>()
              .having((e) => e.kind, 'kind', ServerErrorKind.format)));
    }
  });

  test('list, download and overwrite round-trip with If-Match', () async {
    final server = FakeServer();
    final stored = server.add('Main.askrypt', bytes);
    final client = signedIn(server);

    final vaults = await client.list();
    expect(vaults.single.name, 'Main.askrypt');
    expect(vaults.single.host, 'linux@desk');
    expect(server.requests.last.headers['Authorization'],
        'Bearer ${FakeServer.token}');

    final (downloaded, etag) = await client.download(stored.id);
    expect(downloaded, bytes);
    expect(etag, stored.etag); // unquoted

    final next = Uint8List.fromList([...bytes, 1]);
    final written = await client.overwrite(stored.id, next, etag);
    expect(server.requests.last.headers['If-Match'], '"$etag"');
    expect(written.etag, stored.etag);
    expect(stored.bytes, next);
  });

  test('a stale ETag is a conflict, never an overwrite', () async {
    final server = FakeServer();
    final stored = server.add('Main.askrypt', bytes);
    final before = stored.bytes;
    await expectLater(
        signedIn(server).overwrite(stored.id, bytes, 'stale'),
        throwsA(isA<ServerException>()
            .having((e) => e.kind, 'kind', ServerErrorKind.conflict)
            .having((e) => e.status, 'status', 412)));
    expect(stored.bytes, same(before));
  });

  test('create sends the name in the query and maps a taken name', () async {
    final server = FakeServer();
    final client = signedIn(server);
    final created = await client.create('New Vault.askrypt', bytes);
    expect(created.name, 'New Vault.askrypt');
    expect(server.requests.last.url.query, 'name=New%20Vault.askrypt');

    await expectLater(
        client.create('New Vault.askrypt', bytes),
        throwsA(isA<ServerException>()
            .having((e) => e.kind, 'kind', ServerErrorKind.conflict)));
  });

  test('status codes map like check_status', () async {
    final server = FakeServer();
    final bad = ServerClient(
        baseUrl: 'https://cloud.test', token: 'nope', httpClient: server.client);
    await expectLater(
        bad.list(),
        throwsA(isA<ServerException>()
            .having((e) => e.kind, 'kind', ServerErrorKind.auth)
            .having((e) => e.code, 'code', 'unauthorized')));
    await expectLater(
        signedIn(server).download('missing'),
        throwsA(isA<ServerException>()
            .having((e) => e.kind, 'kind', ServerErrorKind.notFound)));

    // A proxy's own error page is not the envelope: keep a fallback code.
    final proxy = ServerClient(
        baseUrl: 'https://cloud.test',
        token: 't',
        httpClient: MockClient((_) async => http.Response('<html>', 502)));
    await expectLater(
        proxy.list(),
        throwsA(isA<ServerException>()
            .having((e) => e.kind, 'kind', ServerErrorKind.remote)
            .having((e) => e.code, 'code', 'unexpected_response')));
  });

  test('transport failures are network errors', () async {
    final client = ServerClient(
        baseUrl: 'https://cloud.test',
        token: 't',
        httpClient: MockClient((_) async => throw http.ClientException('down')));
    await expectLater(
        client.list(),
        throwsA(isA<ServerException>()
            .having((e) => e.kind, 'kind', ServerErrorKind.network)));
  });

  test('an oversize vault is refused before uploading', () async {
    final server = FakeServer();
    await expectLater(
        signedIn(server).create('big', Uint8List(maxVaultBytes + 1)),
        throwsA(isA<ServerException>()
            .having((e) => e.code, 'code', 'payload_too_large')));
    expect(server.requests, isEmpty);
  });

  group('browser login', () {
    test('start, poll pending, then approved', () async {
      final server = FakeServer();
      final link = await BrowserLogin.start('https://cloud.test/',
          deviceLabel: 'android@phone', httpClient: server.client);
      expect(link.verificationUrl, 'https://cloud.test/link/link-1');
      expect(link.userCode, 'ABCD-EFGH');
      expect(link.interval, const Duration(seconds: 1));
      expect(jsonDecode(server.requests.last.body),
          {'device_label': 'android@phone'});
      expect(link.toString(), isNot(contains(FakeServer.pollToken)));

      expect(await link.poll(), isA<LoginPending>());
      expect(jsonDecode(server.requests.last.body),
          {'poll_token': FakeServer.pollToken});

      server.pollAnswers.add({
        'status': 'approved',
        'token': FakeServer.token,
        'account': {'email': 'me@example.com'},
      });
      final approved = await link.poll() as LoginApproved;
      expect(approved.email, 'me@example.com');
      expect(approved.client.token, FakeServer.token);
      expect(approved.client.baseUrl, 'https://cloud.test');
    });

    test('unknown statuses keep waiting; denied/expired are terminal',
        () async {
      final server = FakeServer()
        ..pollAnswers.addAll([
          {'status': 'something_new'},
          {'status': 'denied'},
          {'status': 'expired'},
          {'status': 'approved'},
        ]);
      final link =
          await BrowserLogin.start('https://cloud.test', httpClient: server.client);
      expect(await link.poll(), isA<LoginPending>());
      expect(await link.poll(), isA<LoginDenied>());
      expect(await link.poll(), isA<LoginExpired>());
      // Approved without a session is a format error, not a sign-in.
      await expectLater(
          link.poll(),
          throwsA(isA<ServerException>()
              .having((e) => e.kind, 'kind', ServerErrorKind.format)));
    });

    test('a hostile verification path is refused', () async {
      final client = MockClient((_) async => http.Response(
          jsonEncode({
            'poll_token': 'p',
            'user_code': 'X',
            'verification_path': '//evil.test/phish',
            'expires_in': 10,
            'interval': 5,
          }),
          201));
      await expectLater(
          BrowserLogin.start('https://cloud.test', httpClient: client),
          throwsA(isA<ServerException>()
              .having((e) => e.kind, 'kind', ServerErrorKind.format)));
    });
  });
}
