/// `CloudNotifier`: browser sign-in lifecycle, persistence, cancellation.
library;

import 'package:askrypt/platform/server_session_store.dart';
import 'package:askrypt/session/cloud_session.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'cloud_fakes.dart';

void main() {
  late FakeServer server;
  late FakeServerSessionStore store;
  late List<Uri> opened;

  ProviderContainer container() {
    final c = ProviderContainer(overrides: [
      httpClientProvider.overrideWithValue(server.client),
      serverSessionStoreProvider.overrideWithValue(store),
      urlOpenerProvider.overrideWithValue((url) async {
        opened.add(url);
        return true;
      }),
    ]);
    addTearDown(c.dispose);
    return c;
  }

  setUp(() {
    server = FakeServer();
    store = FakeServerSessionStore()..url = 'https://cloud.test';
    opened = [];
  });

  Future<void> until(bool Function() done) async {
    for (var i = 0; i < 100 && !done(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(done(), isTrue);
  }

  test('restores a saved session for the configured server', () async {
    store.session = const ServerSession(
        baseUrl: 'https://cloud.test', email: 'me@example.com', token: 't');
    final c = container();
    await c.read(cloudProvider.notifier).ready;
    final state = c.read(cloudProvider) as CloudSignedIn;
    expect(state.email, 'me@example.com');
    expect(state.serves('https://cloud.test', 'me@example.com'), isTrue);
  });

  test('a session for another server is not used', () async {
    store.session = const ServerSession(
        baseUrl: 'https://other.test', email: 'me@example.com', token: 't');
    final c = container();
    await c.read(cloudProvider.notifier).ready;
    expect(c.read(cloudProvider), isA<CloudSignedOut>());
  });

  test('sign-in opens the page, polls, and persists the session', () async {
    final c = container();
    final notifier = c.read(cloudProvider.notifier);
    await notifier.ready;

    await notifier.signIn();
    final linking = c.read(cloudProvider) as CloudLinking;
    expect(linking.userCode, 'ABCD-EFGH');
    expect(opened.single.toString(), 'https://cloud.test/link/link-1');

    server.pollAnswers.add({
      'status': 'approved',
      'token': FakeServer.token,
      'account': {'email': 'me@example.com'},
    });
    notifier.pollNow();
    await until(() => c.read(cloudProvider) is CloudSignedIn);
    expect(store.session?.token, FakeServer.token);
    expect(store.session?.email, 'me@example.com');
  });

  test('cancel drops a late approval and tells the server', () async {
    final c = container();
    final notifier = c.read(cloudProvider.notifier);
    await notifier.ready;
    await notifier.signIn();

    notifier.cancel();
    expect(c.read(cloudProvider), isA<CloudSignedOut>());
    server.pollAnswers.add({
      'status': 'approved',
      'token': FakeServer.token,
      'account': {'email': 'me@example.com'},
    });
    notifier.pollNow(); // no link any more: nothing happens
    await Future<void>.delayed(const Duration(milliseconds: 1500));
    expect(c.read(cloudProvider), isA<CloudSignedOut>());
    expect(store.session, isNull);
    expect(server.requests.map((r) => r.url.path),
        contains('/api/v1/auth/device/cancel'));
  });

  test('a denied sign-in says so', () async {
    final c = container();
    final notifier = c.read(cloudProvider.notifier);
    await notifier.ready;
    await notifier.signIn();
    server.pollAnswers.add({'status': 'denied'});
    notifier.pollNow();
    await until(() => c.read(cloudProvider) is CloudSignedOut);
    expect((c.read(cloudProvider) as CloudSignedOut).error, contains('denied'));
  });

  test('a rejected token signs out and forgets the session', () async {
    store.session = const ServerSession(
        baseUrl: 'https://cloud.test', email: 'me@example.com', token: 't');
    final c = container();
    final notifier = c.read(cloudProvider.notifier);
    await notifier.ready;
    await notifier.sessionRejected();
    expect(c.read(cloudProvider), isA<CloudSignedOut>());
    expect(store.session, isNull);
  });

  test('changing the server signs out of the old one', () async {
    store.session = const ServerSession(
        baseUrl: 'https://cloud.test', email: 'me@example.com', token: 't');
    final c = container();
    final notifier = c.read(cloudProvider.notifier);
    await notifier.ready;
    await notifier.setServerUrl('https://new.test/');
    expect(c.read(cloudProvider).serverUrl, 'https://new.test');
    expect(c.read(cloudProvider), isA<CloudSignedOut>());
    expect(store.session, isNull);
    expect(store.url, 'https://new.test');
  });
}
