/// Askrypt Cloud through the real app shell: reopen a remembered cloud vault,
/// save it back conflict-checked, and resolve a conflict — against a fake
/// server, with the real (cheap-iteration) crypto.
library;

import 'dart:typed_data';

import 'package:askrypt/app.dart';
import 'package:askrypt/crypto/vault.dart';
import 'package:askrypt/platform/biometric_store.dart';
import 'package:askrypt/platform/platform_security.dart';
import 'package:askrypt/platform/recent_vault_store.dart';
import 'package:askrypt/platform/server_session_store.dart';
import 'package:askrypt/platform/vault_io.dart';
import 'package:askrypt/session/cloud_session.dart';
import 'package:askrypt/session/offline_copies.dart';
import 'package:askrypt/session/vault_home.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'cloud_fakes.dart';

class _NoBiometrics implements BiometricStore {
  @override
  Future<bool> canUse() async => false;
  @override
  Future<bool> hasCredentialFor(String question0) async => false;
  @override
  Future<bool> save(String question0, List<String> answers) async => false;
  @override
  Future<List<String>?> reveal(String question0) async => null;
  @override
  Future<void> forget(String question0) async {}
}

class _NoopSecurity implements PlatformSecurity {
  @override
  Future<void> setSecureFlag(bool secure) async {}
  @override
  Future<void> copySensitive(String text) async {}
}

class _NoIo implements VaultIo {
  Uint8List? saved;
  @override
  Future<PickedVault?> pickVault() async => null;
  @override
  Future<String?> saveVault(Uint8List bytes,
      {String suggestedName = 'vault.askrypt'}) async {
    saved = bytes;
    return '/tmp/$suggestedName';
  }

  @override
  Future<String?> saveAttachment(String name, Uint8List bytes) async => null;
}

class _Recent implements RecentVaultStore {
  final List<RecentVault> vaults = [];

  /// The most recent vault; assigning replaces the whole list.
  RecentVault? get stored => vaults.firstOrNull;
  set stored(RecentVault? vault) => vaults
    ..clear()
    ..addAll([if (vault != null) vault]);

  void _putFirst(RecentVault vault) => vaults
    ..removeWhere(vault.sameAs)
    ..insert(0, vault);

  @override
  Future<List<RecentVault>> load() async => List.of(vaults);

  @override
  Future<void> remember(Uint8List bytes, String name) async =>
      _putFirst(RecentLocal(PickedVault(bytes: bytes, name: name)));

  @override
  Future<void> rememberCloud(RecentCloud vault) async => _putFirst(vault);

  @override
  Future<void> forget(RecentVault vault) async =>
      vaults.removeWhere(vault.sameAs);
}

/// Pump while real async work (PBKDF2, the fake server) makes progress, then
/// let animations finish. Not `pumpAndSettle`: the save and sign-in progress
/// bars are indeterminate and never settle while a dialog waits on the user.
Future<void> pumpUntil(WidgetTester tester, bool Function() condition,
    {Duration timeout = const Duration(seconds: 30)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('pumpUntil timed out waiting for condition');
    }
    await tester
        .runAsync(() => Future<void>.delayed(const Duration(milliseconds: 20)));
    await tester.pump();
  }
  await tester.pump(const Duration(seconds: 1));
}

bool shown(String text) => find.text(text).evaluate().isNotEmpty;

void main() {
  const base = 'https://cloud.test';
  const email = 'me@example.com';

  Future<List<String>> entryNames(WidgetTester tester, Uint8List bytes) async {
    final names = await tester.runAsync(() async {
      final file = AskryptFile.fromBytes(bytes);
      final qd = await file.getQuestionsData('Rex');
      return (await file.decrypt(qd, const ['Kazan']))
          .map((e) => e.name)
          .toList();
    });
    return names!;
  }

  Future<void> addEntry(WidgetTester tester, String name) async {
    await tester.tap(find.byIcon(Icons.add));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).at(0), name);
    await tester.tap(find.byIcon(Icons.check));
    await tester.pumpAndSettle();
  }

  testWidgets(
      'remembered cloud vault opens, saves back, and resolves a '
      'conflict', (tester) async {
    final server = FakeServer();
    final initial = await tester.runAsync(() async => (await AskryptFile.create(
          questions: ['First pet?', 'Birth city?'],
          answers: ['Rex', 'Kazan'],
          entries: const [],
          iterations: 1000,
        ))
            .toBytes());
    final stored = server.add('Main.askrypt', initial!);
    final store = FakeServerSessionStore()
      ..url = base
      ..session = const ServerSession(
          baseUrl: base, email: email, token: FakeServer.token);
    final recent = _Recent()
      ..stored = RecentCloud(
          baseUrl: base, email: email, id: stored.id, name: 'Main.askrypt');

    await tester.pumpWidget(ProviderScope(
      overrides: [
        httpClientProvider.overrideWithValue(server.client),
        serverSessionStoreProvider.overrideWithValue(store),
        recentVaultStoreProvider.overrideWithValue(recent),
        vaultIoProvider.overrideWithValue(_NoIo()),
        biometricStoreProvider.overrideWithValue(_NoBiometrics()),
        platformSecurityProvider.overrideWithValue(_NoopSecurity()),
        offlineCopyStoreProvider.overrideWithValue(FakeOfflineCopyStore()),
        ...quietLeakCheckOverrides,
      ],
      child: const AskryptApp(),
    ));
    await tester.pumpAndSettle();

    // Welcome → reopen the remembered cloud vault: downloads, then unlocks.
    await tester.tap(find.text('Open Main.askrypt'));
    await pumpUntil(tester, () => shown('Next'));
    await tester.enterText(find.byType(TextField).first, 'Rex');
    await tester.tap(find.text('Next'));
    await pumpUntil(
        tester, () => find.byType(TextField).evaluate().length >= 2);
    await tester.enterText(find.byType(TextField).at(1), 'Kazan');
    await tester.tap(find.text('Unlock'));
    await pumpUntil(tester, () => shown('No entries'));

    // Edit and save: overwrites the same vault with If-Match.
    await addEntry(tester, 'GitHub');
    expect(shown('Askrypt •'), isTrue);
    await tester.tap(find.byIcon(Icons.cloud_upload));
    await pumpUntil(tester, () => stored.etag == '${stored.id}-v2');
    expect(await entryNames(tester, stored.bytes), ['GitHub']);
    await pumpUntil(tester, () => shown('Askrypt'));

    // Someone else saves meanwhile; our next save is a conflict.
    stored.bytes = Uint8List.fromList(stored.bytes); // v3
    await addEntry(tester, 'Mail');
    await tester.tap(find.byIcon(Icons.cloud_upload));
    await pumpUntil(tester, () => shown('Changed on another device'));

    // Cancel keeps the unsaved work marked unsaved, and the server untouched.
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(shown('Askrypt •'), isTrue);
    expect(stored.etag, '${stored.id}-v3');

    // Try again and choose to overwrite theirs.
    await tester.tap(find.byIcon(Icons.cloud_upload));
    await pumpUntil(tester, () => shown('Save mine'));
    await tester.tap(find.text('Save mine'));
    await pumpUntil(tester, () => stored.etag == '${stored.id}-v4');
    expect(await entryNames(tester, stored.bytes),
        unorderedEquals(['GitHub', 'Mail']));
    await pumpUntil(tester, () => shown('Askrypt'));
    expect(shown('Askrypt •'), isFalse);
  });

  testWidgets(
      'an unreachable server offers the offline copy, and a save '
      'once it is back is checked against the copy', (tester) async {
    final server = FakeServer();
    final initial = await tester.runAsync(() async => (await AskryptFile.create(
          questions: ['First pet?', 'Birth city?'],
          answers: ['Rex', 'Kazan'],
          entries: const [],
          iterations: 1000,
        ))
            .toBytes());
    final stored = server.add('Main.askrypt', initial!);
    final copies = FakeOfflineCopyStore();
    final io = _NoIo();
    final recent = _Recent()
      ..stored = RecentCloud(
          baseUrl: base, email: email, id: stored.id, name: 'Main.askrypt');

    await tester.pumpWidget(ProviderScope(
      overrides: [
        httpClientProvider.overrideWithValue(server.client),
        serverSessionStoreProvider.overrideWithValue(FakeServerSessionStore()
          ..url = base
          ..session = const ServerSession(
              baseUrl: base, email: email, token: FakeServer.token)),
        recentVaultStoreProvider.overrideWithValue(recent),
        vaultIoProvider.overrideWithValue(io),
        biometricStoreProvider.overrideWithValue(_NoBiometrics()),
        platformSecurityProvider.overrideWithValue(_NoopSecurity()),
        offlineCopyStoreProvider.overrideWithValue(copies),
        ...quietLeakCheckOverrides,
      ],
      child: const AskryptApp(),
    ));
    await tester.pumpAndSettle();

    Future<void> unlock() async {
      await pumpUntil(tester, () => shown('Next'));
      await tester.enterText(find.byType(TextField).first, 'Rex');
      await tester.tap(find.text('Next'));
      await pumpUntil(
          tester, () => find.byType(TextField).evaluate().length >= 2);
      await tester.enterText(find.byType(TextField).at(1), 'Kazan');
      await tester.tap(find.text('Unlock'));
      await pumpUntil(tester, () => shown('No entries'));
    }

    // Online: the download is kept as the offline copy, at its ETag.
    await tester.tap(find.text('Open Main.askrypt'));
    await unlock();
    expect(copies.copies.values.single.etag, stored.etag);
    expect(copies.copies.values.single.bytes, stored.bytes);
    await tester.tap(find.byIcon(Icons.lock));
    await tester.pumpAndSettle();

    // Offline: the copy is offered and opens, marked as a copy.
    server.unreachable = true;
    await tester.tap(find.text('Open Main.askrypt'));
    await pumpUntil(tester, () => shown('Server unreachable'));
    await tester.tap(find.text('Open offline copy'));
    await unlock();
    expect(find.textContaining('Offline copy from'), findsOneWidget);

    // A save while still offline fails, says so, and offers a device copy.
    await addEntry(tester, 'GitHub');
    await tester.tap(find.byIcon(Icons.cloud_upload));
    await pumpUntil(tester, () => shown('Save a copy'));
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(shown('Askrypt •'), isTrue);
    expect(io.saved, isNull);

    // Back online: the save is If-Match'd against the copy's ETag, lands, and
    // the landed bytes become the new copy.
    server.unreachable = false;
    final copiedAt = stored.etag;
    await tester.tap(find.byIcon(Icons.cloud_upload));
    await pumpUntil(tester, () => stored.etag != copiedAt);
    expect(server.requests.last.headers['If-Match'], '"$copiedAt"');
    expect(await entryNames(tester, stored.bytes), ['GitHub']);
    await pumpUntil(tester, () => shown('Askrypt'));
    expect(find.textContaining('Offline copy from'), findsNothing);
    expect(copies.copies.values.single.etag, stored.etag);
  });

  testWidgets('a vault gone from the server loses its offline copy',
      (tester) async {
    final server = FakeServer();
    final copies = FakeOfflineCopyStore();
    await copies.keep(
        offlineLocationOf(const CloudHome(
            baseUrl: base,
            email: email,
            id: 'id-gone',
            name: 'Gone.askrypt',
            etag: 'e')),
        'Gone.askrypt',
        Uint8List(1),
        'e');
    await tester.pumpWidget(ProviderScope(
      overrides: [
        httpClientProvider.overrideWithValue(server.client),
        serverSessionStoreProvider.overrideWithValue(FakeServerSessionStore()
          ..url = base
          ..session = const ServerSession(
              baseUrl: base, email: email, token: FakeServer.token)),
        recentVaultStoreProvider.overrideWithValue(_Recent()
          ..stored = const RecentCloud(
              baseUrl: base,
              email: email,
              id: 'id-gone',
              name: 'Gone.askrypt')),
        offlineCopyStoreProvider.overrideWithValue(copies),
        ...quietLeakCheckOverrides,
      ],
      child: const AskryptApp(),
    ));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Open Gone.askrypt'));
    await pumpUntil(
        tester, () => shown('That vault is no longer on the server.'));
    expect(copies.copies, isEmpty);
  });

  testWidgets('without a session the cloud screen offers browser sign-in',
      (tester) async {
    final server = FakeServer();
    await tester.pumpWidget(ProviderScope(
      overrides: [
        httpClientProvider.overrideWithValue(server.client),
        serverSessionStoreProvider
            .overrideWithValue(FakeServerSessionStore()..url = base),
        recentVaultStoreProvider.overrideWithValue(_Recent()),
        urlOpenerProvider.overrideWithValue((_) async => true),
        ...quietLeakCheckOverrides,
      ],
      child: const AskryptApp(),
    ));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Askrypt Cloud'));
    await tester.pumpAndSettle();
    expect(shown('Sign in with browser'), isTrue);

    await tester.tap(find.text('Sign in with browser'));
    await pumpUntil(tester, () => shown('ABCD-EFGH'));
    expect(shown('The page should show this code.'), isTrue);

    // Leave the screen with the wait still running, so no poll timer is left
    // behind for the test harness to complain about.
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(shown('Sign in with browser'), isTrue);
  });
}
