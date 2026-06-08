/// Widget tests for Phase 4 biometric quick-unlock, driven through the real app
/// shell with fakes for the biometric store, file picker, and platform-security
/// channel so no real biometrics or platform channels are involved.
///
/// Vaults are built with a tiny PBKDF2 iteration count to keep derivation fast.
library;

import 'dart:typed_data';

import 'package:askrypt/app.dart';
import 'package:askrypt/crypto/vault.dart';
import 'package:askrypt/platform/biometric_store.dart';
import 'package:askrypt/platform/platform_security.dart';
import 'package:askrypt/platform/vault_io.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

/// In-memory [BiometricStore] keyed by question0 (the real impl hashes the key
/// internally, but the interface is question0-based).
class FakeBiometricStore implements BiometricStore {
  FakeBiometricStore({this.available = true, this.authSucceeds = true});

  bool available;
  bool authSucceeds;
  final Map<String, List<String>> store = {};
  int forgotten = 0;

  void seed(String question0, List<String> answers) =>
      store[question0] = answers;

  @override
  Future<bool> canUse() async => available;

  @override
  Future<bool> hasCredentialFor(String question0) async =>
      store.containsKey(question0);

  @override
  Future<bool> save(String question0, List<String> answers) async {
    if (!authSucceeds) return false;
    store[question0] = answers;
    return true;
  }

  @override
  Future<List<String>?> reveal(String question0) async =>
      authSucceeds ? store[question0] : null;

  @override
  Future<void> forget(String question0) async {
    store.remove(question0);
    forgotten++;
  }
}

class NoopPlatformSecurity implements PlatformSecurity {
  @override
  Future<void> setSecureFlag(bool secure) async {}
  @override
  Future<void> copySensitive(String text) async {}
}

class FakeVaultIo implements VaultIo {
  PickedVault? toPick;
  @override
  Future<PickedVault?> pickVault() async => toPick;
  @override
  Future<String?> saveVault(Uint8List bytes,
          {String suggestedName = 'vault.askrypt'}) async =>
      '/tmp/$suggestedName';
}

/// Pumps real *and* fake async until [condition] holds (or times out). Unlock
/// now derives keys on a real background isolate (`Isolate.run`), which the
/// default fake-async `pumpAndSettle` never advances; alternating `runAsync`
/// (lets the isolate result land) with `pump` (renders the resulting frame)
/// drives these flows to completion.
Future<void> pumpUntil(
  WidgetTester tester,
  bool Function() condition, {
  Duration timeout = const Duration(seconds: 20),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('pumpUntil timed out waiting for condition');
    }
    await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 20)));
    await tester.pump();
  }
  await tester.pumpAndSettle();
}

void main() {
  // A known 2-question vault with no entries, cheap to derive.
  Uint8List makeVault(List<String> questions, List<String> answers) =>
      AskryptFile.create(
        questions: questions,
        answers: answers,
        entries: const [],
        iterations: 1000,
      ).toBytes();

  Future<void> pumpApp(
    WidgetTester tester, {
    required FakeVaultIo io,
    required FakeBiometricStore bio,
  }) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          vaultIoProvider.overrideWithValue(io),
          biometricStoreProvider.overrideWithValue(bio),
          platformSecurityProvider.overrideWithValue(NoopPlatformSecurity()),
        ],
        child: const AskryptApp(),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('manual unlock offers enrollment, which stores the answers',
      (tester) async {
    final bytes = makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore(); // available, nothing stored

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault'));
    await tester.pumpAndSettle();

    // No biometric button (nothing enrolled yet).
    expect(find.text('Unlock with biometrics'), findsNothing);

    // Answer the first question, reveal the rest, answer them, unlock. The
    // derivations run on a background isolate, so wait with pumpUntil.
    await tester.enterText(find.byType(TextField).first, 'Rex');
    await tester.tap(find.text('Next'));
    await pumpUntil(
        tester, () => find.byType(TextField).evaluate().length >= 2);
    await tester.enterText(find.byType(TextField).at(1), 'Kazan');
    await tester.tap(find.text('Unlock'));
    await pumpUntil(tester,
        () => find.text('Enable biometric unlock?').evaluate().isNotEmpty);

    // Enrollment dialog appears; accept it.
    expect(find.text('Enable biometric unlock?'), findsOneWidget);
    await tester.tap(find.text('Enable'));
    await tester.pumpAndSettle();

    // Landed on the entries screen and the answers were stored.
    expect(find.text('No entries'), findsOneWidget);
    expect(bio.store['First pet?'], ['Rex', 'Kazan']);
  });

  testWidgets('stored credentials auto-unlock without typing', (tester) async {
    final bytes = makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore()..seed('First pet?', ['Rex', 'Kazan']);

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault'));
    // Auto-triggered biometric unlock decrypts on a background isolate.
    await pumpUntil(tester, () => find.text('No entries').evaluate().isNotEmpty);

    // Auto-triggered biometric unlock landed us on the entries screen with no
    // typed answers.
    expect(find.text('No entries'), findsOneWidget);
  });

  testWidgets('stale stored credentials are forgotten and fall back to manual',
      (tester) async {
    final bytes = makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    // Wrong answers for this vault (e.g. questions were re-keyed elsewhere).
    final bio = FakeBiometricStore()..seed('First pet?', ['Wrong', 'Answers']);

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault'));
    // The stale credential's answers are tried on a background isolate, fail,
    // and the credential is forgotten.
    await pumpUntil(tester, () => bio.forgotten == 1);

    // Stayed on the unlock screen, credential dropped, error shown.
    expect(bio.forgotten, 1);
    expect(bio.store.containsKey('First pet?'), isFalse);
    expect(find.textContaining('no longer open this vault'), findsOneWidget);
  });
}
