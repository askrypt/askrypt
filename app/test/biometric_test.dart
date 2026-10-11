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
import 'package:askrypt/session/cloud_session.dart';
import 'package:askrypt/platform/vault_io.dart';
import 'package:askrypt/session/vault_session.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'cloud_fakes.dart';

/// In-memory [BiometricStore] keyed like the real one, by [biometricIdFor]
/// of the vault's full question list.
class FakeBiometricStore implements BiometricStore {
  FakeBiometricStore({this.available = true, this.authSucceeds = true});

  bool available;
  bool authSucceeds;
  bool throwOnReveal = false;
  final Map<String, BiometricCredential> store = {};
  int forgotten = 0;

  void seed(List<String> questions, List<String> answers) {
    final id = biometricIdFor(questions);
    store[id] =
        BiometricCredential(id: id, questions: questions, answers: answers);
  }

  List<String>? answersFor(List<String> questions) =>
      store[biometricIdFor(questions)]?.answers;

  @override
  Future<bool> canUse() async => available;

  @override
  Future<bool> hasCredentialFor(String question0) async =>
      store.keys.any((k) => k.startsWith(biometricPrefixFor(question0)));

  @override
  Future<bool> contains(String id) async => store.containsKey(id);

  @override
  Future<bool> enroll(List<String> questions, List<String> answers) async {
    if (!authSucceeds) return false;
    seed(questions, answers);
    return true;
  }

  @override
  Future<List<BiometricCredential>?> reveal(String question0) async {
    if (throwOnReveal) {
      store.clear();
      throw const BiometricStoreException('unreadable');
    }
    if (!authSucceeds) return null;
    return store.values
        .where((c) => c.questions.first == question0)
        .toList();
  }

  @override
  Future<void> replace(
      String? oldId, List<String> questions, List<String> answers) async {
    seed(questions, answers);
    final id = biometricIdFor(questions);
    if (oldId != null && oldId != id) store.remove(oldId);
  }

  @override
  Future<void> forget(String id) async {
    store.remove(id);
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
  @override
  Future<String?> saveAttachment(String name, Uint8List bytes) async =>
      '/tmp/$name';
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
  Future<Uint8List> makeVault(
          List<String> questions, List<String> answers) async =>
      (await AskryptFile.create(
        questions: questions,
        answers: answers,
        entries: const [],
        iterations: 1000,
      ))
          .toBytes();

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
          serverSessionStoreProvider.overrideWithValue(FakeServerSessionStore()),
          platformSecurityProvider.overrideWithValue(NoopPlatformSecurity()),
          ...quietLeakCheckOverrides,
        ],
        child: const AskryptApp(),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('manual unlock offers enrollment, which stores the answers',
      (tester) async {
    final bytes = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore(); // available, nothing stored

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
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
    expect(bio.answersFor(['First pet?', 'Birth city?']), ['Rex', 'Kazan']);
  });

  // The inline knowledge check replaces the manual form with a single field
  // for one randomly picked question; figure out which from the rendered
  // label. Its "Enter all answers" fall-back button marks check mode.
  String checkQuestion(List<String> questions) {
    for (final q in questions) {
      if (find.text(q).evaluate().isNotEmpty) return q;
    }
    fail('knowledge check shows none of the known questions');
  }

  bool checkShown() => find.text('Enter all answers').evaluate().isNotEmpty;

  testWidgets('stored credentials unlock after one random answer',
      (tester) async {
    const answers = {'First pet?': 'Rex', 'Birth city?': 'Kazan'};
    final bytes = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
    // The auto-triggered biometric reveal leads to the inline knowledge check
    // (a hidden question first needs a derivation on a background isolate).
    await pumpUntil(tester, checkShown);

    final q = checkQuestion(answers.keys.toList());
    await tester.enterText(find.byType(TextField), answers[q]!);
    await tester.tap(find.text('Unlock'));
    await pumpUntil(tester, () => find.text('No entries').evaluate().isNotEmpty);

    expect(find.text('No entries'), findsOneWidget);
  });

  testWidgets('wrong random answer shows an error and allows retry',
      (tester) async {
    const answers = {'First pet?': 'Rex', 'Birth city?': 'Kazan'};
    final bytes = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
    await pumpUntil(tester, checkShown);

    await tester.enterText(find.byType(TextField), 'nope');
    await tester.tap(find.text('Unlock'));
    await tester.pumpAndSettle();

    // The check stays up with an inline error; retrying with the right answer
    // unlocks.
    expect(find.text('Incorrect answer.'), findsOneWidget);
    expect(checkShown(), isTrue);
    final q = checkQuestion(answers.keys.toList());
    await tester.enterText(find.byType(TextField), answers[q]!);
    await tester.tap(find.text('Unlock'));
    await pumpUntil(tester, () => find.text('No entries').evaluate().isNotEmpty);

    expect(find.text('No entries'), findsOneWidget);
  });

  testWidgets('random-answer check can fall back to manual entry',
      (tester) async {
    final bytes = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
    await pumpUntil(tester, checkShown);

    await tester.tap(find.text('Enter all answers'));
    await tester.pumpAndSettle();

    // Back on the manual form, credential kept so biometrics can be retried.
    expect(checkShown(), isFalse);
    expect(find.text('Unlock with biometrics'), findsOneWidget);
    expect(find.text('Next'), findsOneWidget);
    expect(bio.answersFor(['First pet?', 'Birth city?']), isNotNull);
    expect(bio.forgotten, 0);
  });

  /// Manually unlocks the open unlock screen with [answers] (two questions).
  Future<void> typeAnswers(WidgetTester tester, List<String> answers) async {
    await tester.enterText(find.byType(TextField).first, answers[0]);
    await tester.tap(find.text('Next'));
    await pumpUntil(
        tester, () => find.byType(TextField).evaluate().length >= 2);
    await tester.enterText(find.byType(TextField).at(1), answers[1]);
    await tester.tap(find.text('Unlock'));
  }

  testWidgets('stale answers for the same questions are forgotten and '
      're-offered', (tester) async {
    final bytes = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    // Same questions, but the answers were changed on another device. The
    // first answer still matches, so the question list decrypts and matches.
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Moscow']);

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
    await pumpUntil(tester, checkShown);
    final q = checkQuestion(['First pet?', 'Birth city?']);
    await tester.enterText(
        find.byType(TextField), q == 'First pet?' ? 'Rex' : 'Moscow');
    await tester.tap(find.text('Unlock'));
    await pumpUntil(tester, () => bio.forgotten == 1);

    expect(bio.store, isEmpty);
    expect(find.textContaining('no longer open this vault'), findsOneWidget);

    // A manual unlock offers enrollment again and stores the new answers.
    await typeAnswers(tester, ['Rex', 'Kazan']);
    await pumpUntil(tester,
        () => find.text('Enable biometric unlock?').evaluate().isNotEmpty);
    await tester.tap(find.text('Enable'));
    await tester.pumpAndSettle();
    expect(bio.answersFor(['First pet?', 'Birth city?']), ['Rex', 'Kazan']);
  });

  testWidgets('vaults sharing a first question keep separate credentials',
      (tester) async {
    final a = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final b = await makeVault(['First pet?', 'Favourite band?'], ['Tom', 'Queen']);
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Kazan'])
      ..seed(['First pet?', 'Favourite band?'], ['Tom', 'Queen']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: b, name: 'b.askrypt');

    await pumpApp(tester, io: io, bio: bio);

    // Vault B picks its own credential out of the two.
    await tester.tap(find.text('Open vault (file)'));
    await pumpUntil(tester, checkShown);
    const bAnswers = {'First pet?': 'Tom', 'Favourite band?': 'Queen'};
    final q = checkQuestion(bAnswers.keys.toList());
    await tester.enterText(find.byType(TextField), bAnswers[q]!);
    await tester.tap(find.text('Unlock'));
    await pumpUntil(tester, () => find.text('No entries').evaluate().isNotEmpty);

    expect(bio.forgotten, 0);
    expect(bio.store, hasLength(2));
    expect(a, isNotEmpty);
  });

  testWidgets('an unenrolled vault sharing a first question is told so and '
      'offered enrollment', (tester) async {
    final b = await makeVault(['First pet?', 'Favourite band?'], ['Tom', 'Queen']);
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: b, name: 'b.askrypt');

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
    await pumpUntil(tester,
        () => find.textContaining('No saved answers match').evaluate().isNotEmpty);
    expect(checkShown(), isFalse);

    await typeAnswers(tester, ['Tom', 'Queen']);
    await pumpUntil(tester,
        () => find.text('Enable biometric unlock?').evaluate().isNotEmpty);
    await tester.tap(find.text('Enable'));
    await tester.pumpAndSettle();

    // Both vaults now have their own credential; A's was never touched.
    expect(bio.forgotten, 0);
    expect(bio.answersFor(['First pet?', 'Birth city?']), ['Rex', 'Kazan']);
    expect(bio.answersFor(['First pet?', 'Favourite band?']), ['Tom', 'Queen']);
  });

  testWidgets('unreadable stored answers show an error, not a silent fallback',
      (tester) async {
    final bytes = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Kazan'])
      ..throwOnReveal = true;

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
    await pumpUntil(tester,
        () => find.textContaining("couldn't be read").evaluate().isNotEmpty);
    expect(find.text('Unlock with biometrics'), findsNothing);
    expect(find.text('Next'), findsOneWidget);
  });

  testWidgets('saving a questions change moves the credential', (tester) async {
    final bytes = await makeVault(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);
    final io = FakeVaultIo()
      ..toPick = PickedVault(bytes: bytes, name: 'vault.askrypt');
    final bio = FakeBiometricStore()
      ..seed(['First pet?', 'Birth city?'], ['Rex', 'Kazan']);

    await pumpApp(tester, io: io, bio: bio);

    await tester.tap(find.text('Open vault (file)'));
    await pumpUntil(tester, checkShown);
    const answers = {'First pet?': 'Rex', 'Birth city?': 'Kazan'};
    final q = checkQuestion(answers.keys.toList());
    await tester.enterText(find.byType(TextField), answers[q]!);
    await tester.tap(find.text('Unlock'));
    await pumpUntil(tester, () => find.text('No entries').evaluate().isNotEmpty);

    final container = ProviderScope.containerOf(
        tester.element(find.text('No entries')));
    container.read(vaultSessionProvider.notifier).updateQuestions(
      questions: ['First pet?', 'Best friend?'],
      answers: ['Rex', 'Ann'],
      translit: false,
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Save'));
    await pumpUntil(
        tester, () => find.text('Vault saved').evaluate().isNotEmpty);

    expect(bio.answersFor(['First pet?', 'Birth city?']), isNull);
    expect(bio.answersFor(['First pet?', 'Best friend?']), ['Rex', 'Ann']);
    expect(container.read(biometricIdProvider),
        biometricIdFor(['First pet?', 'Best friend?']));

    // Disabling forgets exactly that credential.
    await tester.tap(find.byWidgetPredicate((w) => w is PopupMenuButton).first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Disable biometric unlock'));
    await tester.pumpAndSettle();
    expect(bio.store, isEmpty);
  });
}
