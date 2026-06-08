/// Phase 2 gate: a full create -> unlock -> edit -> save cycle, entirely in
/// Dart, driven through the Riverpod session layer. Also asserts that summaries
/// never leak secrets and that saved bytes re-open into an equivalent vault.
library;

import 'dart:typed_data';

import 'package:askrypt/crypto/secret_entry.dart';
import 'package:askrypt/crypto/vault.dart';
import 'package:askrypt/session/unlocked_vault.dart';
import 'package:askrypt/session/vault_session.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

const _questions = ['First pet?', 'Birth city?', 'Favorite teacher?'];
const _answers = ['Rex', 'Kazan', 'Mrs Smith'];

/// Cheap KDF cost so the save/open round-trips (which now derive on a real
/// background isolate) stay fast and don't flake under full-suite contention.
const _iters = 1000;

SecretEntry _entry(String name, String secret) => SecretEntry(
      name: name,
      userName: '$name-user',
      secret: secret,
      url: 'https://$name.example',
      notes: 'notes for $name',
      entryType: 'login',
      tags: const ['t1'],
      created: 0,
      modified: 0,
    );

/// Fresh container so each test starts from `VaultLocked`.
ProviderContainer _container() {
  final c = ProviderContainer();
  addTearDown(c.dispose);
  return c;
}

VaultSessionNotifier _notifier(ProviderContainer c) =>
    c.read(vaultSessionProvider.notifier);

void main() {
  test('starts locked', () {
    final c = _container();
    expect(c.read(vaultSessionProvider), isA<VaultLocked>());
  });

  test('create -> add -> save -> unlock round-trips through the session',
      () async {
    // Create + populate.
    final c1 = _container();
    final n1 = _notifier(c1);
    n1.createNew(questions: _questions, answers: _answers, iterations: _iters);
    n1.addEntry(_entry('github', 's3cr3t-gh'));
    n1.addEntry(_entry('email', 's3cr3t-mail'));

    final unlocked = c1.read(vaultSessionProvider) as VaultUnlocked;
    expect(unlocked.vault.entryCount, 2);
    expect(unlocked.vault.isModified, isTrue);

    final bytes = await n1.toBytes();
    // toBytes() clears the dirty flag and re-emits.
    expect((c1.read(vaultSessionProvider) as VaultUnlocked).vault.isModified,
        isFalse);

    // Unlock the saved bytes in a brand-new session.
    final c2 = _container();
    final n2 = _notifier(c2);
    await n2.open(Uint8List.fromList(bytes), _answers);
    final reopened = c2.read(vaultSessionProvider) as VaultUnlocked;
    expect(reopened.vault.entryCount, 2);

    final names = reopened.vault.summaries.map((s) => s.name).toList();
    expect(names, ['github', 'email']);
    // Secret is only available via reveal, not via the summary projection.
    expect(reopened.vault.reveal(0).secret, 's3cr3t-gh');
    expect(reopened.vault.reveal(1).secret, 's3cr3t-mail');
  });

  test('edit (update + delete) then save persists the changes', () async {
    final c1 = _container();
    final n1 = _notifier(c1);
    n1.createNew(questions: _questions, answers: _answers, iterations: _iters);
    n1.addEntry(_entry('alpha', 'a'));
    n1.addEntry(_entry('beta', 'b'));
    n1.addEntry(_entry('gamma', 'c'));

    // Update beta's secret, delete gamma.
    final v = (c1.read(vaultSessionProvider) as VaultUnlocked).vault;
    final updated = v.reveal(1)..secret = 'b-new';
    n1.updateEntry(1, updated);
    n1.removeEntry(2);

    final bytes = await n1.toBytes();

    final c2 = _container();
    final n2 = _notifier(c2);
    await n2.open(Uint8List.fromList(bytes), _answers);
    final v2 = (c2.read(vaultSessionProvider) as VaultUnlocked).vault;

    expect(v2.summaries.map((s) => s.name).toList(), ['alpha', 'beta']);
    expect(v2.reveal(1).secret, 'b-new');
    // modified bumped on update; created preserved.
    expect(v2.reveal(1).modified, greaterThanOrEqualTo(v2.reveal(1).created));
  });

  test('lock clears decrypted state', () {
    final c = _container();
    final n = _notifier(c);
    n.createNew(questions: _questions, answers: _answers);
    expect(c.read(vaultSessionProvider), isA<VaultUnlocked>());
    n.lock();
    expect(c.read(vaultSessionProvider), isA<VaultLocked>());
  });

  test('saved bytes open with the low-level AskryptFile (format parity)',
      () async {
    final c = _container();
    final n = _notifier(c);
    n.createNew(
        questions: _questions,
        answers: _answers,
        translit: true,
        iterations: _iters);
    n.addEntry(_entry('site', 'pw'));
    final bytes = await n.toBytes();

    // Open via the raw crypto API the same way desktop/parity tests do.
    final file = AskryptFile.fromBytes(Uint8List.fromList(bytes));
    expect(file.question0, _questions.first);
    expect(file.translit, isTrue);
    final qd = file.getQuestionsData(_answers.first);
    final entries = file.decrypt(qd, _answers.sublist(1));
    expect(entries.single.secret, 'pw');
  });

  test('wrong answers fail to unlock', () async {
    final c1 = _container();
    final n1 = _notifier(c1);
    n1.createNew(questions: _questions, answers: _answers, iterations: _iters);
    n1.addEntry(_entry('x', 'y'));
    final bytes = Uint8List.fromList(await n1.toBytes());

    final c2 = _container();
    final n2 = _notifier(c2);
    await expectLater(
      n2.open(bytes, const ['Rex', 'WRONG', 'WRONG']),
      throwsA(isA<Object>()),
    );
    // State is unchanged (still locked) after a failed unlock.
    expect(c2.read(vaultSessionProvider), isA<VaultLocked>());
  });

  test('updateQuestions re-keys the vault, keeps entries, re-opens with new answers',
      () async {
    final c1 = _container();
    final n1 = _notifier(c1);
    n1.createNew(questions: _questions, answers: _answers, iterations: _iters);
    n1.addEntry(_entry('keep', 'sekret'));

    // Re-key with a different question/answer set + translit on.
    const newQuestions = ['New Q1?', 'New Q2?'];
    const newAnswers = ['alpha', 'beta'];
    n1.updateQuestions(
        questions: newQuestions, answers: newAnswers, translit: true);

    final v = (c1.read(vaultSessionProvider) as VaultUnlocked).vault;
    expect(v.questions, newQuestions);
    expect(v.translit, isTrue);
    expect(v.isModified, isTrue);
    // Entry survived the re-key.
    expect(v.summaries.single.name, 'keep');

    final bytes = await n1.toBytes();

    // Old answers no longer open it; the new ones do.
    final c2 = _container();
    await expectLater(_notifier(c2).open(Uint8List.fromList(bytes), _answers),
        throwsA(isA<Object>()));

    final c3 = _container();
    final n3 = _notifier(c3);
    await n3.open(Uint8List.fromList(bytes), newAnswers);
    final v3 = (c3.read(vaultSessionProvider) as VaultUnlocked).vault;
    expect(v3.reveal(0).secret, 'sekret');
  });

  test('UnlockedVault.create rejects fewer than 2 questions', () {
    expect(
      () => UnlockedVault.create(
          questions: const ['only one'], answers: const ['a']),
      throwsA(isA<VaultException>()),
    );
  });
}
