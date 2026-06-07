/// Cross-implementation parity tests.
///
/// Asserts the Dart crypto core matches the Rust core byte-for-byte against the
/// golden vectors committed at `test/fixtures/vectors.json`. Regenerate those
/// with `cargo run -p askrypt-core --example gen_vectors` whenever the format or
/// normalization rules change — drift between Rust and Dart fails here.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:askrypt/crypto/aes.dart';
import 'package:askrypt/crypto/kdf.dart';
import 'package:askrypt/crypto/normalize.dart';
import 'package:askrypt/crypto/secret_entry.dart';
import 'package:askrypt/crypto/translit.dart';
import 'package:askrypt/crypto/vault.dart';
import 'package:flutter_test/flutter_test.dart';

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final vectors = jsonDecode(
    File('test/fixtures/vectors.json').readAsStringSync(),
  ) as Map<String, dynamic>;

  test('normalize matches Rust', () {
    for (final c in vectors['normalize'] as List) {
      final m = c as Map<String, dynamic>;
      expect(
        normalizeAnswer(m['input'] as String, m['translit'] as bool),
        m['expected'],
        reason: 'normalize ${m['input']}',
      );
    }
  });

  test('transliterate matches Rust', () {
    for (final c in vectors['transliterate'] as List) {
      final m = c as Map<String, dynamic>;
      expect(transliterate(m['input'] as String), m['expected'],
          reason: 'translit ${m['input']}');
    }
  });

  test('sha256 hex matches Rust', () {
    for (final c in vectors['sha256'] as List) {
      final m = c as Map<String, dynamic>;
      expect(sha256Hex(m['data'] as String, m['salt'] as String),
          m['expected_hex'],
          reason: 'sha256 ${m['data']}');
    }
  });

  test('pbkdf2 matches Rust', () {
    for (final c in vectors['pbkdf2'] as List) {
      final m = c as Map<String, dynamic>;
      final salt = base64.decode(m['salt_b64'] as String);
      final key = pbkdf2(m['secret'] as String, salt, m['iterations'] as int);
      expect(_hex(key), m['key_hex'],
          reason: 'pbkdf2 ${m['secret']} x${m['iterations']}');
    }
  });

  test('aes-256-cbc + pkcs7 matches Rust', () {
    for (final c in vectors['aes_cbc_pkcs7'] as List) {
      final m = c as Map<String, dynamic>;
      final pt = base64.decode(m['plaintext_b64'] as String);
      final key = base64.decode(m['key_b64'] as String);
      final iv = base64.decode(m['iv_b64'] as String);
      final ct = aesCbcEncrypt(pt, key, iv);
      expect(base64.encode(ct), m['ciphertext_b64'], reason: 'aes encrypt');
      // round-trip decrypt
      expect(aesCbcDecrypt(ct, key, iv), pt, reason: 'aes decrypt');
    }
  });

  test('opens a Rust-produced vault', () {
    final v = vectors['vault'] as Map<String, dynamic>;
    final bytes = base64.decode(v['vault_b64'] as String);
    final file = AskryptFile.fromBytes(Uint8List.fromList(bytes));
    final answers = (v['answers'] as List).cast<String>();

    final qd = file.getQuestionsData(answers[0]);
    final entries = file.decrypt(qd, answers.sublist(1));

    final expected = (v['expected_entries'] as List)
        .map((e) => SecretEntry.fromJson(e as Map<String, dynamic>))
        .toList();
    expect(entries.length, expected.length);
    for (var i = 0; i < entries.length; i++) {
      expect(entries[i].toJson(), expected[i].toJson(), reason: 'entry $i');
    }
  });

  test('Dart-created vault round-trips through Dart', () {
    final questions = ['Q one?', 'Q two?', 'Q three?'];
    final answers = ['Ответ Один', 'answer-two', 'Answer Three'];
    final entries = [
      SecretEntry(
        name: 'site',
        userName: 'bob',
        secret: 's3cr3t',
        url: 'https://x.test',
        notes: 'n',
        entryType: 'password',
        tags: ['a'],
        created: 1,
        modified: 2,
        hidden: false,
      ),
    ];
    final file = AskryptFile.create(
      questions: questions,
      answers: answers,
      entries: entries,
      iterations: 1000,
      translit: true,
    );
    final reopened = AskryptFile.fromBytes(file.toBytes());
    final qd = reopened.getQuestionsData(answers[0]);
    expect(qd.questions, questions.sublist(1));
    final out = reopened.decrypt(qd, answers.sublist(1));
    expect(out.single.toJson(), entries.single.toJson());
  });
}
