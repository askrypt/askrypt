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
import 'package:archive/archive.dart';
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

  test('pbkdf2 matches Rust', () async {
    for (final c in vectors['pbkdf2'] as List) {
      final m = c as Map<String, dynamic>;
      final salt = base64.decode(m['salt_b64'] as String);
      final key = await pbkdf2(m['secret'] as String, salt, m['iterations'] as int);
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

  test('opens a Rust-produced vault', () async {
    final v = vectors['vault'] as Map<String, dynamic>;
    final bytes = base64.decode(v['vault_b64'] as String);
    final file = AskryptFile.fromBytes(Uint8List.fromList(bytes));
    final answers = (v['answers'] as List).cast<String>();

    final qd = await file.getQuestionsData(answers[0]);
    final entries = await file.decrypt(qd, answers.sublist(1));

    final expected = (v['expected_entries'] as List)
        .map((e) => SecretEntry.fromJson(e as Map<String, dynamic>))
        .toList();
    expect(entries.length, expected.length);
    for (var i = 0; i < entries.length; i++) {
      expect(entries[i].toJson(), expected[i].toJson(), reason: 'entry $i');
    }

    // Write stamp (params.host / params.updated_at), pinned by the generator.
    expect(file.host, v['expected_host']);
    expect(file.updatedAt, v['expected_updated_at']);

    // The attachment: not merely carried, but decrypted. Its bytes are a ZIP
    // member of their own, so this is what pins the multi-member reader — and
    // `expected_entries` above is what pins the `attachments` key surviving
    // `toJson`, which is the difference between carrying an attached file and
    // deleting it on the next mobile save.
    final id = v['expected_attachment_id'] as String;
    final blob = file.attachments[id];
    expect(blob, isNotNull, reason: 'the files/ member was not read');
    final meta = entries.last.attachments.single;
    expect(meta.id, id);
    final opened = await file.decryptWithMaster(qd, answers.sublist(1));
    expect(
      utf8.decode(openAttachment(blob!, meta, opened.masterKey)),
      v['expected_attachment_plaintext'],
    );
    expect(opened.entries.last.attachments.single.name, meta.name);

    // The random id is the whole of the member's name, so the archive listing
    // never says what the attached file is called.
    final names = ZipDecoder()
        .decodeBytes(Uint8List.fromList(bytes))
        .files
        .map((f) => f.name);
    expect(names, contains('files/$id'));
    expect(names.any((n) => n.contains(meta.name)), isFalse);
  });

  test('carries attachments across a Dart save, and prunes orphans', () async {
    final v = vectors['vault'] as Map<String, dynamic>;
    final bytes = base64.decode(v['vault_b64'] as String);
    final file = AskryptFile.fromBytes(Uint8List.fromList(bytes));
    final answers = (v['answers'] as List).cast<String>();
    final qd = await file.getQuestionsData(answers[0]);
    final opened = await file.decryptWithMaster(qd, answers.sublist(1));
    final id = v['expected_attachment_id'] as String;

    // A save from this app must keep the blob *and* the reference — it edits
    // neither, but rebuilds the whole archive.
    final resaved = await AskryptFile.create(
      questions: (v['questions'] as List).cast<String>(),
      answers: answers,
      entries: opened.entries,
      iterations: v['iterations'] as int,
      masterKey: opened.masterKey,
      attachments: file.attachments,
    );
    final reread = AskryptFile.fromBytes(resaved.toBytes());
    expect(reread.attachments[id], isNotNull);
    final rq = await reread.getQuestionsData(answers[0]);
    final rOpened = await reread.decryptWithMaster(rq, answers.sublist(1));
    expect(
      utf8.decode(openAttachment(
          reread.attachments[id]!, rOpened.entries.last.attachments.single, rOpened.masterKey)),
      v['expected_attachment_plaintext'],
    );

    // And a blob no entry refers to is dropped rather than written: deleting an
    // attachment has to actually shrink the vault (SPEC.md).
    final stripped = opened.entries.map((e) {
      e.attachments = [];
      return e;
    }).toList();
    final pruned = await AskryptFile.create(
      questions: (v['questions'] as List).cast<String>(),
      answers: answers,
      entries: stripped,
      iterations: v['iterations'] as int,
      masterKey: opened.masterKey,
      attachments: file.attachments,
    );
    expect(pruned.attachments, isEmpty);
  });

  test('stamps host/updated_at, and omits them when absent', () async {
    final file = await AskryptFile.create(
      questions: ['Q one?', 'Q two?'],
      answers: ['a1', 'a2'],
      entries: const [],
      iterations: 1,
      host: 'test-host',
      updatedAt: DateTime.utc(2026, 8, 2, 10, 15, 30, 456),
    );
    expect(file.host, 'test-host');
    expect(file.updatedAt, '2026-08-02T10:15:30Z');

    final params =
        AskryptFile.fromBytes(file.toBytes()).toJson()['params'] as Map;
    expect(params['host'], 'test-host');
    expect(params['updated_at'], '2026-08-02T10:15:30Z');

    // Local time is converted to UTC, matching the Rust stamp.
    expect(formatUtcStamp(DateTime.utc(2026, 1, 2, 3, 4, 5).toLocal()),
        '2026-01-02T03:04:05Z');

    // Pre-stamp files load, and round-trip without inventing the keys.
    final legacy = AskryptFile(
      version: '0.9',
      question0: 'Q0',
      kdf: 'pbkdf2',
      iterations: 1,
      salt0B64: 'c2FsdA==',
      translit: false,
      qs: 'qs',
      master: 'master',
      data: 'data',
    );
    expect((legacy.toJson()['params'] as Map).containsKey('host'), isFalse);
    expect(
        (legacy.toJson()['params'] as Map).containsKey('updated_at'), isFalse);
  });

  test('Dart-created vault round-trips through Dart', () async {
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
    final file = await AskryptFile.create(
      questions: questions,
      answers: answers,
      entries: entries,
      iterations: 1000,
      translit: true,
    );
    final reopened = AskryptFile.fromBytes(file.toBytes());
    final qd = await reopened.getQuestionsData(answers[0]);
    expect(qd.questions, questions.sublist(1));
    final out = await reopened.decrypt(qd, answers.sublist(1));
    expect(out.single.toJson(), entries.single.toJson());
  });

  test('carries the card fields it has no UI for', () {
    // This app shows and edits none of the `card_*` fields, so the only thing
    // that can go wrong is losing them: `toJson` writes a fixed key list, and
    // a key it forgets is deleted from the vault on the next save.
    final json = {
      'name': 'Personal Visa',
      'user_name': '',
      'secret': '',
      'url': '',
      'notes': '',
      'type': 'Card',
      'tags': <String>[],
      'created': 1704067200,
      'modified': 1704153600,
      'hidden': false,
      'card_holder': 'Ruslan A.',
      'card_brand': 'Visa',
      'card_number': '4242 4242 4242 4242',
      'card_expiry': '04/29',
      'card_cvv': '123',
      'card_pin': '9876',
    };

    expect(SecretEntry.fromJson(json).toJson(), json);
  });

  test('omits the card keys on an entry that is not a card', () {
    // Rust marks all six `skip_serializing_if = "String::is_empty"`; writing
    // them as empty strings here would make every login entry bigger than the
    // desktop app writes it.
    final login = SecretEntry(
      name: 'site',
      userName: 'bob',
      secret: 's3cr3t',
      url: '',
      notes: '',
      entryType: 'password',
      tags: const [],
      created: 1,
      modified: 2,
    );

    expect(login.toJson().keys.where((k) => k.startsWith('card_')), isEmpty);
  });
}
