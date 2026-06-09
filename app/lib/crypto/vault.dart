/// Askrypt vault format — pure-Dart port of `AskryptFile` (`core/src/lib.rs`).
///
/// Reads and writes byte-compatible `vault.askrypt` files (ZIP containing
/// `askrypt.json`). The layered scheme:
///   - first answer       -> derives first-key -> decrypts `qs` (remaining Qs)
///   - all answers joined  -> derives second-key -> decrypts `master` (key+iv)
///   - master key+iv       -> decrypts `data` (the entry list)
/// IV for the first two layers is that layer's salt; `data` uses the stored iv.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:archive/archive.dart';

import 'aes.dart';
import 'kdf.dart';
import 'normalize.dart';
import 'secret_entry.dart';

const String _version = '0.9';
const String _defaultKdf = 'pbkdf2';
const int defaultIterations = 600000;
const String _zipEntryName = 'askrypt.json';

/// Remaining questions + the second-level salt (the decrypted `qs` blob).
class QuestionsData {
  QuestionsData(this.questions, this.saltB64);
  final List<String> questions;
  final String saltB64;

  factory QuestionsData.fromJson(Map<String, dynamic> j) => QuestionsData(
        (j['questions'] as List<dynamic>).cast<String>(),
        j['salt'] as String,
      );
  Map<String, dynamic> toJson() => {'questions': questions, 'salt': saltB64};
}

class VaultException implements Exception {
  VaultException(this.message);
  final String message;
  @override
  String toString() => 'VaultException: $message';
}

class AskryptFile {
  AskryptFile({
    required this.version,
    required this.question0,
    required this.kdf,
    required this.iterations,
    required this.salt0B64,
    required this.translit,
    required this.qs,
    required this.master,
    required this.data,
  });

  final String version;
  final String question0;
  final String kdf;
  final int iterations;
  final String salt0B64; // params.salt
  final bool translit;
  final String qs;
  final String master;
  final String data;

  // --- parsing / serialization (ZIP <-> askrypt.json) ---

  factory AskryptFile.fromJson(Map<String, dynamic> j) {
    final params = j['params'] as Map<String, dynamic>;
    return AskryptFile(
      version: j['version'] as String,
      question0: j['question0'] as String,
      kdf: params['kdf'] as String,
      iterations: params['iterations'] as int,
      salt0B64: params['salt'] as String,
      translit: (params['translit'] as bool?) ?? false,
      qs: j['qs'] as String,
      master: j['master'] as String,
      data: j['data'] as String,
    );
  }

  Map<String, dynamic> toJson() => {
        'version': version,
        'question0': question0,
        'params': {
          'kdf': kdf,
          'iterations': iterations,
          'salt': salt0B64,
          'translit': translit,
        },
        'qs': qs,
        'master': master,
        'data': data,
      };

  factory AskryptFile.fromBytes(Uint8List bytes) {
    final archive = ZipDecoder().decodeBytes(bytes);
    final entry = archive.findFile(_zipEntryName);
    if (entry == null) {
      throw VaultException('archive missing $_zipEntryName');
    }
    final json = utf8.decode(entry.content as List<int>);
    final file = AskryptFile.fromJson(jsonDecode(json) as Map<String, dynamic>);
    if (file.version != _version) {
      throw VaultException('unsupported version: ${file.version}');
    }
    return file;
  }

  Uint8List toBytes() {
    final json = utf8.encode(jsonEncode(toJson()));
    final archive = Archive()
      ..addFile(ArchiveFile(_zipEntryName, json.length, json));
    final encoded = ZipEncoder().encode(archive);
    return Uint8List.fromList(encoded!);
  }

  // --- decryption (layered unlock) ---

  /// Decrypt the remaining questions using the first answer.
  ///
  /// Async because the PBKDF2 derivation is delegated to native platform
  /// crypto (see [pbkdf2]); awaiting it on the UI isolate is fine since the
  /// native work doesn't block the Dart event loop.
  Future<QuestionsData> getQuestionsData(String firstAnswer) async {
    final salt0 = base64.decode(salt0B64);
    final hashed = sha256Hex(normalizeAnswer(firstAnswer, translit), salt0B64);
    final firstKey = await pbkdf2(hashed, salt0, iterations);
    final plain = aesCbcDecrypt(base64.decode(qs), firstKey, salt0);
    return QuestionsData.fromJson(
        jsonDecode(utf8.decode(plain)) as Map<String, dynamic>);
  }

  /// Decrypt the entry list given the remaining answers (questions 2..n).
  Future<List<SecretEntry>> decrypt(QuestionsData qd, List<String> answers) async {
    if (answers.isEmpty) {
      throw VaultException('at least 1 answer required');
    }
    if (qd.questions.length != answers.length) {
      throw VaultException('questions/answers count mismatch');
    }
    final salt1 = base64.decode(qd.saltB64);
    final combined =
        answers.map((a) => normalizeAnswer(a, translit)).join();
    final secondKey = await pbkdf2(sha256Hex(combined, salt0B64), salt1, iterations);

    final masterJson = utf8.decode(aesCbcDecrypt(base64.decode(master), secondKey, salt1));
    final md = jsonDecode(masterJson) as Map<String, dynamic>;
    final masterKey = base64.decode(md['masterKey'] as String);
    final iv = base64.decode(md['iv'] as String);

    final dataJson = utf8.decode(aesCbcDecrypt(base64.decode(data), masterKey, iv));
    final list = jsonDecode(dataJson) as List<dynamic>;
    return list
        .map((e) => SecretEntry.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  // --- creation (mirror of AskryptFile::create) ---

  static Future<AskryptFile> create({
    required List<String> questions,
    required List<String> answers,
    required List<SecretEntry> entries,
    int iterations = defaultIterations,
    bool translit = false,
    Random? rng,
  }) async {
    if (questions.length < 2) {
      throw VaultException('at least 2 questions required');
    }
    if (questions.length != answers.length) {
      throw VaultException('questions/answers count mismatch');
    }
    for (final q in questions) {
      if (q.length > 500) {
        throw VaultException('question length must not exceed 500 characters');
      }
    }

    final norm = answers.map((a) => normalizeAnswer(a, translit)).toList();
    final r = rng ?? Random.secure();
    final salt0 = _randomBytes(16, r);
    final salt1 = _randomBytes(16, r);
    final masterKey = _randomBytes(32, r);
    final iv = _randomBytes(16, r);
    final salt0B64 = base64.encode(salt0);

    // Layer 1: first answer -> first-key -> encrypt remaining questions.
    final firstKey = await pbkdf2(sha256Hex(norm[0], salt0B64), salt0, iterations);
    final qd = QuestionsData(questions.sublist(1), base64.encode(salt1));
    final qs = base64.encode(
        aesCbcEncrypt(_jsonBytes(qd.toJson()), firstKey, salt0));

    // Layer 2: all remaining answers -> second-key -> encrypt master key+iv.
    final combined = norm.sublist(1).join();
    final secondKey = await pbkdf2(sha256Hex(combined, salt0B64), salt1, iterations);
    final masterData = {'masterKey': base64.encode(masterKey), 'iv': base64.encode(iv)};
    final master =
        base64.encode(aesCbcEncrypt(_jsonBytes(masterData), secondKey, salt1));

    // Layer 3: master key+iv -> encrypt entry list.
    final dataJson = entries.map((e) => e.toJson()).toList();
    final data = base64.encode(aesCbcEncrypt(_jsonBytes(dataJson), masterKey, iv));

    return AskryptFile(
      version: _version,
      question0: questions[0],
      kdf: _defaultKdf,
      iterations: iterations,
      salt0B64: salt0B64,
      translit: translit,
      qs: qs,
      master: master,
      data: data,
    );
  }
}

Uint8List _jsonBytes(Object value) =>
    Uint8List.fromList(utf8.encode(jsonEncode(value)));

Uint8List _randomBytes(int n, Random r) {
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = r.nextInt(256);
  }
  return out;
}
