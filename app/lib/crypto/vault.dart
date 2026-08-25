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

/// The prefix every file-attachment ZIP member carries. The rest of the name is
/// the attachment's id and nothing else, so the archive listing of a vault says
/// how many files it holds but never what they are called. Mirrors
/// `ATTACHMENT_PREFIX` in `core/src/lib.rs`.
const String attachmentPrefix = 'files/';

/// Ceiling on the *inflated* bytes of all attachments in one archive.
///
/// A bound on what a **crafted** file can make a reader allocate, not a limit
/// on what anyone may attach: this app inflates every member into memory to
/// open a vault, so a hundred deflated members of zeros would be a zip bomb
/// waiting to be handed to it.
///
/// It is a property of *this reader*, not of the format — `SPEC.md` says so —
/// and the Rust core no longer has a counterpart: it streams members instead of
/// inflating them, so there is nothing for a ceiling to bound. A vault whose
/// attachments exceed this opens on the desktop and not here, which is the
/// honest trade for an app that holds them in memory.
const int maxAttachmentBytes = 256 * 1024 * 1024;

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
    this.host,
    this.updatedAt,
    required this.qs,
    required this.master,
    required this.data,
    Map<String, Uint8List>? attachments,
  }) : attachments = attachments ?? <String, Uint8List>{};

  final String version;
  final String question0;
  final String kdf;
  final int iterations;
  final String salt0B64; // params.salt
  final bool translit;

  /// Name of the host that last wrote the vault (`params.host`), or `null` for
  /// files written before the stamp existed. Stored **unencrypted**.
  final String? host;

  /// When the vault was last written (`params.updated_at`), RFC 3339 UTC with
  /// second precision (e.g. `2026-08-02T10:15:30Z`); `null` in older files.
  final String? updatedAt;

  final String qs;
  final String master;
  final String data;

  /// The encrypted bytes of every file attached to an entry, keyed by
  /// [Attachment.id]. **Not part of `askrypt.json`** — these are ZIP members of
  /// their own, read by [fromBytes] and written by [toBytes].
  ///
  /// This app does not add or remove attachments, but it must carry these
  /// across a save or one edit here deletes every attached file in the vault.
  final Map<String, Uint8List> attachments;

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
      host: params['host'] as String?,
      updatedAt: params['updated_at'] as String?,
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
          // Omitted when absent, matching the Rust `skip_serializing_if`.
          if (host != null) 'host': host,
          if (updatedAt != null) 'updated_at': updatedAt,
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
    // Every `files/` member is an attachment's ciphertext, named by its id.
    // Anything else in the archive is ignored, as it was before attachments
    // existed.
    var total = 0;
    for (final member in archive.files) {
      if (!member.name.startsWith(attachmentPrefix)) continue;
      final id = member.name.substring(attachmentPrefix.length);
      if (id.isEmpty) continue;
      // Checked against the declared size before touching `content`, which is
      // what triggers the decompression.
      total += member.size;
      if (total > maxAttachmentBytes) {
        throw VaultException('vault attachments are implausibly large');
      }
      file.attachments[id] = Uint8List.fromList(member.content as List<int>);
    }
    return file;
  }

  Uint8List toBytes() {
    final json = utf8.encode(jsonEncode(toJson()));
    final archive = Archive()
      ..addFile(ArchiveFile(_zipEntryName, json.length, json));
    // Deflated, like `askrypt.json` — every member of the archive is written
    // the same way, which is `ArchiveFile.compress`'s default. It buys no space
    // (the body is AES-CBC ciphertext, which does not compress), so this is
    // uniformity rather than economy.
    final ids = attachments.keys.toList()..sort();
    for (final id in ids) {
      final blob = attachments[id]!;
      archive.addFile(ArchiveFile('$attachmentPrefix$id', blob.length, blob));
    }
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
  Future<List<SecretEntry>> decrypt(QuestionsData qd, List<String> answers) async =>
      (await decryptWithMaster(qd, answers)).entries;

  /// Decrypt the entry list *and* hand back the vault's master key.
  ///
  /// This is the call anything that will save the vault again should make:
  /// feeding the recovered key back into [create] re-wraps it instead of
  /// rotating it, so blobs encrypted under it stay readable across the write.
  /// The key falls out of the same derivation that opens the vault, so it costs
  /// nothing over [decrypt] — mirrors `AskryptFile::decrypt_with_master` in
  /// `core/src/lib.rs`.
  Future<({List<SecretEntry> entries, Uint8List masterKey})> decryptWithMaster(
      QuestionsData qd, List<String> answers) async {
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
    final entries = list
        .map((e) => SecretEntry.fromJson(e as Map<String, dynamic>))
        .toList();
    return (entries: entries, masterKey: masterKey);
  }

  // --- creation (mirror of AskryptFile::create) ---

  /// Build a vault file from questions, answers and entries.
  ///
  /// [masterKey] is the vault's existing 32-byte master key, recovered by
  /// [decryptWithMaster]. Pass it on **every** save of an already-open vault —
  /// including one that changes the questions — so that everything encrypted
  /// under it survives the write; leave it null only for a vault that is coming
  /// into existence. `salt0`, `salt1` and the data IV are always regenerated:
  /// AES-CBC under a repeated key *and* IV would let anyone holding two versions
  /// of a vault read off how long a prefix of the entry list went unchanged.
  ///
  /// [attachments] is the vault's attachment ciphertexts, which must be handed
  /// back on every save for the same reason [masterKey] must: they are
  /// encrypted under it and this call rebuilds the whole archive. Blobs no
  /// entry in [entries] refers to are **dropped** here rather than written —
  /// `SPEC.md` makes that a rule, so that deleting an attachment shrinks the
  /// vault.
  ///
  /// Note for the [rng] seam: the draw order is salt0, salt1, master key, IV,
  /// and supplying [masterKey] skips the third draw. The golden parity fixtures
  /// pass [rng] without a [masterKey], so they are unaffected — keep it that way.
  static Future<AskryptFile> create({
    required List<String> questions,
    required List<String> answers,
    required List<SecretEntry> entries,
    int iterations = defaultIterations,
    bool translit = false,
    String? host,
    DateTime? updatedAt,
    List<int>? masterKey,
    Map<String, Uint8List>? attachments,
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

    if (masterKey != null && masterKey.length != 32) {
      throw VaultException('master key must be 32 bytes');
    }

    final norm = answers.map((a) => normalizeAnswer(a, translit)).toList();
    final r = rng ?? Random.secure();
    final salt0 = _randomBytes(16, r);
    final salt1 = _randomBytes(16, r);
    // Only minted when the caller has no key to keep.
    final key =
        masterKey == null ? _randomBytes(32, r) : Uint8List.fromList(masterKey);
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
    final masterData = {'masterKey': base64.encode(key), 'iv': base64.encode(iv)};
    final master =
        base64.encode(aesCbcEncrypt(_jsonBytes(masterData), secondKey, salt1));

    // Layer 3: master key+iv -> encrypt entry list.
    final dataJson = entries.map((e) => e.toJson()).toList();
    final data = base64.encode(aesCbcEncrypt(_jsonBytes(dataJson), key, iv));

    // Carry the attachment blobs across, less any the entries being written no
    // longer refer to.
    final referenced = <String>{
      for (final e in entries)
        for (final a in e.attachments) a.id,
    };
    final kept = <String, Uint8List>{
      for (final entry in (attachments ?? const <String, Uint8List>{}).entries)
        if (referenced.contains(entry.key)) entry.key: entry.value,
    };

    return AskryptFile(
      version: _version,
      question0: questions[0],
      kdf: _defaultKdf,
      iterations: iterations,
      salt0B64: salt0B64,
      translit: translit,
      host: host,
      updatedAt: formatUtcStamp(updatedAt ?? DateTime.now()),
      qs: qs,
      master: master,
      data: data,
      attachments: kept,
    );
  }
}

/// Decrypt one attachment's bytes, given its metadata and the vault's master
/// key. Mirrors `open_attachment` in `core/src/lib.rs`.
///
/// `attachment.size` is deliberately not checked against the result: the format
/// offers no integrity (`SPEC.md`, "Integrity: not provided"), so a mismatch
/// would be a hint rather than a verdict.
Uint8List openAttachment(
  Uint8List ciphertext,
  Attachment attachment,
  List<int> masterKey,
) {
  final iv = base64.decode(attachment.iv);
  if (iv.length != 16) {
    throw VaultException('invalid attachment IV length');
  }
  return aesCbcDecrypt(ciphertext, Uint8List.fromList(masterKey), iv);
}

/// Mint a fresh 32-byte master key. Only a vault coming into existence should
/// need one — mirrors `MasterSecret::generate` in `core/src/types.rs`.
Uint8List generateMasterKey([Random? rng]) =>
    _randomBytes(32, rng ?? Random.secure());

/// Format [t] as RFC 3339 UTC with second precision — the `params.updated_at`
/// shape written by `AskryptFile::touch` in `core/src/lib.rs`.
String formatUtcStamp(DateTime t) {
  final u = t.toUtc();
  String pad(int v, [int width = 2]) => v.toString().padLeft(width, '0');
  return '${pad(u.year, 4)}-${pad(u.month)}-${pad(u.day)}'
      'T${pad(u.hour)}:${pad(u.minute)}:${pad(u.second)}Z';
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
