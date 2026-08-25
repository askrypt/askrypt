/// In-memory state of an unlocked vault — the Dart counterpart of the desktop
/// app's unlocked session (`src/main.rs`).
///
/// Mirrors the desktop save model exactly: while unlocked we keep the full
/// question + answer lists in memory — and the vault's master key — and *every*
/// save reconstructs the whole `AskryptFile` via [AskryptFile.create], rotating
/// the salts and the data IV but **re-wrapping the same master key** so that
/// anything else encrypted under it survives the write. There is no incremental
/// "re-encrypt just the data layer" path.
///
/// Plaintext lifetime is minimized at the *view* level — list rendering uses
/// [EntrySummary] (no secret/notes), and the secret is only handed out on an
/// explicit [reveal] — but note the documented PLAN limitation that Dart cannot
/// zeroize the managed heap. Call [lock]/drop the reference to clear state.
library;

import 'dart:typed_data';

import '../crypto/secret_entry.dart';
import '../crypto/vault.dart';
import '../platform/host_name.dart';

/// A read-only projection of a [SecretEntry] for list/search UI: everything
/// except the sensitive `secret` and `notes` fields, plus the entry's index in
/// the owning [UnlockedVault].
class EntrySummary {
  const EntrySummary({
    required this.index,
    required this.name,
    required this.userName,
    required this.url,
    required this.entryType,
    required this.tags,
    required this.hidden,
    required this.created,
    required this.modified,
  });

  final int index;
  final String name;
  final String userName;
  final String url;
  final String entryType;
  final List<String> tags;
  final bool hidden;
  final int created;
  final int modified;

  factory EntrySummary.of(int index, SecretEntry e) => EntrySummary(
        index: index,
        name: e.name,
        userName: e.userName,
        url: e.url,
        entryType: e.entryType,
        tags: List.unmodifiable(e.tags),
        hidden: e.hidden,
        created: e.created,
        modified: e.modified,
      );
}

class UnlockedVault {
  UnlockedVault._({
    required this.questions,
    required List<String> answers,
    required List<SecretEntry> entries,
    required this.translit,
    required this.iterations,
    List<int>? masterKey,
    Map<String, Uint8List>? attachments,
  })  : _answers = answers,
        _entries = entries,
        _masterKey = masterKey,
        _attachments = attachments ?? <String, Uint8List>{};

  /// Full question list, including the first question (`question0`).
  final List<String> questions;

  /// Full answer list, aligned with [questions]. Retained in memory because a
  /// save re-derives every layer from the answers (see class doc).
  final List<String> _answers;

  final List<SecretEntry> _entries;

  /// The vault's 32-byte master key, recovered by the unlock that opened it.
  /// Handed back to [AskryptFile.create] on every save so the key is re-wrapped
  /// rather than rotated. Null for a vault that has never been written; the
  /// first [toBytes] mints one and keeps it, so a second save of a brand-new
  /// vault does not mint a second key.
  List<int>? _masterKey;

  /// The vault's attachment ciphertexts, keyed by `Attachment.id`, carried from
  /// the file this vault was opened from and handed back on every save.
  ///
  /// This app cannot add or remove an attachment, but it must carry these:
  /// [AskryptFile.create] writes only the blobs the entries still refer to, so
  /// a save that forgot them would delete every attached file in the vault.
  final Map<String, Uint8List> _attachments;

  final bool translit;
  final int iterations;

  /// Set when entries/questions change and not yet persisted via [toBytes].
  bool isModified = false;

  // --- construction --------------------------------------------------------

  /// Create a brand-new, empty vault session.
  ///
  /// [answers] must align 1:1 with [questions]; both need at least 2 entries
  /// (enforced by [AskryptFile.create] at save time, validated eagerly here).
  factory UnlockedVault.create({
    required List<String> questions,
    required List<String> answers,
    bool translit = false,
    int iterations = defaultIterations,
  }) {
    _validateQa(questions, answers);
    return UnlockedVault._(
      questions: List.of(questions),
      answers: List.of(answers),
      entries: <SecretEntry>[],
      translit: translit,
      iterations: iterations,
    );
  }

  /// Open (decrypt) an existing `vault.askrypt` given the answers.
  ///
  /// [answers] is the full list: `answers[0]` unlocks the remaining questions,
  /// `answers[1..]` unlock the master key. This is the only path that performs
  /// the layered decryption; it throws [VaultException] on bad input/answers.
  ///
  /// Async because the two PBKDF2 derivations run on native platform crypto
  /// (see [pbkdf2]); awaiting them keeps the UI responsive without an isolate.
  static Future<UnlockedVault> open(
      Uint8List bytes, List<String> answers) async {
    if (answers.isEmpty) {
      throw VaultException('at least 1 answer required');
    }
    final file = AskryptFile.fromBytes(bytes);
    final qd = await file.getQuestionsData(answers[0]);
    final opened = await file.decryptWithMaster(qd, answers.sublist(1));
    return UnlockedVault._(
      questions: [file.question0, ...qd.questions],
      answers: List.of(answers),
      entries: opened.entries,
      translit: file.translit,
      iterations: file.iterations,
      masterKey: opened.masterKey,
      attachments: file.attachments,
    );
  }

  /// The stored bytes of one attachment, or null when the entry refers to a
  /// blob this archive does not hold — a dangling reference, which `SPEC.md`
  /// requires readers to tolerate.
  Uint8List? attachmentBytes(String id) => _attachments[id];

  /// Decrypt one attachment, ready to be written out.
  ///
  /// Throws [VaultException] when the vault has no master key yet (a brand-new
  /// vault, which cannot have attachments) or the blob is missing.
  Uint8List openAttachmentBytes(Attachment attachment) {
    final key = _masterKey;
    if (key == null) {
      throw VaultException('this vault has no master key yet');
    }
    final blob = _attachments[attachment.id];
    if (blob == null) {
      throw VaultException(
          '\u201c${attachment.name}\u201d is not stored in this vault');
    }
    return openAttachment(blob, attachment, key);
  }

  // --- read (no secrets) ---------------------------------------------------

  int get entryCount => _entries.length;

  /// The answer list, aligned with [questions]. Sensitive — only used by the
  /// questions editor to prefill existing answers; never shown in list UI.
  List<String> get answers => List.unmodifiable(_answers);

  /// Secret-free projections for list/search rendering. Order matches the
  /// underlying entry order (the index in each summary is the stable handle).
  List<EntrySummary> get summaries => List.unmodifiable(
        List.generate(_entries.length, (i) => EntrySummary.of(i, _entries[i])),
      );

  /// Reveal the full entry (including `secret`/`notes`) on demand.
  SecretEntry reveal(int index) {
    _checkIndex(index);
    return _entries[index];
  }

  // --- mutation (CRUD) -----------------------------------------------------

  /// Append a new entry; returns its index. Stamps `created`/`modified` if the
  /// caller left them at 0.
  int add(SecretEntry entry) {
    final now = _nowSeconds();
    if (entry.created == 0) entry.created = now;
    if (entry.modified == 0) entry.modified = now;
    _entries.add(entry);
    isModified = true;
    return _entries.length - 1;
  }

  /// Replace the entry at [index], bumping its `modified` timestamp.
  void update(int index, SecretEntry entry) {
    _checkIndex(index);
    entry.modified = _nowSeconds();
    _entries[index] = entry;
    isModified = true;
  }

  void removeAt(int index) {
    _checkIndex(index);
    _entries.removeAt(index);
    isModified = true;
  }

  /// Replace the questions/answers (and the transliteration setting), keeping
  /// the existing entries. Mirrors the desktop "Edit questions" flow: the next
  /// [toBytes] re-derives the answer-side layers from the new answers, and
  /// re-wraps the *same* master key — which is exactly what the master-key
  /// indirection is for. Returns a fresh [UnlockedVault] carrying the same
  /// entries; the caller swaps it into the session.
  UnlockedVault withQuestions({
    required List<String> questions,
    required List<String> answers,
    required bool translit,
  }) {
    _validateQa(questions, answers);
    return UnlockedVault._(
      questions: List.of(questions),
      answers: List.of(answers),
      entries: _entries,
      translit: translit,
      iterations: iterations,
      masterKey: _masterKey,
      attachments: _attachments,
    )..isModified = true;
  }

  // --- persistence ---------------------------------------------------------

  /// Serialize the current state to a byte-compatible `vault.askrypt`.
  ///
  /// Re-creates the whole file — fresh salts and a fresh data IV, but the
  /// vault's *existing* master key — like the desktop save path, then clears
  /// [isModified]. The bytes are ready to write to a file/SAF document. Each
  /// save stamps `params.host`/`params.updated_at` with this device and the
  /// current UTC time.
  ///
  /// Async because [AskryptFile.create] performs two PBKDF2 derivations on
  /// native platform crypto (see [pbkdf2]); awaiting keeps a save responsive
  /// without an isolate.
  Future<Uint8List> toBytes() async {
    // Minted here rather than left to `create`, so this vault keeps the key its
    // first write used instead of minting another on the next save.
    final key = _masterKey ??= generateMasterKey();
    final file = await AskryptFile.create(
      questions: questions,
      answers: _answers,
      entries: _entries,
      iterations: iterations,
      translit: translit,
      host: currentHostName(),
      masterKey: key,
      attachments: _attachments,
    );
    isModified = false;
    return file.toBytes();
  }

  // --- helpers -------------------------------------------------------------

  void _checkIndex(int index) {
    if (index < 0 || index >= _entries.length) {
      throw RangeError.index(index, _entries, 'index');
    }
  }

  static void _validateQa(List<String> questions, List<String> answers) {
    if (questions.length < 2) {
      throw VaultException('at least 2 questions required');
    }
    if (questions.length != answers.length) {
      throw VaultException('questions/answers count mismatch');
    }
  }

  static int _nowSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;
}
