/// In-memory state of an unlocked vault — the Dart counterpart of the desktop
/// app's unlocked session (`src/main.rs`).
///
/// Mirrors the desktop save model exactly: while unlocked we keep the full
/// question + answer lists in memory, and *every* save reconstructs the whole
/// `AskryptFile` via [AskryptFile.create] (rotating salts + master key). There
/// is no incremental "re-encrypt just the data layer" path; this matches
/// `Message::SaveVault` in `src/main.rs`.
///
/// Plaintext lifetime is minimized at the *view* level — list rendering uses
/// [EntrySummary] (no secret/notes), and the secret is only handed out on an
/// explicit [reveal] — but note the documented PLAN limitation that Dart cannot
/// zeroize the managed heap. Call [lock]/drop the reference to clear state.
library;

import 'dart:isolate';
import 'dart:typed_data';

import '../crypto/secret_entry.dart';
import '../crypto/vault.dart';

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
  })  : _answers = answers,
        _entries = entries;

  /// Full question list, including the first question (`question0`).
  final List<String> questions;

  /// Full answer list, aligned with [questions]. Retained in memory because a
  /// save re-derives every layer from the answers (see class doc).
  final List<String> _answers;

  final List<SecretEntry> _entries;

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
  factory UnlockedVault.open(Uint8List bytes, List<String> answers) {
    if (answers.isEmpty) {
      throw VaultException('at least 1 answer required');
    }
    final file = AskryptFile.fromBytes(bytes);
    final qd = file.getQuestionsData(answers[0]);
    final entries = file.decrypt(qd, answers.sublist(1));
    return UnlockedVault._(
      questions: [file.question0, ...qd.questions],
      answers: List.of(answers),
      entries: entries,
      translit: file.translit,
      iterations: file.iterations,
    );
  }

  /// [open] run on a background isolate. The layered decrypt performs two
  /// PBKDF2 derivations (600k iterations each); on the UI isolate that freezes
  /// the app long enough to trip Android's ANR dialog, so offload it. The
  /// returned [UnlockedVault] is plain data and copies cleanly across isolates.
  static Future<UnlockedVault> openAsync(
          Uint8List bytes, List<String> answers) =>
      Isolate.run(() => UnlockedVault.open(bytes, answers));

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
  /// the existing entries. Mirrors the desktop "Edit questions" flow, which
  /// re-keys the whole vault: the next [toBytes] re-derives every layer from
  /// the new answers. Returns a fresh [UnlockedVault] carrying the same
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
    )..isModified = true;
  }

  // --- persistence ---------------------------------------------------------

  /// Serialize the current state to a byte-compatible `vault.askrypt`.
  ///
  /// Re-creates the whole file (fresh salts + master key) like the desktop
  /// save path, then clears [isModified]. The bytes are ready to write to a
  /// file/SAF document.
  Uint8List toBytes() {
    final bytes = AskryptFile.create(
      questions: questions,
      answers: _answers,
      entries: _entries,
      iterations: iterations,
      translit: translit,
    ).toBytes();
    isModified = false;
    return bytes;
  }

  /// [toBytes] run on a background isolate. [AskryptFile.create] performs two
  /// PBKDF2 derivations (600k iterations each); doing that on the UI isolate
  /// freezes a save long enough to trip Android's ANR dialog, so offload it.
  Future<Uint8List> toBytesAsync() async {
    final qs = questions;
    final ans = _answers;
    final ent = _entries;
    final it = iterations;
    final tr = translit;
    final bytes = await Isolate.run(() => AskryptFile.create(
          questions: qs,
          answers: ans,
          entries: ent,
          iterations: it,
          translit: tr,
        ).toBytes());
    isModified = false;
    return bytes;
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
