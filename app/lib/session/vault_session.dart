/// Riverpod session layer: the single source of truth for "is a vault open,
/// and what's in it" for the whole app.
///
/// State is a sealed [VaultSession]: either [VaultLocked] (welcome/unlock
/// screens) or [VaultUnlocked] (everything else). Mutations go through
/// [VaultSessionNotifier] so the rest of the app never touches an
/// [UnlockedVault] directly — it watches the provider and reacts.
///
/// Because [UnlockedVault] is mutable, each CRUD mutation bumps a [revision]
/// counter and re-emits the state object so `ref.watch` listeners rebuild.
library;

import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../crypto/secret_entry.dart';
import '../crypto/vault.dart';
import 'unlocked_vault.dart';

/// Sealed session state. Use pattern matching at the UI layer:
/// `switch (session) { VaultLocked() => ..., VaultUnlocked(:final vault) => ... }`.
sealed class VaultSession {
  const VaultSession();
}

class VaultLocked extends VaultSession {
  const VaultLocked();
}

class VaultUnlocked extends VaultSession {
  const VaultUnlocked(this.vault, {this.revision = 0});

  final UnlockedVault vault;

  /// Incremented on every in-place mutation so equality changes and watchers
  /// rebuild even though [vault] is the same instance.
  final int revision;

  VaultUnlocked _bumped() => VaultUnlocked(vault, revision: revision + 1);

  @override
  bool operator ==(Object other) =>
      other is VaultUnlocked &&
      identical(other.vault, vault) &&
      other.revision == revision;

  @override
  int get hashCode => Object.hash(vault, revision);
}

class VaultSessionNotifier extends Notifier<VaultSession> {
  @override
  VaultSession build() => const VaultLocked();

  /// Currently-unlocked vault, or `null` if locked.
  UnlockedVault? get _vaultOrNull =>
      state is VaultUnlocked ? (state as VaultUnlocked).vault : null;

  UnlockedVault get _vault {
    final v = _vaultOrNull;
    if (v == null) throw StateError('no vault is unlocked');
    return v;
  }

  // --- lifecycle -----------------------------------------------------------

  /// Decrypt and open an existing vault. Throws [VaultException] on failure
  /// (caller shows the error); state is left untouched on throw.
  void open(Uint8List bytes, List<String> answers) {
    state = VaultUnlocked(UnlockedVault.open(bytes, answers));
  }

  /// Start a brand-new, empty vault.
  void createNew({
    required List<String> questions,
    required List<String> answers,
    bool translit = false,
    int iterations = defaultIterations,
  }) {
    state = VaultUnlocked(UnlockedVault.create(
      questions: questions,
      answers: answers,
      translit: translit,
      iterations: iterations,
    ));
  }

  /// Drop all decrypted state and return to the locked screen.
  void lock() => state = const VaultLocked();

  // --- CRUD (no-op-safe re-emit so watchers rebuild) ----------------------

  int addEntry(SecretEntry entry) {
    final index = _vault.add(entry);
    _reemit();
    return index;
  }

  void updateEntry(int index, SecretEntry entry) {
    _vault.update(index, entry);
    _reemit();
  }

  void removeEntry(int index) {
    _vault.removeAt(index);
    _reemit();
  }

  /// Replace the questions/answers/translit of the open vault, keeping entries
  /// (desktop "Edit questions"). Throws [VaultException] on invalid input;
  /// state is left untouched on throw.
  void updateQuestions({
    required List<String> questions,
    required List<String> answers,
    required bool translit,
  }) {
    final next = _vault.withQuestions(
      questions: questions,
      answers: answers,
      translit: translit,
    );
    state = VaultUnlocked(next);
  }

  /// Serialize the current vault to byte-compatible `vault.askrypt` bytes and
  /// re-emit so the cleared `isModified` flag propagates.
  Uint8List toBytes() {
    final bytes = _vault.toBytes();
    _reemit();
    return bytes;
  }

  void _reemit() => state = (state as VaultUnlocked)._bumped();
}

final vaultSessionProvider =
    NotifierProvider<VaultSessionNotifier, VaultSession>(
  VaultSessionNotifier.new,
);
