/// Layered unlock: enter the first answer to reveal the remaining questions,
/// then enter the rest to decrypt the vault.
///
/// Mirrors the desktop `FirstQuestion` → `OtherQuestions` flow: `answer0`
/// decrypts the `qs` blob (the remaining questions); all answers together
/// decrypt the master key and the entries. We call the crypto layer directly
/// for the intermediate step (to display the remaining questions) and then hand
/// the full answer list to the session notifier to perform the real open.
library;

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show listEquals;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app.dart';
import '../crypto/normalize.dart';
import '../crypto/vault.dart';
import '../platform/biometric_store.dart';
import '../platform/recent_vault_store.dart';
import '../session/unlocked_vault.dart';
import '../session/vault_home.dart';
import '../session/vault_session.dart';

class UnlockScreen extends ConsumerStatefulWidget {
  const UnlockScreen({super.key, required this.bytes, required this.home});

  final Uint8List bytes;

  /// Where [bytes] came from — becomes the open vault's home, so Save writes
  /// back to the same place.
  final VaultHome home;

  @override
  ConsumerState<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends ConsumerState<UnlockScreen> {
  AskryptFile? _file;
  QuestionsData? _qd;

  final _answer0 = TextEditingController();
  final List<TextEditingController> _answers = [];
  String? _error;

  /// True while a key derivation is running on a background isolate. Drives the
  /// progress indicator and disables the action buttons.
  bool _busy = false;

  /// True once we know biometric answers are stored for a vault starting with
  /// this first question (not necessarily this vault — see [_quickUnlock]).
  bool _hasBiometric = false;

  /// Set when stored answers turned out not to open this vault, so a manual
  /// unlock offers enrollment even if a credential with its id exists.
  bool _offerEnroll = false;

  /// The credential this vault was opened with or enrolled under; becomes
  /// [biometricIdProvider] on commit.
  String? _credentialId;

  /// Biometric knowledge check, shown inline in place of the manual form:
  /// the matched credential, the index of the randomly picked question, and
  /// its text. [_checkQuestion] non-null means check mode.
  BiometricCredential? _revealed;
  int _checkIndex = 0;
  String? _checkQuestion;
  final _checkAnswer = TextEditingController();

  /// Guards the one-shot auto-prompt so we don't re-trigger on rebuilds.
  bool _biometricTried = false;

  @override
  void initState() {
    super.initState();
    try {
      _file = AskryptFile.fromBytes(widget.bytes);
    } catch (e) {
      _error = 'Not a valid vault file.';
    }
    if (_file != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _initBiometric());
    }
  }

  /// Check for stored biometric credentials for this vault and, if present,
  /// auto-trigger the biometric prompt once.
  Future<void> _initBiometric() async {
    final has =
        await ref.read(biometricStoreProvider).hasCredentialFor(_file!.question0);
    if (!mounted) return;
    setState(() => _hasBiometric = has);
    if (has && !_biometricTried) {
      _biometricTried = true;
      _quickUnlock();
    }
  }

  @override
  void dispose() {
    _answer0.dispose();
    _checkAnswer.dispose();
    for (final c in _answers) {
      c.dispose();
    }
    super.dispose();
  }

  /// Step 1 → 2: decrypt the remaining questions with the first answer. The
  /// The PBKDF2 derivation runs on native platform crypto (off the Dart event
  /// loop), so awaiting it here keeps the UI responsive without an ANR.
  Future<void> _revealQuestions() async {
    final file = _file;
    if (file == null || _busy) return;
    setState(() {
      _error = null;
      _busy = true;
    });
    try {
      final qd = await file.getQuestionsData(_answer0.text);
      if (!mounted) return;
      setState(() {
        _qd = qd;
        _answers
          ..clear()
          ..addAll(List.generate(qd.questions.length, (_) => TextEditingController()));
      });
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = 'Wrong answer to the first question.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Step 2: full decrypt from the typed answers. We decrypt *locally* first so
  /// we can offer biometric enrollment before the session swap tears this route
  /// down, then hand the decrypted vault to the session via [adopt].
  Future<void> _unlock() async {
    if (_busy) return;
    setState(() {
      _error = null;
      _busy = true;
    });
    final all = [_answer0.text, ..._answers.map((c) => c.text)];
    final UnlockedVault vault;
    try {
      vault = await UnlockedVault.open(widget.bytes, all);
    } catch (_) {
      if (mounted) {
        setState(() {
          _error = 'Could not unlock — check your answers.';
          _busy = false;
        });
      }
      return;
    }
    if (!mounted) return;
    setState(() => _busy = false);
    await _maybeOfferEnroll(vault.questions, all);
    _commit(vault);
  }

  /// Biometric path: one prompt reveals every credential sharing this vault's
  /// first question; the one whose first answer decrypts the remaining
  /// questions — and whose question list matches them — is this vault's.
  /// Then the screen switches to the inline knowledge check (one randomly
  /// chosen question) before the real open in [_verifyAndOpen]. Every failure
  /// says so on screen; none is silent.
  Future<void> _quickUnlock() async {
    final file = _file;
    if (file == null || _busy) return;
    setState(() {
      _error = null;
      _busy = true;
    });
    final List<BiometricCredential>? candidates;
    try {
      candidates = await ref.read(biometricStoreProvider).reveal(file.question0);
    } on BiometricStoreException {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _hasBiometric = false;
        _offerEnroll = true;
        _error = 'Saved answers couldn\'t be read — enter them manually, then '
            're-enable biometric unlock.';
      });
      return;
    }
    if (!mounted) return;
    if (candidates == null) {
      // Prompt cancelled or not recognized: stay on the manual form.
      setState(() => _busy = false);
      return;
    }

    BiometricCredential? match;
    for (final c in candidates) {
      if (c.answers.length != c.questions.length || c.questions.length < 2) {
        continue;
      }
      try {
        final qd = await file.getQuestionsData(c.answers[0]);
        if (listEquals([file.question0, ...qd.questions], c.questions)) {
          match = c;
          break;
        }
      } catch (_) {
        // Another vault's credential sharing this first question — keep it.
      }
    }
    if (!mounted) return;
    if (match == null) {
      setState(() {
        _busy = false;
        _offerEnroll = true;
        _error = 'No saved answers match this vault — enter them manually.';
      });
      return;
    }

    final index = Random().nextInt(match.questions.length);
    setState(() {
      _busy = false;
      _revealed = match;
      _checkIndex = index;
      _checkQuestion = match!.questions[index];
      _checkAnswer.clear();
    });
  }

  /// Inline knowledge check: compare the typed answer (normalized, like the
  /// crypto layer would) against the stored one, then perform the real open.
  Future<void> _verifyAndOpen() async {
    final credential = _revealed;
    final file = _file;
    if (credential == null || file == null || _busy) return;
    final answers = credential.answers;
    if (normalizeAnswer(_checkAnswer.text, file.translit) !=
        normalizeAnswer(answers[_checkIndex], file.translit)) {
      setState(() => _error = 'Incorrect answer.');
      return;
    }
    setState(() {
      _error = null;
      _busy = true;
    });
    final UnlockedVault vault;
    try {
      vault = await UnlockedVault.open(widget.bytes, answers);
    } catch (_) {
      // The question list matched, so these are this vault's old answers.
      await _forgetStale(credential.id);
      return;
    }
    if (!mounted) return;
    setState(() => _busy = false);
    _credentialId = credential.id;
    _commit(vault);
  }

  /// Leave the knowledge check for the full manual form. The stored credential
  /// is kept, so biometrics can still be retried from there.
  void _enterAllAnswers() => setState(() {
        _revealed = null;
        _checkQuestion = null;
        _error = null;
      });

  /// Drop a stale biometric credential and surface the manual-entry fallback.
  Future<void> _forgetStale(String id) async {
    await ref.read(biometricStoreProvider).forget(id);
    if (!mounted) return;
    final still = await ref
        .read(biometricStoreProvider)
        .hasCredentialFor(_file!.question0);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _hasBiometric = still;
      _offerEnroll = true;
      _revealed = null;
      _checkQuestion = null;
      _error = 'Saved answers no longer open this vault — enter them manually.';
    });
  }

  /// Record the vault's identity (for the disable-biometric menu) and adopt the
  /// decrypted vault. This swaps the app to the entries tree and tears this
  /// route down, so it must be the last thing we do with [context].
  void _commit(UnlockedVault vault) {
    if (!mounted) return;
    ref.read(biometricIdProvider.notifier).state = _credentialId;
    final home = widget.home;
    ref.read(vaultHomeProvider.notifier).state = home;
    // Remember this vault for the welcome screen's recent-vault list:
    // a local file by its bytes, a cloud vault by where it lives. Best-effort
    // and fire-and-forget: adopting tears this route down, and a cache
    // failure must never block the unlock.
    final recent = ref.read(recentVaultStoreProvider);
    unawaited((switch (home) {
      LocalHome(:final name) => recent.remember(widget.bytes, name),
      CloudHome cloud => recent.rememberCloud(RecentCloud(
          baseUrl: cloud.baseUrl,
          email: cloud.email,
          id: cloud.id,
          name: cloud.name)),
    })
        .catchError((Object _) {}));
    ref.read(vaultSessionProvider.notifier).adopt(vault);
  }

  /// If biometrics are available and this vault isn't enrolled (or its stored
  /// answers just failed), ask whether to remember the answers behind a
  /// biometric prompt. An existing, working credential is kept as is.
  Future<void> _maybeOfferEnroll(
      List<String> questions, List<String> answers) async {
    final store = ref.read(biometricStoreProvider);
    final id = biometricIdFor(questions);
    if (!_offerEnroll && await store.contains(id)) {
      _credentialId = id;
      return;
    }
    if (!await store.canUse() || !mounted) return;
    final wants = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Enable biometric unlock?'),
        content: const Text(
          'Unlock this vault with your fingerprint or face next time, instead '
          'of typing your answers. Answers are stored in the device keystore. '
          'You\'ll still be asked one of your answers, chosen at random, each '
          'time.',
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Not now')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Enable')),
        ],
      ),
    );
    if (wants != true) return;
    try {
      if (await store.enroll(questions, answers)) _credentialId = id;
    } catch (e) {
      // Never block the open over it; the vault still unlocks.
      debugPrint('biometric: enrollment failed: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final file = _file;
    final qd = _qd;
    return Scaffold(
      appBar: AppBar(title: Text(widget.home.name)),
      body: file == null
          ? _errorBody()
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                if (_checkQuestion != null) ...[
                  Text('Answer this question to finish unlocking',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodySmall),
                  const SizedBox(height: 16),
                  _QuestionField(
                    question: _checkQuestion!,
                    controller: _checkAnswer,
                    enabled: true,
                    onSubmitted: (_) => _verifyAndOpen(),
                  ),
                ] else ...[
                  if (_hasBiometric) ...[
                    FilledButton.icon(
                      onPressed: _busy ? null : _quickUnlock,
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('Unlock with biometrics'),
                    ),
                    const SizedBox(height: 8),
                    Text('or enter your answers',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.bodySmall),
                    const SizedBox(height: 16),
                  ],
                  _QuestionField(
                    question: file.question0,
                    controller: _answer0,
                    enabled: qd == null,
                    onSubmitted: qd == null ? (_) => _revealQuestions() : null,
                  ),
                  if (qd != null) ...[
                    for (var i = 0; i < qd.questions.length; i++)
                      _QuestionField(
                        question: qd.questions[i],
                        controller: _answers[i],
                        enabled: true,
                        onSubmitted: i == qd.questions.length - 1
                            ? (_) => _unlock()
                            : null,
                      ),
                  ],
                ],
                if (_error != null) ...[
                  const SizedBox(height: 8),
                  Text(_error!,
                      style: TextStyle(
                          color: Theme.of(context).colorScheme.error)),
                ],
                const SizedBox(height: 16),
                if (_busy) ...[
                  const Center(child: CircularProgressIndicator()),
                  const SizedBox(height: 8),
                  Text('Decrypting…',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodySmall),
                  const SizedBox(height: 16),
                ],
                if (_checkQuestion != null) ...[
                  FilledButton.icon(
                    onPressed: _busy ? null : _verifyAndOpen,
                    icon: const Icon(Icons.lock_open),
                    label: const Text('Unlock'),
                  ),
                  const SizedBox(height: 8),
                  TextButton(
                    onPressed: _busy ? null : _enterAllAnswers,
                    child: const Text('Enter all answers'),
                  ),
                ] else if (qd == null)
                  FilledButton(
                    onPressed: _busy ? null : _revealQuestions,
                    child: const Text('Next'),
                  )
                else
                  FilledButton.icon(
                    onPressed: _busy ? null : _unlock,
                    icon: const Icon(Icons.lock_open),
                    label: const Text('Unlock'),
                  ),
              ],
            ),
    );
  }

  Widget _errorBody() => Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(_error ?? 'Error',
              style: TextStyle(color: Theme.of(context).colorScheme.error)),
        ),
      );
}

/// Owns its own show/hide state so each answer field toggles independently.
class _QuestionField extends StatefulWidget {
  const _QuestionField({
    required this.question,
    required this.controller,
    required this.enabled,
    this.onSubmitted,
  });

  final String question;
  final TextEditingController controller;
  final bool enabled;
  final ValueChanged<String>? onSubmitted;

  @override
  State<_QuestionField> createState() => _QuestionFieldState();
}

class _QuestionFieldState extends State<_QuestionField> {
  bool _obscure = true;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: TextField(
        controller: widget.controller,
        enabled: widget.enabled,
        obscureText: _obscure,
        autofocus: widget.enabled,
        textInputAction: widget.onSubmitted != null
            ? TextInputAction.done
            : TextInputAction.next,
        onSubmitted: widget.onSubmitted,
        decoration: InputDecoration(
          labelText: widget.question,
          border: const OutlineInputBorder(),
          suffixIcon: IconButton(
            tooltip: _obscure ? 'Show' : 'Hide',
            icon: Icon(_obscure ? Icons.visibility : Icons.visibility_off),
            onPressed: () => setState(() => _obscure = !_obscure),
          ),
        ),
      ),
    );
  }
}
