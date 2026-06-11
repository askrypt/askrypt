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

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app.dart';
import '../crypto/normalize.dart';
import '../crypto/vault.dart';
import '../session/unlocked_vault.dart';
import '../session/vault_session.dart';

class UnlockScreen extends ConsumerStatefulWidget {
  const UnlockScreen({super.key, required this.bytes, required this.fileName});

  final Uint8List bytes;
  final String fileName;

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

  /// True once we know biometric answers are stored for this vault.
  bool _hasBiometric = false;

  /// Biometric knowledge check, shown inline in place of the manual form:
  /// the answers revealed from the store, the index of the randomly picked
  /// question, and its text. [_checkQuestion] non-null means check mode.
  List<String>? _revealed;
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
    await _maybeOfferEnroll(all);
    _commit(vault);
  }

  /// Biometric path: reveal stored answers, then switch the screen into the
  /// inline knowledge check — one randomly chosen question — before the real
  /// open in [_verifyAndOpen]. On a stale credential (e.g. the questions were
  /// re-keyed elsewhere) forget it and fall back to manual entry.
  Future<void> _quickUnlock() async {
    if (_busy) return;
    final file = _file!;
    final store = ref.read(biometricStoreProvider);
    final answers = await store.reveal(file.question0);
    if (answers == null || !mounted) return;

    // Pick the question to ask. The hidden questions' texts live in the
    // encrypted `qs` blob, so for index > 0 decrypt it with the stored first
    // answer (one extra derivation behind the spinner).
    final index = Random().nextInt(answers.length);
    final String question;
    if (index == 0) {
      question = file.question0;
    } else {
      setState(() => _busy = true);
      final QuestionsData qd;
      try {
        qd = await file.getQuestionsData(answers[0]);
      } catch (_) {
        await _forgetStale();
        return;
      }
      if (!mounted) return;
      setState(() => _busy = false);
      question = qd.questions[index - 1];
    }

    setState(() {
      _error = null;
      _revealed = answers;
      _checkIndex = index;
      _checkQuestion = question;
      _checkAnswer.clear();
    });
  }

  /// Inline knowledge check: compare the typed answer (normalized, like the
  /// crypto layer would) against the stored one, then perform the real open.
  Future<void> _verifyAndOpen() async {
    final answers = _revealed;
    final file = _file;
    if (answers == null || file == null || _busy) return;
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
      await _forgetStale();
      return;
    }
    if (!mounted) return;
    setState(() => _busy = false);
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
  Future<void> _forgetStale() async {
    await ref.read(biometricStoreProvider).forget(_file!.question0);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _hasBiometric = false;
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
    ref.read(currentQuestion0Provider.notifier).state = _file!.question0;
    // Cache this vault for the welcome screen's "open last vault" button.
    // Best-effort and fire-and-forget: adopting tears this route down, and a
    // cache failure must never block the unlock.
    unawaited(ref
        .read(recentVaultStoreProvider)
        .remember(widget.bytes, widget.fileName)
        .catchError((Object _) {}));
    ref.read(vaultSessionProvider.notifier).adopt(vault);
  }

  /// If biometrics are available and not yet enrolled for this vault, ask
  /// whether to remember the answers behind a biometric prompt.
  Future<void> _maybeOfferEnroll(List<String> answers) async {
    if (_hasBiometric) return;
    final store = ref.read(biometricStoreProvider);
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
    await store.save(_file!.question0, answers); // prompts for biometrics
  }

  @override
  Widget build(BuildContext context) {
    final file = _file;
    final qd = _qd;
    return Scaffold(
      appBar: AppBar(title: Text(widget.fileName)),
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
