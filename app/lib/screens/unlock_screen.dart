/// Layered unlock: enter the first answer to reveal the remaining questions,
/// then enter the rest to decrypt the vault.
///
/// Mirrors the desktop `FirstQuestion` → `OtherQuestions` flow: `answer0`
/// decrypts the `qs` blob (the remaining questions); all answers together
/// decrypt the master key and the entries. We call the crypto layer directly
/// for the intermediate step (to display the remaining questions) and then hand
/// the full answer list to the session notifier to perform the real open.
library;

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../crypto/vault.dart';
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
  bool _obscure = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    try {
      _file = AskryptFile.fromBytes(widget.bytes);
    } catch (e) {
      _error = 'Not a valid vault file.';
    }
  }

  @override
  void dispose() {
    _answer0.dispose();
    for (final c in _answers) {
      c.dispose();
    }
    super.dispose();
  }

  /// Step 1 → 2: decrypt the remaining questions with the first answer.
  void _revealQuestions() {
    final file = _file;
    if (file == null) return;
    setState(() => _error = null);
    try {
      final qd = file.getQuestionsData(_answer0.text);
      setState(() {
        _qd = qd;
        _answers
          ..clear()
          ..addAll(List.generate(qd.questions.length, (_) => TextEditingController()));
      });
    } catch (_) {
      setState(() => _error = 'Wrong answer to the first question.');
    }
  }

  /// Step 2: full decrypt via the session notifier.
  void _unlock() {
    setState(() => _error = null);
    final all = [_answer0.text, ..._answers.map((c) => c.text)];
    try {
      ref.read(vaultSessionProvider.notifier).open(widget.bytes, all);
      // Session is now unlocked; the app shell swaps to the entries tree and
      // tears this route down — no explicit pop needed.
    } catch (_) {
      setState(() => _error = 'Could not unlock — check your answers.');
    }
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
                _QuestionField(
                  question: file.question0,
                  controller: _answer0,
                  obscure: _obscure,
                  enabled: qd == null,
                  onToggleObscure: () => setState(() => _obscure = !_obscure),
                  onSubmitted: qd == null ? (_) => _revealQuestions() : null,
                ),
                if (qd != null) ...[
                  for (var i = 0; i < qd.questions.length; i++)
                    _QuestionField(
                      question: qd.questions[i],
                      controller: _answers[i],
                      obscure: _obscure,
                      enabled: true,
                      onToggleObscure: () =>
                          setState(() => _obscure = !_obscure),
                      onSubmitted: i == qd.questions.length - 1
                          ? (_) => _unlock()
                          : null,
                    ),
                ],
                if (_error != null) ...[
                  const SizedBox(height: 8),
                  Text(_error!,
                      style: TextStyle(
                          color: Theme.of(context).colorScheme.error)),
                ],
                const SizedBox(height: 16),
                if (qd == null)
                  FilledButton(
                    onPressed: _revealQuestions,
                    child: const Text('Next'),
                  )
                else
                  FilledButton.icon(
                    onPressed: _unlock,
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

class _QuestionField extends StatelessWidget {
  const _QuestionField({
    required this.question,
    required this.controller,
    required this.obscure,
    required this.enabled,
    required this.onToggleObscure,
    this.onSubmitted,
  });

  final String question;
  final TextEditingController controller;
  final bool obscure;
  final bool enabled;
  final VoidCallback onToggleObscure;
  final ValueChanged<String>? onSubmitted;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: TextField(
        controller: controller,
        enabled: enabled,
        obscureText: obscure,
        autofocus: enabled,
        textInputAction:
            onSubmitted != null ? TextInputAction.done : TextInputAction.next,
        onSubmitted: onSubmitted,
        decoration: InputDecoration(
          labelText: question,
          border: const OutlineInputBorder(),
          suffixIcon: IconButton(
            tooltip: obscure ? 'Show' : 'Hide',
            icon: Icon(obscure ? Icons.visibility : Icons.visibility_off),
            onPressed: onToggleObscure,
          ),
        ),
      ),
    );
  }
}
