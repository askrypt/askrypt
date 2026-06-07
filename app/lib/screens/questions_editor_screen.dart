/// Security-questions editor — used both to create a new vault and to re-key
/// an existing one (desktop "Edit questions"). Manages a list of
/// question/answer rows plus the transliteration toggle.
///
/// In *create* mode, saving starts a new in-memory session (the app shell then
/// swaps to the entries tree). In *edit* mode, saving replaces the open vault's
/// questions/answers (keeping entries) and pops back.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../session/vault_session.dart';

class QuestionsEditorScreen extends ConsumerStatefulWidget {
  const QuestionsEditorScreen.create({super.key}) : isCreate = true;
  const QuestionsEditorScreen.edit({super.key}) : isCreate = false;

  final bool isCreate;

  @override
  ConsumerState<QuestionsEditorScreen> createState() =>
      _QuestionsEditorScreenState();
}

class _QuestionRow {
  _QuestionRow([String question = '', String answer = ''])
      : question = TextEditingController(text: question),
        answer = TextEditingController(text: answer);
  final TextEditingController question;
  final TextEditingController answer;

  void dispose() {
    question.dispose();
    answer.dispose();
  }
}

class _QuestionsEditorScreenState
    extends ConsumerState<QuestionsEditorScreen> {
  final List<_QuestionRow> _rows = [];
  bool _translit = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    if (widget.isCreate) {
      _rows.addAll([_QuestionRow(), _QuestionRow()]);
    } else {
      final session = ref.read(vaultSessionProvider);
      if (session is VaultUnlocked) {
        final v = session.vault;
        _translit = v.translit;
        for (var i = 0; i < v.questions.length; i++) {
          _rows.add(_QuestionRow(v.questions[i], v.answers[i]));
        }
      }
      if (_rows.length < 2) {
        _rows.addAll(List.generate(2 - _rows.length, (_) => _QuestionRow()));
      }
    }
  }

  @override
  void dispose() {
    for (final r in _rows) {
      r.dispose();
    }
    super.dispose();
  }

  void _addRow() => setState(() => _rows.add(_QuestionRow()));

  void _removeRow(int index) => setState(() => _rows.removeAt(index).dispose());

  void _save() {
    final questions = _rows.map((r) => r.question.text.trim()).toList();
    final answers = _rows.map((r) => r.answer.text).toList();

    if (questions.length < 2) {
      setState(() => _error = 'At least 2 questions are required.');
      return;
    }
    for (var i = 0; i < questions.length; i++) {
      if (questions[i].isEmpty || answers[i].trim().isEmpty) {
        setState(() => _error = 'Every question and answer must be filled in.');
        return;
      }
      if (questions[i].length > 500) {
        setState(() => _error = 'Questions must be 500 characters or fewer.');
        return;
      }
    }

    final notifier = ref.read(vaultSessionProvider.notifier);
    try {
      if (widget.isCreate) {
        notifier.createNew(
            questions: questions, answers: answers, translit: _translit);
        // Session is now unlocked; the shell swaps to the entries tree.
      } else {
        notifier.updateQuestions(
            questions: questions, answers: answers, translit: _translit);
        Navigator.of(context).pop();
      }
    } catch (e) {
      setState(() => _error = '$e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.isCreate ? 'New vault' : 'Edit questions'),
        actions: [
          IconButton(
            tooltip: 'Save',
            icon: const Icon(Icons.check),
            onPressed: _save,
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Answers are normalized (lowercased, spaces and dashes removed) '
            'before they unlock the vault. Choose answers you can reproduce '
            'exactly.',
            style: theme.textTheme.bodySmall
                ?.copyWith(color: theme.colorScheme.outline),
          ),
          const SizedBox(height: 12),
          for (var i = 0; i < _rows.length; i++)
            _RowEditor(
              index: i,
              row: _rows[i],
              canRemove: _rows.length > 2,
              onRemove: () => _removeRow(i),
            ),
          const SizedBox(height: 4),
          OutlinedButton.icon(
            onPressed: _addRow,
            icon: const Icon(Icons.add),
            label: const Text('Add question'),
          ),
          const SizedBox(height: 8),
          SwitchListTile(
            value: _translit,
            onChanged: (v) => setState(() => _translit = v),
            title: const Text('Use transliteration'),
            subtitle: const Text(
                'Normalize Russian/Ukrainian answers to Latin (BGN/PCGN).'),
            contentPadding: EdgeInsets.zero,
          ),
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
          ],
        ],
      ),
    );
  }
}

class _RowEditor extends StatelessWidget {
  const _RowEditor({
    required this.index,
    required this.row,
    required this.canRemove,
    required this.onRemove,
  });

  final int index;
  final _QuestionRow row;
  final bool canRemove;
  final VoidCallback onRemove;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          children: [
            Row(
              children: [
                Expanded(
                  child: Text('Question ${index + 1}',
                      style: Theme.of(context).textTheme.labelLarge),
                ),
                if (canRemove)
                  IconButton(
                    tooltip: 'Remove',
                    icon: const Icon(Icons.delete_outline),
                    onPressed: onRemove,
                  ),
              ],
            ),
            TextField(
              controller: row.question,
              textInputAction: TextInputAction.next,
              decoration: const InputDecoration(
                labelText: 'Question',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: row.answer,
              textInputAction: TextInputAction.next,
              decoration: const InputDecoration(
                labelText: 'Answer',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
