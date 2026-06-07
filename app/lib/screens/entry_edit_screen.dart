/// Entry view/editor: add a new entry (index == null) or edit an existing one.
///
/// The full secret/notes are only materialized here, via [UnlockedVault.reveal]
/// on an existing index. Saving mutates the in-memory session (add/update); it
/// does *not* write the file — the user persists via "Save" on the entries
/// screen, matching the desktop split between `SaveEntry` and `SaveVault`.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../crypto/secret_entry.dart';
import '../session/vault_session.dart';
import 'password_generator_screen.dart';

class EntryEditScreen extends ConsumerStatefulWidget {
  const EntryEditScreen({super.key, this.index});

  /// Existing entry index, or `null` to create a new entry.
  final int? index;

  @override
  ConsumerState<EntryEditScreen> createState() => _EntryEditScreenState();
}

class _EntryEditScreenState extends ConsumerState<EntryEditScreen> {
  late final TextEditingController _name;
  late final TextEditingController _userName;
  late final TextEditingController _secret;
  late final TextEditingController _url;
  late final TextEditingController _notes;
  late final TextEditingController _tags;
  late String _entryType;
  bool _hidden = false;
  bool _obscure = true;

  bool get _isNew => widget.index == null;

  @override
  void initState() {
    super.initState();
    SecretEntry? e;
    if (widget.index != null) {
      final session = ref.read(vaultSessionProvider);
      if (session is VaultUnlocked) e = session.vault.reveal(widget.index!);
    }
    _name = TextEditingController(text: e?.name ?? '');
    _userName = TextEditingController(text: e?.userName ?? '');
    _secret = TextEditingController(text: e?.secret ?? '');
    _url = TextEditingController(text: e?.url ?? '');
    _notes = TextEditingController(text: e?.notes ?? '');
    _tags = TextEditingController(text: e?.tags.join(', ') ?? '');
    _entryType = e?.entryType ?? 'login';
    _hidden = e?.hidden ?? false;
  }

  @override
  void dispose() {
    _name.dispose();
    _userName.dispose();
    _secret.dispose();
    _url.dispose();
    _notes.dispose();
    _tags.dispose();
    super.dispose();
  }

  void _save() {
    final notifier = ref.read(vaultSessionProvider.notifier);
    final tags = _tags.text
        .split(',')
        .map((t) => t.trim())
        .where((t) => t.isNotEmpty)
        .toList();
    final entry = SecretEntry(
      name: _name.text.trim(),
      userName: _userName.text,
      secret: _secret.text,
      url: _url.text.trim(),
      notes: _notes.text,
      entryType: _entryType,
      tags: tags,
      created: 0,
      modified: 0,
      hidden: _hidden,
    );
    if (_isNew) {
      notifier.addEntry(entry);
    } else {
      notifier.updateEntry(widget.index!, entry);
    }
    Navigator.of(context).pop();
  }

  Future<void> _delete() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete entry'),
        content: Text('Delete "${_name.text}"?'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Delete')),
        ],
      ),
    );
    if (confirm != true || !mounted) return;
    ref.read(vaultSessionProvider.notifier).removeEntry(widget.index!);
    if (mounted) Navigator.of(context).pop();
  }

  Future<void> _copy(String value, String label) async {
    if (value.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('$label copied')));
  }

  Future<void> _openUrl() async {
    final raw = _url.text.trim();
    if (raw.isEmpty) return;
    final uri = Uri.tryParse(
        raw.contains('://') ? raw : 'https://$raw');
    final ok =
        uri != null && await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!ok && mounted) {
      ScaffoldMessenger.of(context)
          .showSnackBar(const SnackBar(content: Text('Could not open URL')));
    }
  }

  Future<void> _generate() async {
    final result = await Navigator.of(context).push<String>(
      MaterialPageRoute(
          builder: (_) => const PasswordGeneratorScreen(returnOnUse: true)),
    );
    if (result != null) setState(() => _secret.text = result);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_isNew ? 'New entry' : 'Edit entry'),
        actions: [
          if (!_isNew)
            IconButton(
              tooltip: 'Delete',
              icon: const Icon(Icons.delete_outline),
              onPressed: _delete,
            ),
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
          _field(_name, 'Name', autofocus: _isNew),
          const SizedBox(height: 12),
          _field(
            _userName,
            'Username',
            trailing: _copyButton(() => _copy(_userName.text, 'Username')),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _secret,
            obscureText: _obscure,
            decoration: InputDecoration(
              labelText: 'Secret',
              border: const OutlineInputBorder(),
              suffixIcon: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    tooltip: _obscure ? 'Show' : 'Hide',
                    icon: Icon(
                        _obscure ? Icons.visibility : Icons.visibility_off),
                    onPressed: () => setState(() => _obscure = !_obscure),
                  ),
                  IconButton(
                    tooltip: 'Generate',
                    icon: const Icon(Icons.casino),
                    onPressed: _generate,
                  ),
                  IconButton(
                    tooltip: 'Copy',
                    icon: const Icon(Icons.copy),
                    onPressed: () => _copy(_secret.text, 'Secret'),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _url,
            keyboardType: TextInputType.url,
            decoration: InputDecoration(
              labelText: 'URL',
              border: const OutlineInputBorder(),
              suffixIcon: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    tooltip: 'Open',
                    icon: const Icon(Icons.open_in_new),
                    onPressed: _openUrl,
                  ),
                  _copyButton(() => _copy(_url.text, 'URL')),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          _field(_tags, 'Tags (comma-separated)'),
          const SizedBox(height: 12),
          TextField(
            controller: _notes,
            minLines: 2,
            maxLines: 6,
            decoration: const InputDecoration(
              labelText: 'Notes',
              border: OutlineInputBorder(),
              alignLabelWithHint: true,
            ),
          ),
          const SizedBox(height: 8),
          SwitchListTile(
            value: _hidden,
            onChanged: (v) => setState(() => _hidden = v),
            title: const Text('Hidden'),
            subtitle: const Text('Only shown when "show hidden" is on.'),
            contentPadding: EdgeInsets.zero,
          ),
        ],
      ),
    );
  }

  Widget _field(TextEditingController c, String label,
      {bool autofocus = false, Widget? trailing}) {
    return TextField(
      controller: c,
      autofocus: autofocus,
      decoration: InputDecoration(
        labelText: label,
        border: const OutlineInputBorder(),
        suffixIcon: trailing,
      ),
    );
  }

  Widget _copyButton(VoidCallback onPressed) => IconButton(
        tooltip: 'Copy',
        icon: const Icon(Icons.copy),
        onPressed: onPressed,
      );
}
