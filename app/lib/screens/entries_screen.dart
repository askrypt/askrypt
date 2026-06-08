/// Entries list (unlocked state): search, tag filter, show-hidden toggle, and
/// the entry points for add/edit, save, lock, edit-questions and the generator.
///
/// Rendering uses [EntrySummary] only — secrets are never materialized for the
/// list. Tapping a row opens the entry editor, which reveals the secret on
/// demand.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app.dart';
import '../session/unlocked_vault.dart';
import '../session/vault_session.dart';
import 'entry_edit_screen.dart';
import 'password_generator_screen.dart';
import 'questions_editor_screen.dart';

enum _Menu { editQuestions, passwordGenerator, disableBiometric }

class EntriesScreen extends ConsumerStatefulWidget {
  const EntriesScreen({super.key});

  @override
  ConsumerState<EntriesScreen> createState() => _EntriesScreenState();
}

class _EntriesScreenState extends ConsumerState<EntriesScreen> {
  String _query = '';
  String? _tagFilter;
  bool _showHidden = false;

  /// Whether biometric answers are stored for this vault (drives the
  /// "Disable biometric unlock" menu item).
  bool _hasBiometric = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkBiometric());
  }

  Future<void> _checkBiometric() async {
    final q0 = ref.read(currentQuestion0Provider);
    if (q0 == null) return;
    final has = await ref.read(biometricStoreProvider).hasCredentialFor(q0);
    if (mounted) setState(() => _hasBiometric = has);
  }

  Future<void> _disableBiometric() async {
    final q0 = ref.read(currentQuestion0Provider);
    if (q0 != null) {
      await ref.read(biometricStoreProvider).forget(q0);
    }
    if (!mounted) return;
    setState(() => _hasBiometric = false);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Biometric unlock disabled')),
    );
  }

  bool _matches(EntrySummary s) {
    if (s.hidden && !_showHidden) return false;
    if (_tagFilter != null && !s.tags.contains(_tagFilter)) return false;
    if (_query.isEmpty) return true;
    final q = _query.toLowerCase();
    return s.name.toLowerCase().contains(q) ||
        s.userName.toLowerCase().contains(q) ||
        s.url.toLowerCase().contains(q) ||
        s.tags.any((t) => t.toLowerCase().contains(q));
  }

  Future<void> _save() async {
    final notifier = ref.read(vaultSessionProvider.notifier);
    final io = ref.read(vaultIoProvider);
    final name = ref.read(vaultFileNameProvider);
    final bytes = await notifier.toBytes();
    final saved = await io.saveVault(bytes, suggestedName: name);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(saved == null ? 'Save cancelled' : 'Vault saved')),
    );
  }

  Future<void> _confirmLock(UnlockedVault vault) async {
    if (vault.isModified) {
      final discard = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Unsaved changes'),
          content: const Text('Lock without saving? Changes will be lost.'),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: const Text('Cancel')),
            FilledButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: const Text('Lock')),
          ],
        ),
      );
      if (discard != true) return;
    }
    ref.read(vaultSessionProvider.notifier).lock();
  }

  void _onMenu(_Menu item) {
    switch (item) {
      case _Menu.editQuestions:
        Navigator.of(context).push(MaterialPageRoute<void>(
            builder: (_) => const QuestionsEditorScreen.edit()));
      case _Menu.passwordGenerator:
        Navigator.of(context).push(MaterialPageRoute<void>(
            builder: (_) => const PasswordGeneratorScreen()));
      case _Menu.disableBiometric:
        _disableBiometric();
    }
  }

  void _openEntry(int? index) {
    Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) => EntryEditScreen(index: index)));
  }

  @override
  Widget build(BuildContext context) {
    final session = ref.watch(vaultSessionProvider);
    if (session is! VaultUnlocked) return const SizedBox.shrink();
    final vault = session.vault;

    final summaries = vault.summaries.where(_matches).toList();
    final allTags =
        (vault.summaries.expand((s) => s.tags).toSet().toList()..sort());

    return Scaffold(
      appBar: AppBar(
        title: Text(vault.isModified ? 'Askrypt •' : 'Askrypt'),
        actions: [
          IconButton(
            tooltip: 'Show hidden',
            icon: Icon(_showHidden ? Icons.visibility : Icons.visibility_off),
            onPressed: () => setState(() => _showHidden = !_showHidden),
          ),
          IconButton(
            tooltip: 'Save',
            icon: const Icon(Icons.save),
            onPressed: _save,
          ),
          IconButton(
            tooltip: 'Lock',
            icon: const Icon(Icons.lock),
            onPressed: () => _confirmLock(vault),
          ),
          PopupMenuButton<_Menu>(
            onSelected: _onMenu,
            itemBuilder: (_) => [
              const PopupMenuItem(
                  value: _Menu.editQuestions, child: Text('Edit questions')),
              const PopupMenuItem(
                  value: _Menu.passwordGenerator,
                  child: Text('Password generator')),
              if (_hasBiometric)
                const PopupMenuItem(
                    value: _Menu.disableBiometric,
                    child: Text('Disable biometric unlock')),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
            child: TextField(
              decoration: InputDecoration(
                hintText: 'Search',
                prefixIcon: const Icon(Icons.search),
                isDense: true,
                border:
                    OutlineInputBorder(borderRadius: BorderRadius.circular(24)),
              ),
              onChanged: (v) => setState(() => _query = v),
            ),
          ),
          if (allTags.isNotEmpty)
            SizedBox(
              height: 48,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 12),
                children: [
                  for (final tag in allTags)
                    Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: FilterChip(
                        label: Text(tag),
                        selected: _tagFilter == tag,
                        onSelected: (sel) =>
                            setState(() => _tagFilter = sel ? tag : null),
                      ),
                    ),
                ],
              ),
            ),
          Expanded(
            child: summaries.isEmpty
                ? const Center(child: Text('No entries'))
                : ListView.separated(
                    itemCount: summaries.length,
                    separatorBuilder: (_, __) => const Divider(height: 1),
                    itemBuilder: (_, i) {
                      final s = summaries[i];
                      return ListTile(
                        leading: CircleAvatar(
                          child: Text(s.name.isEmpty
                              ? '?'
                              : s.name.characters.first.toUpperCase()),
                        ),
                        title: Text(s.name),
                        subtitle: s.userName.isEmpty ? null : Text(s.userName),
                        trailing: s.hidden
                            ? const Icon(Icons.visibility_off, size: 18)
                            : null,
                        onTap: () => _openEntry(s.index),
                      );
                    },
                  ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        tooltip: 'Add entry',
        onPressed: () => _openEntry(null),
        child: const Icon(Icons.add),
      ),
    );
  }
}
