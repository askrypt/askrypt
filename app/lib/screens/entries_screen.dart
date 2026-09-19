/// Entries list (unlocked state): search, tag filter, show-hidden toggle, and
/// the entry points for add/edit, save, lock, edit-questions and the generator.
///
/// Rendering uses [EntrySummary] only — secrets are never materialized for the
/// list. Tapping a row opens the entry editor, which reveals the secret on
/// demand.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app.dart';
import '../platform/recent_vault_store.dart';
import '../platform/server_client.dart';
import '../session/cloud_session.dart';
import '../session/unlocked_vault.dart';
import '../session/vault_home.dart';
import '../session/vault_session.dart';
import 'cloud_screen.dart';
import 'entry_edit_screen.dart';
import 'password_generator_screen.dart';
import 'questions_editor_screen.dart';

enum _Menu { editQuestions, passwordGenerator, disableBiometric }

enum _SaveTarget { device, cloud }

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
    // Folded, like the search below and like `src/data.rs::same_tag`: `Work`
    // and `work` are one tag to whoever typed them.
    if (_tagFilter != null &&
        !s.tags.any((t) => t.toLowerCase() == _tagFilter)) {
      return false;
    }
    if (_query.isEmpty) return true;
    final q = _query.toLowerCase();
    return s.name.toLowerCase().contains(q) ||
        s.userName.toLowerCase().contains(q) ||
        s.url.toLowerCase().contains(q) ||
        s.tags.any((t) => t.toLowerCase().contains(q));
  }

  /// A save is in flight (serializing, or uploading to the server).
  bool _saving = false;

  void _say(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
  }

  /// Save wherever the vault lives: back to its server, or — for a local or
  /// brand-new vault — to a file on the device, or to Askrypt Cloud when
  /// signed in.
  Future<void> _save() async {
    if (_saving) return;
    setState(() => _saving = true);
    try {
      final home = ref.read(vaultHomeProvider);
      switch (home) {
        case CloudHome cloud:
          await _saveToCloud(cloud);
        case LocalHome local:
          await _saveLocal(local);
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _saveLocal(LocalHome home) async {
    await ref.read(cloudProvider.notifier).ready;
    if (!mounted) return;
    final cloud = ref.read(cloudProvider);
    if (cloud is! CloudSignedIn) return _saveToDevice(home.name);

    final choice = await showModalBottomSheet<_SaveTarget>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.phone_android),
              title: const Text('Save to this device'),
              onTap: () => Navigator.pop(ctx, _SaveTarget.device),
            ),
            ListTile(
              leading: const Icon(Icons.cloud_upload_outlined),
              title: const Text('Save to Askrypt Cloud'),
              subtitle: Text('${cloud.email} · ${cloud.client.host}'),
              onTap: () => Navigator.pop(ctx, _SaveTarget.cloud),
            ),
          ],
        ),
      ),
    );
    switch (choice) {
      case _SaveTarget.device:
        await _saveToDevice(home.name);
      case _SaveTarget.cloud:
        await _saveAsCloud(cloud, home.name);
      case null:
        break;
    }
  }

  Future<void> _saveToDevice(String name) async {
    final notifier = ref.read(vaultSessionProvider.notifier);
    final io = ref.read(vaultIoProvider);
    final bytes = await notifier.toBytes();
    final saved = await io.saveVault(bytes, suggestedName: name);
    if (!mounted) return;
    if (saved == null) {
      notifier.setModified(true);
      _say('Save cancelled');
      return;
    }
    // Refresh the welcome screen's "open last vault" cache with what we just
    // wrote. Best-effort: a cache failure must not fail the save.
    try {
      await ref.read(recentVaultStoreProvider).remember(bytes, name);
    } catch (_) {}
    _say('Vault saved');
  }

  /// The signed-in session that can write [home], or `null` after telling the
  /// user why not. Signing in happens from the start screen only: leaving for
  /// the browser would lock this vault and lose the unsaved work.
  Future<CloudSignedIn?> _sessionFor(CloudHome home) async {
    await ref.read(cloudProvider.notifier).ready;
    final cloud = ref.read(cloudProvider);
    if (cloud is CloudSignedIn && cloud.serves(home.baseUrl, home.email)) {
      return cloud;
    }
    if (!mounted) return null;
    final copy = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Not signed in'),
        content: Text(
          'Saving ${home.name} needs you signed in to ${hostOf(home.baseUrl)} '
          'as ${home.email}. Sign in from the start screen — or save a copy '
          'to this device now so nothing is lost.',
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Save a copy')),
        ],
      ),
    );
    if (copy == true) await _saveToDevice(home.name);
    return null;
  }

  /// Overwrite the vault on the server, conflict-checked against the version
  /// this session last read or wrote.
  Future<void> _saveToCloud(CloudHome home) async {
    final cloud = await _sessionFor(home);
    if (cloud == null || !mounted) return;
    final notifier = ref.read(vaultSessionProvider.notifier);
    final bytes = await notifier.toBytes();
    try {
      final vault = await cloud.client.overwrite(home.id, bytes, home.etag);
      _savedToCloud(home.withRemote(vault), 'Saved to ${cloud.client.host}');
    } on ServerException catch (e) {
      if (!mounted) return;
      notifier.setModified(true);
      if (e.kind == ServerErrorKind.conflict) {
        await _resolveConflict(cloud, home, bytes);
      } else {
        await _failed(e);
      }
    }
  }

  /// Someone else saved since we read it. Show who, and let the user decide:
  /// overwrite theirs with this version, or keep editing.
  Future<void> _resolveConflict(
      CloudSignedIn cloud, CloudHome home, Uint8List bytes) async {
    final List<RemoteVault> vaults;
    try {
      vaults = await cloud.client.list();
    } on ServerException catch (e) {
      return _failed(e);
    }
    if (!mounted) return;
    final current = vaults.where((v) => v.id == home.id).firstOrNull;

    final mine = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(current == null
            ? 'Vault deleted on the server'
            : 'Changed on another device'),
        content: Text(current == null
            ? '${home.name} is no longer on ${cloud.client.host}. Upload this '
                'version as a new vault?'
            : '${home.name} was saved elsewhere since you opened it '
                '(${describeRemote(current)}). Saving replaces that version '
                'with yours; the server keeps the previous one in its history.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: Text(current == null ? 'Upload' : 'Save mine')),
        ],
      ),
    );
    if (mine != true || !mounted) return;

    try {
      final vault = current == null
          ? await cloud.client.create(home.name, bytes)
          : await cloud.client.overwrite(home.id, bytes, current.etag);
      _savedToCloud(home.withRemote(vault), 'Saved to ${cloud.client.host}');
    } on ServerException catch (e) {
      await _failed(e);
    }
  }

  /// Upload a local or new vault to the server under a name the user picks.
  Future<void> _saveAsCloud(CloudSignedIn cloud, String suggested) async {
    final name = await _askName(suggested);
    if (name == null || !mounted) return;

    final List<RemoteVault> vaults;
    try {
      vaults = await cloud.client.list();
    } on ServerException catch (e) {
      return _failed(e);
    }
    if (!mounted) return;
    // Case-folded like the desktop wizard, though the server compares exactly:
    // two names differing only in case are a mistake waiting to happen.
    final lower = name.toLowerCase();
    final taken =
        vaults.where((v) => v.name.toLowerCase() == lower).firstOrNull;
    if (taken != null) {
      final replace = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Replace vault?'),
          content: Text('${taken.name} already exists on '
              '${cloud.client.host} (${describeRemote(taken)}). Replace it '
              'with this vault?'),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: const Text('Cancel')),
            FilledButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: const Text('Replace')),
          ],
        ),
      );
      if (replace != true || !mounted) return;
    }

    final notifier = ref.read(vaultSessionProvider.notifier);
    final bytes = await notifier.toBytes();
    try {
      final vault = taken == null
          ? await cloud.client.create(name, bytes)
          : await cloud.client.overwrite(taken.id, bytes, taken.etag);
      final home = CloudHome(
        baseUrl: cloud.client.baseUrl,
        email: cloud.email,
        id: vault.id,
        name: vault.name,
        etag: vault.etag,
      );
      _savedToCloud(home, 'Saved to ${cloud.client.host}');
    } on ServerException catch (e) {
      if (!mounted) return;
      notifier.setModified(true);
      await _failed(e);
    }
  }

  Future<String?> _askName(String suggested) async {
    final controller = TextEditingController(text: suggested);
    final name = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Save to Askrypt Cloud'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'Vault name'),
          onSubmitted: (v) => Navigator.pop(ctx, v),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, controller.text),
              child: const Text('Save')),
        ],
      ),
    );
    controller.dispose();
    final trimmed = name?.trim();
    if (trimmed == null || trimmed.isEmpty) return null;
    return trimmed.toLowerCase().endsWith('.askrypt')
        ? trimmed
        : '$trimmed.askrypt';
  }

  /// Record a landed cloud save: the new version is the next `If-Match`, the
  /// vault is now this session's home, and the welcome screen remembers it.
  void _savedToCloud(CloudHome home, String message) {
    // Locked mid-upload (the app went to the background): the save landed,
    // but there is no session left to record it in.
    if (!mounted) return;
    ref.read(vaultHomeProvider.notifier).state = home;
    final session = ref.read(vaultSessionProvider);
    if (session is VaultUnlocked && session.vault.isModified) {
      ref.read(vaultSessionProvider.notifier).setModified(false);
    }
    unawaited(ref
        .read(recentVaultStoreProvider)
        .rememberCloud(RecentCloud(
            baseUrl: home.baseUrl,
            email: home.email,
            id: home.id,
            name: home.name))
        .catchError((Object _) {}));
    _say(message);
  }

  Future<void> _failed(ServerException e) async {
    if (!mounted) return;
    if (e.kind == ServerErrorKind.auth) {
      await ref.read(cloudProvider.notifier).sessionRejected();
    }
    _say('Not saved: ${e.describe()}');
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

    final summaries = vault.summaries.where(_matches).toList()
      ..sort((a, b) => b.modified.compareTo(a.modified));
    // Keyed by the folded tag, valued by the first spelling seen, so a vault
    // holding both `Work` and `work` offers one chip rather than two that each
    // show half the entries. `_tagFilter` holds the key.
    final allTags = <String, String>{};
    for (final tag in vault.summaries.expand((s) => s.tags)) {
      allTags.putIfAbsent(tag.toLowerCase(), () => tag);
    }
    final tagKeys = allTags.keys.toList()..sort();

    return Scaffold(
      appBar: AppBar(
        title: Text(vault.isModified ? 'Askrypt •' : 'Askrypt'),
        bottom: _saving
            ? const PreferredSize(
                preferredSize: Size.fromHeight(4),
                child: LinearProgressIndicator())
            : null,
        actions: [
          IconButton(
            tooltip: 'Show hidden',
            icon: Icon(_showHidden ? Icons.visibility : Icons.visibility_off),
            onPressed: () => setState(() => _showHidden = !_showHidden),
          ),
          IconButton(
            tooltip: 'Save',
            icon: Icon(ref.watch(vaultHomeProvider) is CloudHome
                ? Icons.cloud_upload
                : Icons.save),
            onPressed: _saving ? null : _save,
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
          if (tagKeys.isNotEmpty)
            SizedBox(
              height: 48,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 12),
                children: [
                  for (final key in tagKeys)
                    Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: FilterChip(
                        label: Text(allTags[key]!),
                        selected: _tagFilter == key,
                        onSelected: (sel) =>
                            setState(() => _tagFilter = sel ? key : null),
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
