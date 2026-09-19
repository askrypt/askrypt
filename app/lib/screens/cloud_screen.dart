/// Askrypt Cloud (locked side): sign in through the browser, then pick a vault
/// stored on the server — the mobile twin of the desktop wizard's server step.
///
/// No credentials are typed here. "Sign in with browser" opens a device link;
/// the page shows the same code as this screen, the user signs in (or
/// registers) there, and the app polls until it holds a session. The listing
/// is refetched every time the screen opens, like the desktop wizard.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../platform/server_client.dart';
import '../session/cloud_session.dart';
import '../session/vault_home.dart';
import 'unlock_screen.dart';

class CloudScreen extends ConsumerStatefulWidget {
  const CloudScreen({super.key});

  @override
  ConsumerState<CloudScreen> createState() => _CloudScreenState();
}

class _CloudScreenState extends ConsumerState<CloudScreen>
    with WidgetsBindingObserver {
  final _url = TextEditingController();

  /// `null` = not fetched yet (loading or signed out), empty = no vaults.
  List<RemoteVault>? _vaults;
  String? _listError;
  bool _loading = false;

  /// Id of the vault being downloaded, to show progress on its row.
  String? _opening;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _url.text = ref.read(cloudProvider).serverUrl;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      await ref.read(cloudProvider.notifier).ready;
      if (!mounted) return;
      _url.text = ref.read(cloudProvider).serverUrl;
      await _refresh();
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _url.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Back from the browser: ask now rather than at the next tick.
    if (state == AppLifecycleState.resumed) {
      ref.read(cloudProvider.notifier).pollNow();
    }
  }

  Future<void> _refresh() async {
    final cloud = ref.read(cloudProvider);
    if (cloud is! CloudSignedIn) return;
    setState(() {
      _loading = true;
      _listError = null;
    });
    try {
      final vaults = await cloud.client.list();
      if (!mounted) return;
      setState(() => _vaults = vaults);
    } on ServerException catch (e) {
      if (e.kind == ServerErrorKind.auth) {
        await ref.read(cloudProvider.notifier).sessionRejected();
      }
      if (!mounted) return;
      setState(() => _listError = e.describe());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _signIn() async {
    final notifier = ref.read(cloudProvider.notifier);
    await notifier.setServerUrl(_url.text);
    await notifier.signIn();
  }

  Future<void> _open(CloudSignedIn cloud, RemoteVault vault) async {
    if (_opening != null) return;
    setState(() => _opening = vault.id);
    final error = await openCloudVault(context, ref, cloud,
        id: vault.id, name: vault.name, listedEtag: vault.etag);
    if (!mounted) return;
    setState(() => _opening = null);
    if (error != null) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(error)));
    }
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<CloudState>(cloudProvider, (prev, next) {
      if (next is CloudSignedIn && prev is! CloudSignedIn) {
        _refresh();
      } else if (next is! CloudSignedIn) {
        setState(() => _vaults = null);
      }
    });
    final cloud = ref.watch(cloudProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Askrypt Cloud'),
        actions: [
          if (cloud is CloudSignedIn)
            IconButton(
              tooltip: 'Refresh',
              icon: const Icon(Icons.refresh),
              onPressed: _loading ? null : _refresh,
            ),
        ],
      ),
      body: switch (cloud) {
        CloudSignedOut out => _signedOut(out),
        CloudLinking linking => _linking(linking),
        CloudSignedIn signedIn => _signedIn(signedIn),
      },
    );
  }

  Widget _signedOut(CloudSignedOut cloud) {
    final theme = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text(
          'Keep vaults on an Askrypt server and open them on any device. The '
          'server stores only encrypted files — your answers never leave '
          'this phone.',
          style: theme.textTheme.bodyMedium,
        ),
        const SizedBox(height: 24),
        TextField(
          controller: _url,
          enabled: !cloud.starting,
          keyboardType: TextInputType.url,
          autocorrect: false,
          decoration: const InputDecoration(
            labelText: 'Server',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        if (cloud.error != null) ...[
          Text(cloud.error!, style: TextStyle(color: theme.colorScheme.error)),
          const SizedBox(height: 16),
        ],
        FilledButton.icon(
          onPressed: cloud.starting ? null : _signIn,
          icon: cloud.starting
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.open_in_browser),
          label: const Text('Sign in with browser'),
        ),
        const SizedBox(height: 12),
        Text(
          'A page opens in your browser. Sign in there — or create an '
          'account — and this app signs itself in.',
          textAlign: TextAlign.center,
          style: theme.textTheme.bodySmall
              ?.copyWith(color: theme.colorScheme.outline),
        ),
      ],
    );
  }

  Widget _linking(CloudLinking cloud) {
    final theme = Theme.of(context);
    final notifier = ref.read(cloudProvider.notifier);
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text(
          cloud.stalled
              ? 'Still waiting for your browser'
              : 'Finish signing in in your browser',
          textAlign: TextAlign.center,
          style: theme.textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        Text(
          cloud.stalled
              ? 'The page is still valid for 24 hours. Open it again to carry on.'
              : 'Sign in there — or create an account — then come back here.',
          textAlign: TextAlign.center,
          style: theme.textTheme.bodyMedium,
        ),
        const SizedBox(height: 24),
        // The one thing that makes approving-on-sight safe: the page shows
        // this code too, and a page showing a different one is somebody
        // else's sign-in.
        SelectableText(
          cloud.userCode,
          textAlign: TextAlign.center,
          style: theme.textTheme.headlineMedium
              ?.copyWith(fontWeight: FontWeight.bold, letterSpacing: 2),
        ),
        const SizedBox(height: 4),
        Text('The page should show this code.',
            textAlign: TextAlign.center, style: theme.textTheme.bodySmall),
        const SizedBox(height: 24),
        if (!cloud.stalled) const LinearProgressIndicator(),
        const SizedBox(height: 24),
        FilledButton.tonalIcon(
          onPressed: notifier.reopen,
          icon: const Icon(Icons.open_in_browser),
          label: const Text('Open the page again'),
        ),
        const SizedBox(height: 8),
        TextButton(onPressed: notifier.cancel, child: const Text('Cancel')),
      ],
    );
  }

  Widget _signedIn(CloudSignedIn cloud) {
    final theme = Theme.of(context);
    final vaults = _vaults;
    final Widget list;
    if (_listError != null && vaults == null) {
      list = ListView(children: [
        Padding(
          padding: const EdgeInsets.all(24),
          child: Text(_listError!,
              textAlign: TextAlign.center,
              style: TextStyle(color: theme.colorScheme.error)),
        ),
      ]);
    } else if (vaults == null) {
      list = const Center(child: CircularProgressIndicator());
    } else if (vaults.isEmpty) {
      list = ListView(children: const [
        Padding(
          padding: EdgeInsets.all(24),
          child: Text(
            'No vaults on this server yet. Open or create one, then choose '
            '"Save to Askrypt Cloud".',
            textAlign: TextAlign.center,
          ),
        ),
      ]);
    } else {
      list = ListView.separated(
        itemCount: vaults.length,
        separatorBuilder: (_, __) => const Divider(height: 1),
        itemBuilder: (_, i) {
          final vault = vaults[i];
          return ListTile(
            leading: const Icon(Icons.cloud_outlined),
            title: Text(vault.name),
            subtitle: Text(describeRemote(vault)),
            trailing: _opening == vault.id
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : null,
            onTap: _opening == null ? () => _open(cloud, vault) : null,
          );
        },
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ListTile(
          leading: const Icon(Icons.account_circle_outlined),
          title: Text(cloud.email),
          subtitle: Text(cloud.client.host),
          trailing: TextButton(
            onPressed: () => ref.read(cloudProvider.notifier).signOut(),
            child: const Text('Sign out'),
          ),
        ),
        if (_loading && vaults != null) const LinearProgressIndicator(),
        const Divider(height: 1),
        Expanded(child: RefreshIndicator(onRefresh: _refresh, child: list)),
      ],
    );
  }
}

/// Download a cloud vault and push the unlock screen for it. Returns a
/// sentence to show when it could not be opened, `null` on success.
///
/// [listedEtag] is the listing's ETag, used only when the download carried
/// none: the next save must be conflict-checked against *some* version.
Future<String?> openCloudVault(
  BuildContext context,
  WidgetRef ref,
  CloudSignedIn cloud, {
  required String id,
  required String name,
  String? listedEtag,
}) async {
  try {
    final (bytes, etag) = await cloud.client.download(id);
    if (!context.mounted) return null;
    final home = CloudHome(
      baseUrl: cloud.client.baseUrl,
      email: cloud.email,
      id: id,
      name: name,
      etag: etag.isNotEmpty ? etag : (listedEtag ?? ''),
    );
    Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) => UnlockScreen(bytes: bytes, home: home)));
    return null;
  } on ServerException catch (e) {
    if (e.kind == ServerErrorKind.auth) {
      await ref.read(cloudProvider.notifier).sessionRejected();
    }
    return e.kind == ServerErrorKind.notFound
        ? 'That vault is no longer on the server.'
        : e.describe();
  }
}

/// "12.3 KB · saved Sep 19, 2026 14:05 on android@pixel-8".
String describeRemote(RemoteVault vault) {
  final parts = <String>[formatBytes(vault.size)];
  final when = DateTime.tryParse(vault.savedAt ?? vault.updatedAt);
  final saved = StringBuffer();
  if (when != null) saved.write('saved ${formatLocalTime(when)}');
  final host = vault.host;
  if (host != null && host.isNotEmpty) {
    saved.write(saved.isEmpty ? 'saved on $host' : ' on $host');
  }
  if (saved.isNotEmpty) parts.add(saved.toString());
  return parts.join(' · ');
}

String formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}

const _months = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', //
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

/// Desktop's `DATETIME_FORMAT` (`%b %-d, %Y %H:%M`), in local time.
String formatLocalTime(DateTime time) {
  final t = time.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${_months[t.month - 1]} ${t.day}, ${t.year} ${two(t.hour)}:${two(t.minute)}';
}
