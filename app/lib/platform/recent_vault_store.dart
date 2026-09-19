/// Remembers the most recently unlocked vault so the welcome screen can offer
/// to reopen it with one tap.
///
/// Android hands us SAF content-URIs with no persistable path, so instead of
/// remembering *where* the vault lives we cache a copy of its bytes in the
/// app-private support directory. The cache holds exactly what the picked file
/// held — the encrypted vault, never decrypted data — so its at-rest security
/// is the same as the original file's. The copy is refreshed on every
/// successful unlock and every save; if the original is edited elsewhere in
/// between, the cached copy is simply a stale snapshot and the user can still
/// pick the real file manually.
///
/// A vault on an Askrypt server is remembered by *location* instead (server,
/// account, vault id, name — no bytes): reopening it downloads the latest
/// version, and a cloud vault leaves no copy of itself on the device.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import 'vault_io.dart';

/// The remembered vault: a cached local file, or where a cloud vault lives.
sealed class RecentVault {
  const RecentVault();
  String get name;
}

class RecentLocal extends RecentVault {
  const RecentLocal(this.vault);
  final PickedVault vault;

  @override
  String get name => vault.name;
}

class RecentCloud extends RecentVault {
  const RecentCloud({
    required this.baseUrl,
    required this.email,
    required this.id,
    required this.name,
  });

  final String baseUrl;
  final String email;
  final String id;
  @override
  final String name;

  Map<String, dynamic> toJson() => {
        'kind': 'cloud',
        'base_url': baseUrl,
        'email': email,
        'id': id,
        'name': name,
      };

  static RecentCloud? fromJson(Object? json) {
    if (json is! Map<String, dynamic> || json['kind'] != 'cloud') return null;
    final baseUrl = json['base_url'], email = json['email'];
    final id = json['id'], name = json['name'];
    if (baseUrl is! String || email is! String || id is! String) return null;
    if (name is! String) return null;
    return RecentCloud(baseUrl: baseUrl, email: email, id: id, name: name);
  }
}

/// Seam over the recent-vault cache, so screens can be tested with a fake.
abstract class RecentVaultStore {
  /// The remembered vault, or `null` if none was cached yet.
  Future<RecentVault?> load();

  /// Cache [bytes] (the encrypted vault file) under display [name].
  Future<void> remember(Uint8List bytes, String name);

  /// Remember a cloud vault by location, dropping any cached local bytes.
  Future<void> rememberCloud(RecentCloud vault);

  /// Drop the cached vault.
  Future<void> forget();
}

/// Production implementation: `recent.askrypt` + `recent.name` (local) or
/// `recent.json` (cloud) in the application support directory.
class FileRecentVaultStore implements RecentVaultStore {
  const FileRecentVaultStore();

  Future<File> _file(String leaf) async {
    final dir = await getApplicationSupportDirectory();
    return File('${dir.path}/$leaf');
  }

  @override
  Future<RecentVault?> load() async {
    final cloud = await _file('recent.json');
    if (await cloud.exists()) {
      try {
        final found = RecentCloud.fromJson(jsonDecode(await cloud.readAsString()));
        if (found != null) return found;
      } catch (_) {
        // Unreadable: fall through to the local cache, if any.
      }
    }
    final vault = await _file('recent.askrypt');
    if (!await vault.exists()) return null;
    final bytes = await vault.readAsBytes();
    final nameFile = await _file('recent.name');
    final name =
        await nameFile.exists() ? await nameFile.readAsString() : 'vault.askrypt';
    return RecentLocal(PickedVault(bytes: bytes, name: name));
  }

  @override
  Future<void> remember(Uint8List bytes, String name) async {
    await (await _file('recent.askrypt')).writeAsBytes(bytes, flush: true);
    await (await _file('recent.name')).writeAsString(name, flush: true);
    await _delete(const ['recent.json']);
  }

  @override
  Future<void> rememberCloud(RecentCloud vault) async {
    await (await _file('recent.json'))
        .writeAsString(jsonEncode(vault.toJson()), flush: true);
    await _delete(const ['recent.askrypt', 'recent.name']);
  }

  @override
  Future<void> forget() =>
      _delete(const ['recent.askrypt', 'recent.name', 'recent.json']);

  Future<void> _delete(List<String> leaves) async {
    for (final leaf in leaves) {
      final f = await _file(leaf);
      if (await f.exists()) await f.delete();
    }
  }
}
