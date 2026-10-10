/// Remembers the most recently opened vaults (up to [maxRecentVaults], newest
/// first) so the welcome screen can offer to reopen each with one tap.
///
/// Android hands us SAF content-URIs with no persistable path, so instead of
/// remembering *where* a local vault lives we cache a copy of its bytes in the
/// app-private support directory. The cache holds exactly what the picked file
/// held — the encrypted vault, never decrypted data — so its at-rest security
/// is the same as the original file's. A copy is refreshed on every successful
/// unlock and every save; if the original is edited elsewhere in between, the
/// cached copy is simply a stale snapshot and the user can still pick the real
/// file manually. With no path, a local vault is known by its display name:
/// two files with the same name share one slot.
///
/// A vault on an Askrypt server is remembered by *location* instead (server,
/// account, vault id, name — no bytes): reopening it downloads the latest
/// version. Its bytes are kept separately, as an offline copy
/// (`offline_copy_store.dart`), only for when the server is unreachable.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/export.dart';

import 'vault_io.dart';

/// How many vaults the welcome screen offers to reopen.
const maxRecentVaults = 5;

/// A remembered vault: a cached local file, or where a cloud vault lives.
sealed class RecentVault {
  const RecentVault();
  String get name;

  /// Whether [other] is the same vault (possibly at another time or name).
  bool sameAs(RecentVault other);
}

class RecentLocal extends RecentVault {
  const RecentLocal(this.vault);
  final PickedVault vault;

  @override
  String get name => vault.name;

  @override
  bool sameAs(RecentVault other) => other is RecentLocal && other.name == name;
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

  @override
  bool sameAs(RecentVault other) =>
      other is RecentCloud &&
      other.baseUrl == baseUrl &&
      other.email == email &&
      other.id == id;

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
  /// The remembered vaults, newest first (empty if none yet).
  Future<List<RecentVault>> load();

  /// Cache [bytes] (the encrypted vault file) under display [name] and move
  /// it to the front.
  Future<void> remember(Uint8List bytes, String name);

  /// Remember a cloud vault by location and move it to the front.
  Future<void> rememberCloud(RecentCloud vault);

  /// Drop one remembered vault (and its cached bytes, if local).
  Future<void> forget(RecentVault vault);
}

/// Production implementation: `recent/index.json` (newest first) plus one
/// `recent/<sha256(name)>.askrypt` per local vault, in the application
/// support directory.
class FileRecentVaultStore implements RecentVaultStore {
  /// [directory] overrides the support directory (tests).
  FileRecentVaultStore({Future<Directory> Function()? directory})
      : _directory = directory ?? getApplicationSupportDirectory;

  final Future<Directory> Function() _directory;

  /// Operations run one at a time: unlock and save remember fire-and-forget,
  /// and two interleaved index rewrites would lose an entry.
  Future<void> _queue = Future.value();

  Future<T> _serial<T>(Future<T> Function() op) {
    final result = _queue.then((_) => op());
    _queue = result.then((_) {}, onError: (_) {});
    return result;
  }

  Future<Directory> _recentDir() async =>
      Directory('${(await _directory()).path}/recent');

  /// The cache file for a local vault. A hash rather than the name: the name
  /// is whatever the picker reported, and a separator in it must not decide
  /// where a file is written.
  static String _fileFor(String name) =>
      '${SHA256Digest().process(utf8.encode(name)).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}.askrypt';

  @override
  Future<List<RecentVault>> load() => _serial(() async {
        final dir = await _recentDir();
        final index = await _readIndex(dir);
        final found = <RecentVault>[];
        for (final entry in index) {
          final cloud = RecentCloud.fromJson(entry);
          if (cloud != null) {
            found.add(cloud);
            continue;
          }
          if (entry is! Map<String, dynamic> || entry['kind'] != 'local') {
            continue;
          }
          final name = entry['name'];
          if (name is! String) continue;
          final file = File('${dir.path}/${_fileFor(name)}');
          try {
            found.add(RecentLocal(
                PickedVault(bytes: await file.readAsBytes(), name: name)));
          } catch (_) {
            // Missing or unreadable copy: skip it.
          }
        }
        return found;
      });

  @override
  Future<void> remember(Uint8List bytes, String name) => _serial(() async {
        final dir = await _recentDir();
        await dir.create(recursive: true);
        await _replace(File('${dir.path}/${_fileFor(name)}'), bytes);
        await _putFirst(dir, {'kind': 'local', 'name': name});
      });

  @override
  Future<void> rememberCloud(RecentCloud vault) => _serial(() async {
        final dir = await _recentDir();
        await dir.create(recursive: true);
        await _putFirst(dir, vault.toJson());
      });

  @override
  Future<void> forget(RecentVault vault) => _serial(() async {
        final dir = await _recentDir();
        final index = await _readIndex(dir);
        final kept = index.where((e) => !_matches(e, vault)).toList();
        await _writeIndex(dir, kept);
        if (vault is RecentLocal) {
          await _deleteIfExists(File('${dir.path}/${_fileFor(vault.name)}'));
        }
      });

  /// Insert [entry] at the front, drop older entries for the same vault, trim
  /// to [maxRecentVaults] and delete the bytes of evicted local vaults.
  Future<void> _putFirst(Directory dir, Map<String, dynamic> entry) async {
    final probe = _parse(entry)!;
    final rest = (await _readIndex(dir)).where((e) => !_matches(e, probe));
    final next = [entry, ...rest];
    final kept = next.take(maxRecentVaults).toList();
    await _writeIndex(dir, kept);
    // Entries are unique per vault, so no kept entry shares an evicted file.
    for (final evicted in next.skip(maxRecentVaults)) {
      if (_parse(evicted) case RecentLocal(:final name)) {
        await _deleteIfExists(File('${dir.path}/${_fileFor(name)}'));
      }
    }
  }

  static PickedVault _stub(String name) =>
      PickedVault(bytes: Uint8List(0), name: name);

  /// The identity of an index entry, without reading any bytes.
  static RecentVault? _parse(Object? entry) {
    final cloud = RecentCloud.fromJson(entry);
    if (cloud != null) return cloud;
    if (entry is Map<String, dynamic> &&
        entry['kind'] == 'local' &&
        entry['name'] is String) {
      return RecentLocal(_stub(entry['name'] as String));
    }
    return null;
  }

  static bool _matches(Object? entry, RecentVault vault) =>
      _parse(entry)?.sameAs(vault) ?? false;

  /// The index, newest first; migrates the single-vault layout of earlier
  /// versions (`recent.json`, or `recent.askrypt` + `recent.name`) on first
  /// read. Unreadable ⇒ empty.
  Future<List<Object?>> _readIndex(Directory dir) async {
    final file = File('${dir.path}/index.json');
    if (await file.exists()) {
      try {
        final decoded = jsonDecode(await file.readAsString());
        if (decoded is List) return decoded;
      } catch (_) {}
      return [];
    }
    return _migrateLegacy(dir);
  }

  Future<List<Object?>> _migrateLegacy(Directory dir) async {
    final root = (await _directory()).path;
    final cloud = File('$root/recent.json');
    final bytes = File('$root/recent.askrypt');
    final nameFile = File('$root/recent.name');
    if (!await cloud.exists() && !await bytes.exists()) return [];
    final index = <Object?>[];
    try {
      final found = await cloud.exists()
          ? RecentCloud.fromJson(jsonDecode(await cloud.readAsString()))
          : null;
      await dir.create(recursive: true);
      if (found != null) {
        index.add(found.toJson());
      } else if (await bytes.exists()) {
        final name = await nameFile.exists()
            ? await nameFile.readAsString()
            : 'vault.askrypt';
        await _replace(
            File('${dir.path}/${_fileFor(name)}'), await bytes.readAsBytes());
        index.add({'kind': 'local', 'name': name});
      }
      await _writeIndex(dir, index);
    } catch (_) {
      return [];
    }
    for (final f in [cloud, bytes, nameFile]) {
      await _deleteIfExists(f);
    }
    return index;
  }

  static Future<void> _writeIndex(Directory dir, List<Object?> index) async {
    await dir.create(recursive: true);
    await _replace(
        File('${dir.path}/index.json'), utf8.encode(jsonEncode(index)));
  }

  static Future<void> _replace(File dest, List<int> bytes) async {
    final staged = File('${dest.path}.tmp');
    try {
      await staged.writeAsBytes(bytes, flush: true);
      await staged.rename(dest.path);
    } catch (_) {
      if (await staged.exists()) await staged.delete();
      rethrow;
    }
  }

  static Future<void> _deleteIfExists(File f) async {
    if (await f.exists()) await f.delete();
  }
}
