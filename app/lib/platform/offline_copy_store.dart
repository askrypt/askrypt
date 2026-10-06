/// Offline copies of cloud vaults — the mobile twin of desktop's
/// `src/offline.rs`.
///
/// Every time a cloud vault is downloaded or saved, the bytes that just
/// crossed the wire are also kept in `<support>/vaults/` — the same ciphertext
/// the server holds, nothing decrypted. When the server later cannot be
/// reached, the copy is offered instead, and opened with a [CloudHome] at the
/// ETag it was kept at, so a save once the server is back is conflict-checked
/// against *that* version rather than whatever the server holds by then.
///
/// The copy is only ever written from bytes the server has: never from an edit
/// made to the copy itself. Writing it is a courtesy, so a failure is logged
/// and never stops the open or the save it rides on.
///
/// The support directory rather than the cache: Android may empty a cache
/// under storage pressure, which is exactly when a copy might be needed.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/export.dart';

/// Which cloud vault a copy belongs to. Ids survive a rename on the server,
/// so they — not names — identify the vault, like the recent-vault store.
class OfflineLocation {
  const OfflineLocation({
    required this.baseUrl,
    required this.email,
    required this.id,
  });

  final String baseUrl;
  final String email;
  final String id;

  /// The file stem the copy is kept under.
  ///
  /// A hash rather than the id: the id is server-supplied text, and a `..` or
  /// a separator in it must not decide where a file is written. Server and
  /// account are part of it, so two accounts' vaults never share a copy.
  String get key {
    final input = BytesBuilder();
    for (final part in [baseUrl, email, id]) {
      input.add(utf8.encode(part));
      // A separator no part can contain, so ("ab", "c") and ("a", "bc") differ.
      input.addByte(0);
    }
    return SHA256Digest()
        .process(input.toBytes())
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  bool sameAs(OfflineLocation other) =>
      baseUrl == other.baseUrl && email == other.email && id == other.id;
}

/// A copy found on the device.
class OfflineCopy {
  const OfflineCopy({
    required this.location,
    required this.name,
    required this.etag,
    required this.cachedAt,
    required this.bytes,
  });

  final OfflineLocation location;

  /// The vault's name when the copy was taken.
  final String name;

  /// The server's ETag for exactly these bytes.
  final String etag;

  /// When the copy was taken, RFC 3339 UTC.
  final String cachedAt;

  final Uint8List bytes;
}

/// Seam over the copies, so screens can be tested with a fake.
abstract class OfflineCopyStore {
  /// Keep [bytes] as the copy of [location], at [etag].
  Future<void> keep(
      OfflineLocation location, String name, Uint8List bytes, String etag);

  /// The copy kept for [location], if both halves are there and the sidecar
  /// still describes this vault.
  Future<OfflineCopy?> load(OfflineLocation location);

  /// Forget the copy of a vault the server no longer has.
  Future<void> remove(OfflineLocation location);

  /// Delete every copy — the setting was switched off.
  Future<void> clearAll();
}

/// Production implementation: `<key>.askrypt` + `<key>.json` sidecar.
class FileOfflineCopyStore implements OfflineCopyStore {
  /// [directory] overrides where copies live (tests); by default
  /// `<application support>/vaults`.
  FileOfflineCopyStore({Future<Directory> Function()? directory})
      : _directory = directory ?? _defaultDirectory;

  final Future<Directory> Function() _directory;

  static Future<Directory> _defaultDirectory() async =>
      Directory('${(await getApplicationSupportDirectory()).path}/vaults');

  /// Archive first, sidecar second, each staged and renamed into place: a
  /// copy is only ever found (see [load]) once both halves are whole, and a
  /// write that dies halfway leaves the previous copy readable.
  @override
  Future<void> keep(OfflineLocation location, String name, Uint8List bytes,
      String etag) async {
    final dir = await _directory();
    await dir.create(recursive: true);
    final key = location.key;
    await _replace(File('${dir.path}/$key.askrypt'), bytes);
    final meta = {
      'base_url': location.baseUrl,
      'email': location.email,
      'id': location.id,
      'name': name,
      'etag': etag,
      'cached_at': _nowRfc3339(),
    };
    await _replace(File('${dir.path}/$key.json'),
        utf8.encode(const JsonEncoder.withIndent('  ').convert(meta)));
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

  @override
  Future<OfflineCopy?> load(OfflineLocation location) async {
    final dir = await _directory();
    final key = location.key;
    final archive = File('${dir.path}/$key.askrypt');
    final sidecar = File('${dir.path}/$key.json');
    if (!await archive.exists() || !await sidecar.exists()) return null;
    try {
      final meta = jsonDecode(await sidecar.readAsString());
      if (meta is! Map<String, dynamic>) return null;
      final baseUrl = meta['base_url'], email = meta['email'];
      final id = meta['id'], name = meta['name'];
      final etag = meta['etag'], cachedAt = meta['cached_at'];
      if (baseUrl is! String || email is! String || id is! String) return null;
      if (name is! String || etag is! String || cachedAt is! String) {
        return null;
      }
      final found = OfflineLocation(baseUrl: baseUrl, email: email, id: id);
      if (!found.sameAs(location)) return null;
      return OfflineCopy(
        location: found,
        name: name,
        etag: etag,
        cachedAt: cachedAt,
        bytes: await archive.readAsBytes(),
      );
    } catch (_) {
      return null;
    }
  }

  @override
  Future<void> remove(OfflineLocation location) async {
    final dir = await _directory();
    final key = location.key;
    for (final leaf in ['$key.json', '$key.askrypt']) {
      final f = File('${dir.path}/$leaf');
      if (await f.exists()) await f.delete();
    }
  }

  @override
  Future<void> clearAll() async {
    final dir = await _directory();
    if (await dir.exists()) await dir.delete(recursive: true);
  }
}

String _nowRfc3339() {
  final now = DateTime.now().toUtc();
  // Seconds precision, `Z` suffix — desktop's `SecondsFormat::Secs`.
  return '${now.toIso8601String().split('.').first}Z';
}
