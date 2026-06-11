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
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import 'vault_io.dart';

/// Seam over the recent-vault cache, so screens can be tested with a fake.
abstract class RecentVaultStore {
  /// The remembered vault, or `null` if none was cached yet.
  Future<PickedVault?> load();

  /// Cache [bytes] (the encrypted vault file) under display [name].
  Future<void> remember(Uint8List bytes, String name);

  /// Drop the cached vault.
  Future<void> forget();
}

/// Production implementation: `recent.askrypt` + `recent.name` in the
/// application support directory.
class FileRecentVaultStore implements RecentVaultStore {
  const FileRecentVaultStore();

  Future<File> _file(String leaf) async {
    final dir = await getApplicationSupportDirectory();
    return File('${dir.path}/$leaf');
  }

  @override
  Future<PickedVault?> load() async {
    final vault = await _file('recent.askrypt');
    if (!await vault.exists()) return null;
    final bytes = await vault.readAsBytes();
    final nameFile = await _file('recent.name');
    final name =
        await nameFile.exists() ? await nameFile.readAsString() : 'vault.askrypt';
    return PickedVault(bytes: bytes, name: name);
  }

  @override
  Future<void> remember(Uint8List bytes, String name) async {
    await (await _file('recent.askrypt')).writeAsBytes(bytes, flush: true);
    await (await _file('recent.name')).writeAsString(name, flush: true);
  }

  @override
  Future<void> forget() async {
    for (final leaf in const ['recent.askrypt', 'recent.name']) {
      final f = await _file(leaf);
      if (await f.exists()) await f.delete();
    }
  }
}
