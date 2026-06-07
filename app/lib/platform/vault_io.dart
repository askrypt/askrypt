/// Vault file I/O — picking an existing `vault.askrypt` to open and writing
/// bytes back out, abstracted over `file_picker` so screens don't depend on it
/// directly (and so it can be faked in tests).
///
/// On Android this goes through the Storage Access Framework; on iOS the
/// document picker. We always request the file's *bytes* (`withData: true`)
/// rather than a path, because content-URIs on Android have no usable path.
library;

import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';

/// A vault file the user picked: its raw bytes plus a display name.
class PickedVault {
  const PickedVault({required this.bytes, required this.name});
  final Uint8List bytes;
  final String name;
}

/// Thin seam over the storage backend, so screens can be tested with a fake.
abstract class VaultIo {
  /// Let the user pick a `.askrypt` file. Returns `null` if they cancel.
  Future<PickedVault?> pickVault();

  /// Let the user choose where to write [bytes]. Returns the chosen path/uri,
  /// or `null` if cancelled.
  Future<String?> saveVault(Uint8List bytes, {String suggestedName});
}

/// Production implementation backed by `file_picker`.
class FilePickerVaultIo implements VaultIo {
  const FilePickerVaultIo();

  @override
  Future<PickedVault?> pickVault() async {
    final result = await FilePicker.pickFiles(
      dialogTitle: 'Open vault',
      type: FileType.any,
      withData: true,
    );
    final file = result?.files.singleOrNull;
    final bytes = file?.bytes;
    if (file == null || bytes == null) return null;
    return PickedVault(bytes: bytes, name: file.name);
  }

  @override
  Future<String?> saveVault(Uint8List bytes,
      {String suggestedName = 'vault.askrypt'}) {
    return FilePicker.saveFile(
      dialogTitle: 'Save vault',
      fileName: suggestedName,
      bytes: bytes,
    );
  }
}
