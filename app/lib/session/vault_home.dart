/// Where the open vault lives, which decides what "Save" does.
///
/// Mirrors desktop's `VaultHome`: a local file (the save picker asks where) or
/// a vault on an Askrypt server (overwritten in place, conflict-checked).
library;

import '../platform/server_client.dart';

sealed class VaultHome {
  const VaultHome();

  /// File name, for titles and the save picker's suggestion.
  String get name;
}

/// A file on this device, or a vault not saved anywhere yet. Saving asks where.
class LocalHome extends VaultHome {
  const LocalHome(this.name);

  @override
  final String name;
}

/// A vault on an Askrypt server.
///
/// [etag] is the version this session last read or wrote — the `If-Match` of
/// the next save. Only our own download or save moves it; a probe never does,
/// or it would license overwriting the very edit it detected.
class CloudHome extends VaultHome {
  const CloudHome({
    required this.baseUrl,
    required this.email,
    required this.id,
    required this.name,
    required this.etag,
  });

  final String baseUrl;
  final String email;
  final String id;
  @override
  final String name;
  final String etag;

  /// This home after a save the server answered with [vault].
  CloudHome withRemote(RemoteVault vault) => CloudHome(
        baseUrl: baseUrl,
        email: email,
        id: vault.id,
        name: vault.name,
        etag: vault.etag,
      );
}
