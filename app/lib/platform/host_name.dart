/// Best-effort name of this device, recorded in the vault's `params.host` so
/// the user can tell which machine wrote the file last.
///
/// This lands in the *unencrypted* part of the vault, so it must stay a coarse
/// device label — never anything user-identifying beyond the host name the OS
/// already advertises on the network.
///
/// Kept out of `lib/crypto/` (which is pure Dart, no `dart:io`) and behind a
/// swappable resolver so tests can pin a deterministic value.
library;

import 'dart:io';

/// Resolves the current host name, or `null` when it cannot be determined.
typedef HostNameResolver = String? Function();

/// Platform default: the OS host name, falling back to the platform name when
/// the host name is missing or a useless placeholder (Android devices commonly
/// report `localhost`).
String? platformHostName() {
  try {
    final host = Platform.localHostname.trim();
    if (host.isNotEmpty && host != 'localhost') return host;
  } catch (_) {
    // localHostname can throw on restricted platforms; fall through.
  }
  try {
    return Platform.operatingSystem;
  } catch (_) {
    return null;
  }
}

/// The active resolver; override in tests, restore in `tearDown`.
HostNameResolver hostNameResolver = platformHostName;

/// The host name to stamp into `params.host`.
String? currentHostName() => hostNameResolver();
