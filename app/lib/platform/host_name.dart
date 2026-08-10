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

/// Joins the OS name and the host name into the `os@host` stamp the Rust core
/// writes (`android@pixel-8`), dropping whichever half is unavailable rather
/// than leaving a dangling separator.
///
/// A host name that is missing, blank or the useless `localhost` placeholder
/// (which Android devices commonly report) counts as unavailable.
String? formatHostStamp(String? os, String? host) {
  final osName = os?.trim();
  final hostName = host?.trim();
  final hasOs = osName != null && osName.isNotEmpty;
  final hasHost =
      hostName != null && hostName.isNotEmpty && hostName != 'localhost';
  if (hasOs && hasHost) return '$osName@$hostName';
  if (hasOs) return osName;
  if (hasHost) return hostName;
  return null;
}

/// Platform default: `<operating system>@<host name>`, e.g. `android@pixel-8`,
/// falling back to whichever half the platform can supply.
String? platformHostName() {
  String? read(String Function() get) {
    try {
      return get();
    } catch (_) {
      // Either property can throw on restricted platforms.
      return null;
    }
  }

  return formatHostStamp(
    read(() => Platform.operatingSystem),
    read(() => Platform.localHostname),
  );
}

/// The active resolver; override in tests, restore in `tearDown`.
HostNameResolver hostNameResolver = platformHostName;

/// The host name to stamp into `params.host`.
String? currentHostName() => hostNameResolver();
