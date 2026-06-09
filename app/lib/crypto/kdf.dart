/// Key derivation + hashing — ports `calc_pbkdf2` and `sha256` from
/// `core/src/lib.rs`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart';

/// Lowercase hex encoding (matches Rust's `format!("{:x}", ...)`).
String _toHex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

/// `sha256(data + salt)` returned as a 64-char lowercase hex string.
///
/// Critical: this hex *string* is what gets fed into [pbkdf2] as the secret —
/// not the 32 raw digest bytes.
String sha256Hex(String data, String salt) {
  final input = Uint8List.fromList(utf8.encode(data + salt));
  final digest = SHA256Digest().process(input);
  return _toHex(digest);
}

/// PBKDF2-HMAC-SHA256. `secret` is hashed as its UTF-8 bytes; `salt` is raw
/// bytes; output is [dkLen] bytes (32 for an AES-256 key).
///
/// Delegates to the `cryptography` package so that on device
/// [FlutterCryptography.enable] (called in `main`) routes the 600k-iteration
/// derivation to native, hardware-accelerated platform crypto — an order of
/// magnitude faster than the pure-Dart loop, and fast enough to run on the UI
/// isolate without an ANR. Off device (tests) it falls back to the package's
/// Dart implementation. Either way the bytes match Rust/pointycastle.
Future<Uint8List> pbkdf2(String secret, Uint8List salt, int iterations,
    {int dkLen = 32}) async {
  final algorithm = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: iterations,
    bits: dkLen * 8,
  );
  final derived = await algorithm.deriveKey(
    secretKey: SecretKey(utf8.encode(secret)),
    nonce: salt,
  );
  return Uint8List.fromList(await derived.extractBytes());
}
