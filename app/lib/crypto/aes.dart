/// AES-256-CBC + PKCS7 — ports `encrypt_with_aes` / `decrypt_with_aes` from
/// `core/src/lib.rs`.
///
/// Uses an explicit block loop + `doFinal` rather than pointycastle's
/// `PaddedBlockCipherImpl.process()` convenience method, which miscomputes the
/// output length for empty input (`inputBlocks` rounds to 0 → negative offset).
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

Uint8List _run(bool forEncryption, Uint8List input, Uint8List key, Uint8List iv) {
  final cipher = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()));
  cipher.init(
    forEncryption,
    PaddedBlockCipherParameters<CipherParameters, CipherParameters>(
      ParametersWithIV<KeyParameter>(KeyParameter(key), iv),
      null,
    ),
  );
  final bs = cipher.blockSize;
  // Encryption may append a whole extra padding block; decryption never grows.
  final out = Uint8List(forEncryption ? (input.length ~/ bs + 1) * bs : input.length);

  var inOff = 0;
  var outOff = 0;
  // Run all full blocks except the trailing one through processBlock; doFinal
  // handles the last block (adds/removes PKCS7 padding).
  while (input.length - inOff > bs) {
    cipher.processBlock(input, inOff, out, outOff);
    inOff += bs;
    outOff += bs;
  }
  outOff += cipher.doFinal(input, inOff, out, outOff);
  return out.sublist(0, outOff);
}

Uint8List aesCbcEncrypt(Uint8List plaintext, Uint8List key, Uint8List iv) =>
    _run(true, plaintext, key, iv);

Uint8List aesCbcDecrypt(Uint8List ciphertext, Uint8List key, Uint8List iv) =>
    _run(false, ciphertext, key, iv);
