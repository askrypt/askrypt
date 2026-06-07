/// Password generator — pure-Dart port of `core/src/passgen.rs`.
///
/// Same character sets, same length clamp (8..100), same "at least one set"
/// rule. Uses `Random.secure()` for generation. UI lives in
/// `screens/password_generator_screen.dart`.
library;

import 'dart:math';

const String _lowercase = 'abcdefghijklmnopqrstuvwxyz';
const String _uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const String _numbers = '0123456789';
const String _symbols = r'!@#$%^&*()_+-=[]{}|;:,.<>?';

class PasswordGenConfig {
  PasswordGenConfig({
    this.length = 20,
    this.useUppercase = true,
    this.useLowercase = true,
    this.useNumbers = true,
    this.useSymbols = true,
  });

  static const int minLength = 8;
  static const int maxLength = 100;

  int length;
  bool useUppercase;
  bool useLowercase;
  bool useNumbers;
  bool useSymbols;

  void setLength(int value) =>
      length = value.clamp(minLength, maxLength);

  bool get hasValidOptions =>
      useUppercase || useLowercase || useNumbers || useSymbols;

  String get _charset {
    final buf = StringBuffer();
    if (useLowercase) buf.write(_lowercase);
    if (useUppercase) buf.write(_uppercase);
    if (useNumbers) buf.write(_numbers);
    if (useSymbols) buf.write(_symbols);
    return buf.toString();
  }
}

/// Thrown when no character class is enabled.
class PasswordGenException implements Exception {
  PasswordGenException(this.message);
  final String message;
  @override
  String toString() => 'PasswordGenException: $message';
}

String generatePassword(PasswordGenConfig config, {Random? rng}) {
  if (!config.hasValidOptions) {
    throw PasswordGenException('At least one character type must be selected');
  }
  final charset = config._charset;
  final r = rng ?? Random.secure();
  final buf = StringBuffer();
  for (var i = 0; i < config.length; i++) {
    buf.write(charset[r.nextInt(charset.length)]);
  }
  return buf.toString();
}
