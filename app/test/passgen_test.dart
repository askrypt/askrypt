/// Unit tests for the Dart password generator (mirrors the Rust passgen tests
/// in `core/src/passgen.rs`).
library;

import 'package:askrypt/passgen.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('default config matches the Rust defaults', () {
    final c = PasswordGenConfig();
    expect(c.length, 20);
    expect(c.useUppercase, isTrue);
    expect(c.useLowercase, isTrue);
    expect(c.useNumbers, isTrue);
    expect(c.useSymbols, isTrue);
  });

  test('generated password has the requested length', () {
    expect(generatePassword(PasswordGenConfig()).length, 20);
    expect(generatePassword(PasswordGenConfig(length: 42)).length, 42);
  });

  test('length is clamped to [min, max]', () {
    final c = PasswordGenConfig()..setLength(5);
    expect(c.length, PasswordGenConfig.minLength);
    c.setLength(150);
    expect(c.length, PasswordGenConfig.maxLength);
  });

  test('throws when no character class is enabled', () {
    final c = PasswordGenConfig(
      useUppercase: false,
      useLowercase: false,
      useNumbers: false,
      useSymbols: false,
    );
    expect(c.hasValidOptions, isFalse);
    expect(() => generatePassword(c), throwsA(isA<PasswordGenException>()));
  });

  test('only uses characters from the enabled classes', () {
    final c = PasswordGenConfig(
      length: 200,
      useUppercase: false,
      useLowercase: false,
      useNumbers: true,
      useSymbols: false,
    );
    expect(generatePassword(c), matches(RegExp(r'^[0-9]+$')));
  });
}
