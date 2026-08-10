/// Unit tests for the `params.host` write-stamp label (mirrors the Rust
/// `current_host` tests in `core/src/lib.rs`).
library;

import 'package:askrypt/platform/host_name.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('both halves join as os@host', () {
    expect(formatHostStamp('android', 'pixel-8'), 'android@pixel-8');
    expect(formatHostStamp(' ios ', ' iphone '), 'ios@iphone');
  });

  test('a missing half drops out rather than dangling', () {
    expect(formatHostStamp('android', null), 'android');
    expect(formatHostStamp('android', '  '), 'android');
    expect(formatHostStamp(null, 'pixel-8'), 'pixel-8');
    expect(formatHostStamp('', 'pixel-8'), 'pixel-8');
    expect(formatHostStamp(null, null), isNull);
    expect(formatHostStamp('  ', ''), isNull);
  });

  test('the localhost placeholder is not a host name', () {
    // Android devices commonly report `localhost`, which names no machine.
    expect(formatHostStamp('android', 'localhost'), 'android');
    expect(formatHostStamp(null, 'localhost'), isNull);
  });

  test('the resolver seam is swappable and restores', () {
    final original = hostNameResolver;
    addTearDown(() => hostNameResolver = original);

    hostNameResolver = () => 'android@pixel-8';
    expect(currentHostName(), 'android@pixel-8');
  });

  test('the platform default is either os@host or a single half', () {
    final stamp = platformHostName();
    expect(stamp, isNotNull);
    expect(stamp, isNot(startsWith('@')));
    expect(stamp, isNot(endsWith('@')));
    expect('@'.allMatches(stamp!).length, lessThanOrEqualTo(1));
  });
}
