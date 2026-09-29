/// "Is this password in a known breach?" — the Have I Been Pwned range check,
/// port of `core/src/pwned.rs`.
///
/// k-anonymity: only the first five hex characters of the secret's SHA-1 leave
/// the device (`GET /range/{prefix}`); the match against the returned suffixes
/// happens here. `Add-Padding` makes the server pad the list with count-0 rows
/// so the response size says nothing either. Nothing is cached.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:pointycastle/export.dart';

/// The public range endpoint; the prefix is appended.
const String pwnedRangeUrl = 'https://api.pwnedpasswords.com/range/';

const int _prefixLength = 5;

/// The SHA-1 of [secret] as uppercase hex, split into the five-character
/// prefix that is sent and the 35-character suffix that is looked for.
({String prefix, String suffix}) pwnedRangeQuery(String secret) {
  final digest =
      SHA1Digest().process(Uint8List.fromList(utf8.encode(secret)));
  final hex = digest
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join()
      .toUpperCase();
  return (
    prefix: hex.substring(0, _prefixLength),
    suffix: hex.substring(_prefixLength),
  );
}

/// How many breaches the range response lists for [suffix]; 0 when absent.
/// Padding rows carry a count of 0 and so read as absent.
int pwnedCountInRange(String body, String suffix) {
  final wanted = suffix.toUpperCase();
  for (final line in const LineSplitter().convert(body)) {
    final parts = line.trim().split(':');
    if (parts.length == 2 && parts[0].toUpperCase() == wanted) {
      return int.tryParse(parts[1].trim()) ?? 0;
    }
  }
  return 0;
}

class PwnedClient {
  PwnedClient(this._http);

  final http.Client _http;

  /// How many known breaches contain [secret]. Throws on a transport or
  /// server failure — never on "not found", which is 0.
  Future<int> breachCount(String secret) async {
    final query = pwnedRangeQuery(secret);
    final response = await _http
        .get(Uri.parse('$pwnedRangeUrl${query.prefix}'),
            headers: const {'Add-Padding': 'true'})
        .timeout(const Duration(seconds: 10));
    if (response.statusCode != 200) {
      throw http.ClientException(
          'range lookup answered ${response.statusCode}');
    }
    return pwnedCountInRange(response.body, query.suffix);
  }
}
