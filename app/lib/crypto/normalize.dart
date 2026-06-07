/// Answer normalization — port of `normalize_answer` in `core/src/lib.rs`.
///
/// Removes all Unicode whitespace and every dash variant, lowercases, then
/// optionally transliterates. Must match Rust byte-for-byte.
library;

import 'translit.dart';

// Unicode White_Space property — the set Rust's `char::is_whitespace` uses.
bool _isWhitespace(int cp) {
  switch (cp) {
    case 0x09: // tab
    case 0x0A: // LF
    case 0x0B: // VT
    case 0x0C: // FF
    case 0x0D: // CR
    case 0x20: // space
    case 0x85: // NEL
    case 0xA0: // NBSP
    case 0x1680: // Ogham space mark
    case 0x2028: // line separator
    case 0x2029: // paragraph separator
    case 0x202F: // narrow no-break space
    case 0x205F: // medium mathematical space
    case 0x3000: // ideographic space
      return true;
    default:
      return cp >= 0x2000 && cp <= 0x200A; // en quad .. hair space
  }
}

// '-' (hyphen-minus), '–' (en dash), '—' (em dash).
bool _isDash(int cp) => cp == 0x2D || cp == 0x2013 || cp == 0x2014;

String normalizeAnswer(String answer, bool translit) {
  final sb = StringBuffer();
  for (final cp in answer.runes) {
    if (_isWhitespace(cp) || _isDash(cp)) continue;
    sb.writeCharCode(cp);
  }
  final lowered = sb.toString().toLowerCase();
  return translit ? transliterate(lowered) : lowered;
}
