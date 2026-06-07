/// Russian/Ukrainian -> Latin (QWERTY-compatible) transliteration, BGN/PCGN.
///
/// Direct port of `core/src/translit.rs`. Input is expected to be lowercase
/// (normalization lowercases before calling this). Must stay byte-identical to
/// the Rust implementation — verified by the parity test against committed
/// golden vectors.
library;

const Map<String, String> _map = {
  // Russian
  'а': 'a',
  'б': 'b',
  'в': 'v',
  'г': 'g',
  'д': 'd',
  'е': 'e',
  'ё': 'yo',
  'ж': 'zh',
  'з': 'z',
  'и': 'i',
  'й': 'y',
  'к': 'k',
  'л': 'l',
  'м': 'm',
  'н': 'n',
  'о': 'o',
  'п': 'p',
  'р': 'r',
  'с': 's',
  'т': 't',
  'у': 'u',
  'ф': 'f',
  'х': 'kh',
  'ц': 'ts',
  'ч': 'ch',
  'ш': 'sh',
  'щ': 'shch',
  'ъ': '',
  'ь': '',
  'ы': 'y',
  'э': 'e',
  'ю': 'yu',
  'я': 'ya',
  // Ukrainian
  'ґ': 'g',
  'є': 'ye',
  'і': 'i',
  'ї': 'yi',
};

String transliterate(String input) {
  final sb = StringBuffer();
  for (final rune in input.runes) {
    final ch = String.fromCharCode(rune);
    final mapped = _map[ch];
    if (mapped != null) {
      sb.write(mapped); // includes ъ/ь -> "" (dropped)
    } else {
      sb.write(ch); // passthrough for non-Cyrillic
    }
  }
  return sb.toString();
}
