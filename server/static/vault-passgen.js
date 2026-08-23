// The password generator: a length, four character sets, and a password.
//
// The browser port of `core/src/passgen.rs`, and like Smart Lock it is *not*
// part of the vault format — nothing it produces is written to a file, and no
// other implementation has to read it. It lives beside `vault-format.js` for
// that reason, and is held to the same contract — no DOM, no `fetch`, no
// globals, nothing persisted — so `scripts/vault-js-parity.mjs` can run the
// shipped file unchanged under Node.
//
// Nothing here needs golden vectors either: the output is random, so what the
// gate checks is the rules around it — the defaults, the clamp, the character
// sets, and the refusal when none of them is selected.

import { VaultError } from "./vault-format.js";

/** The clamp `PasswordGenConfig::set_length` applies. */
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 100;

/** The four sets `PasswordGenConfig::get_charset` concatenates, in its order
 *  and byte for byte. Nothing reads the order — a password is drawn uniformly
 *  from the union — but keeping it makes the two files diffable. */
export const CHARSETS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
};

/** `PasswordGenConfig::default`. */
export function defaultConfig() {
  return {
    length: 20,
    useUppercase: true,
    useLowercase: true,
    useNumbers: true,
    useSymbols: true,
  };
}

/** `PasswordGenConfig::set_length`'s clamp, on its own so the slider and the
 *  generator cannot disagree about the bounds. A value that is not a number at
 *  all reads as the minimum rather than producing a `NaN`-long password. */
export function clampLength(length) {
  const n = Math.trunc(Number(length));
  if (!Number.isFinite(n)) return MIN_LENGTH;
  return Math.min(Math.max(n, MIN_LENGTH), MAX_LENGTH);
}

/** `PasswordGenConfig::has_valid_options`. */
export function hasValidOptions(config) {
  return Boolean(
    config.useUppercase || config.useLowercase || config.useNumbers || config.useSymbols,
  );
}

/** The union of the selected sets, as an array of characters. */
export function charsetFor(config) {
  let charset = "";
  if (config.useLowercase) charset += CHARSETS.lowercase;
  if (config.useUppercase) charset += CHARSETS.uppercase;
  if (config.useNumbers) charset += CHARSETS.numbers;
  if (config.useSymbols) charset += CHARSETS.symbols;
  return [...charset];
}

/** `generate_password`: a password of `config.length` characters drawn
 *  uniformly from the selected sets.
 *
 *  Throws a `VaultError` carrying core's own sentence when nothing is
 *  selected, rather than returning an empty string — the caller has to say so
 *  to the visitor either way, and a thrown error cannot be mistaken for a
 *  password. */
export function generatePassword(config) {
  if (!hasValidOptions(config)) {
    throw new VaultError("At least one character type must be selected");
  }
  const charset = charsetFor(config);
  if (charset.length === 0) {
    throw new VaultError("No character set available");
  }

  const length = clampLength(config.length);
  let password = "";
  for (let i = 0; i < length; i += 1) {
    password += charset[randomIndex(charset.length)];
  }
  return password;
}

/** A uniform index into `0..bound`.
 *
 *  `rand`'s `random_range` is unbiased and this has to be too: `% bound` would
 *  favour the first `2^32 % bound` characters of the set, which for the
 *  92-character default is a small but real thumb on the scale of every
 *  password this page produces. So draw 32 fresh bits and reject anything at
 *  or above the largest multiple of `bound` that fits in them. */
function randomIndex(bound) {
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    if (buffer[0] < limit) return buffer[0] % bound;
  }
}
