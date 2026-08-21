// Smart Lock: every answer held re-encrypted under one of themselves.
//
// The browser port of `src/smartlock.rs`, and like that module it is *not*
// part of the vault format — nothing here is ever written to a file, and no
// other implementation has to read it. It is a shallower lock than a full one:
// the entries and the master key are dropped, and what is left is the answer
// set encrypted under one of its own members, so one answer re-opens the vault
// instead of all of them.
//
// It lives beside `vault-format.js` rather than inside it for the reason the
// desktop keeps `smartlock.rs` out of `core/`: the format is what three
// implementations must agree on byte for byte, and this is not that. It is
// nonetheless held to the same contract — no DOM, no `fetch`, no globals,
// nothing persisted — so `scripts/vault-js-parity.mjs` can run the shipped
// file unchanged under Node.
//
// Nothing here needs golden vectors: the derivation is the format's own first
// layer with a different work factor (`sha256Hex` -> `pbkdf2` -> AES-256-CBC),
// and every one of those primitives is already pinned against `core/` by the
// vectors. What the gate checks is the shape around them.

import {
  VaultError, aesCbcDecrypt, aesCbcEncrypt, base64FromBytes, normalizeAnswer,
  pbkdf2, randomBytes, sha256Hex,
} from "./vault-format.js";

/** Iterations for the Smart Lock key.
 *
 *  Deliberately far above the vault's own work factor, exactly as in
 *  `src/smartlock.rs`: this key comes from a *single* answer, so there is less
 *  entropy behind it than behind the layered unlock. */
export const SMART_LOCK_ITERATIONS = 2_000_000;

/** How long an armed Smart Lock lasts before it drops to a full lock, matching
 *  `SMART_LOCK_TIMEOUT`. */
export const SMART_LOCK_TIMEOUT_MS = 8 * 60 * 60 * 1000;

/** Arms Smart Lock: encrypts every answer under one of them, chosen at random
 *  and never the first.
 *
 *  `answers` holds the answers to questions 2.., aligned with `questions`;
 *  `answer0` is separate because the format treats it separately. The returned
 *  bundle is ciphertext, salt and IVs and nothing else — no plaintext answer,
 *  and no master key: recovering the vault still means re-deriving it from the
 *  encrypted file, which is what keeps the bundle alone worth nothing. */
export async function createSmartLock({ answer0, answers, questions, translit }) {
  if (answers.length === 0) {
    throw new VaultError("Smart Lock needs at least two questions.");
  }

  // 1..=answers.length, so `answers[keyAnswerIndex - 1]` is answer 2 onwards.
  const keyAnswerIndex = randomIndex(answers.length);
  const keyAnswer = answers[keyAnswerIndex - 1] ?? "";
  if (keyAnswer === "") throw new VaultError("The chosen answer is empty.");
  const keyQuestion = questions[keyAnswerIndex - 1] || `Question ${keyAnswerIndex + 1}`;

  const salt = randomBytes(16);
  // One IV per ciphertext. They share a key, and AES-CBC under one key *and*
  // one IV encrypts equal leading blocks equally — with a single IV this blob
  // would tell a reader how far the two plaintexts agree.
  const ivAnswer0 = randomBytes(16);
  const ivAnswers = randomBytes(16);

  const key = await smartKey(keyAnswer, salt, translit);
  const encryptedAnswer0 = await aesCbcEncrypt(utf8.encode(answer0), key, ivAnswer0);
  // Every remaining answer, the key answer among them — the unlock knows which
  // one it was from the salt and IVs, not from the plaintext.
  const encryptedAnswers = await aesCbcEncrypt(
    utf8.encode(JSON.stringify(answers)), key, ivAnswers,
  );

  return {
    // Retained for the same reason the Rust struct retains it: diagnostics.
    // Decryption keys off the stored salt and IVs, never off this.
    keyAnswerIndex,
    keyQuestion,
    encryptedAnswer0,
    encryptedAnswers,
    salt,
    ivAnswer0,
    ivAnswers,
    armedAt: Date.now(),
  };
}

/** Recovers the answers from a bundle. Returns `{answer0, answers}` in the
 *  shape [`createSmartLock`] was handed them.
 *
 *  A wrong answer is not reported as such — it simply fails to decrypt,
 *  exactly like the layered unlock, and for the same reason: this format has
 *  no integrity check to tell a wrong key from an altered blob. */
export async function recoverSmartLock(bundle, answer, translit) {
  const key = await smartKey(answer, bundle.salt, translit);
  const answer0 = decodeUtf8(
    await aesCbcDecrypt(bundle.encryptedAnswer0, key, bundle.ivAnswer0),
  );
  const answers = JSON.parse(decodeUtf8(
    await aesCbcDecrypt(bundle.encryptedAnswers, key, bundle.ivAnswers),
  ));
  if (!Array.isArray(answers) || answers.some((a) => typeof a !== "string")) {
    throw new VaultError("could not read the stored answers");
  }
  return { answer0, answers };
}

/** How long an armed bundle has left, in milliseconds; never below zero. */
export function smartLockRemaining(bundle) {
  return Math.max(0, bundle.armedAt + SMART_LOCK_TIMEOUT_MS - Date.now());
}

// ---------------------------------------------------------------------------

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

function decodeUtf8(bytes) {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    // Padding that happened to strip cleanly under the wrong key. Same cause
    // as a decryption failure, so the same sentence.
    throw new VaultError("could not decrypt");
  }
}

/** The one derivation this module does, shared by both directions so they
 *  cannot drift: the format's own answer key, at the Smart Lock work factor. */
async function smartKey(answer, salt, translit) {
  const saltB64 = base64FromBytes(salt);
  const hashed = await sha256Hex(normalizeAnswer(answer, translit), saltB64);
  return pbkdf2(hashed, salt, SMART_LOCK_ITERATIONS);
}

/** A uniform integer in 1..=count, the port of `rng.random_range(1..=len)`.
 *
 *  Rejection sampling rather than a modulo: the bias is tiny at these sizes,
 *  but which answer a bundle keys on is the one thing an attacker would like
 *  to guess, and an unbiased draw costs three lines. */
function randomIndex(count) {
  const limit = Math.floor(0x1_0000_0000 / count) * count;
  const scratch = new Uint32Array(1);
  let draw;
  do {
    crypto.getRandomValues(scratch);
    draw = scratch[0];
  } while (draw >= limit);
  return (draw % count) + 1;
}
