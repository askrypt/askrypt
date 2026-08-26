// The Askrypt vault format, in the browser.
//
// A port of `core/src/lib.rs` (the source of truth) and `core/src/types.rs`,
// following `app/lib/crypto/` function for function. `SPEC.md` is normative.
// Parity with the Rust core is asserted by `scripts/vault-js-parity.mjs`
// against the same golden vectors the Dart port uses.
//
// This module is deliberately pure: no DOM, no `fetch`, no globals of its own,
// nothing persisted. It is the only file in the site that touches
// `crypto.subtle`, and it is imported unchanged by the Node parity script, so
// it must not reach for `window` or `document`.
//
// Every primitive the format needs is native to the Web Cryptography API —
// PBKDF2-HMAC-SHA256, AES-256-CBC with PKCS#7, SHA-256 — which is why this is
// a few hundred lines of JavaScript rather than a wasm build of `core/`.

const VERSION = "0.9";
const ZIP_ENTRY = "askrypt.json";

/** The prefix every file-attachment ZIP member carries. The rest of the name is
 *  the attachment's id and nothing else, so the archive listing of a vault says
 *  how many files it holds but never what they are called. Mirrors
 *  `ATTACHMENT_PREFIX` in `core/src/lib.rs`. */
export const ATTACHMENT_PREFIX = "files/";

/** Ceiling on the *inflated* bytes of all attachments in one archive.
 *
 *  A bound on what a **crafted** file can make this page allocate, not a limit
 *  on what anyone may attach: this page inflates every member into memory to
 *  open a vault, so a hundred deflated members of zeros would be a zip bomb
 *  waiting to be handed to it.
 *
 *  It is a property of *this reader*, not of the format — `SPEC.md` says so —
 *  and the Rust core no longer has a counterpart: it streams members instead of
 *  inflating them, so there is nothing for a ceiling to bound. A tab has far
 *  less room than a desktop app anyway, and `MAX_VAULT_BYTES` below is the
 *  limit that actually bites here. */
const MAX_ATTACHMENT_BYTES = 256 * 1024 * 1024;
const DEFAULT_KDF = "pbkdf2";

/** The work factor a vault created here is born with, matching the
 *  `iterations.unwrap_or(600000)` in `AskryptFile::create` and
 *  `defaultIterations` in `app/lib/crypto/vault.dart`. A vault that already
 *  exists keeps its own, whatever it is. */
export const DEFAULT_ITERATIONS = 600_000;

/** Matches `crate::vaults::MAX_VAULT_BYTES` on the server. */
export const MAX_VAULT_BYTES = 10 * 1024 * 1024;
/** Matches `vaultfile::MAX_JSON_BYTES`: a bound on what a crafted archive can
 *  make us inflate. Real vaults are tens of KB. */
const MAX_JSON_BYTES = 1024 * 1024;
/** `params.iterations` is unauthenticated (see SPEC, "Integrity: not
 *  provided"), so a crafted file could otherwise park a phone in PBKDF2 for
 *  the rest of the afternoon. The production default is 600,000. */
const MAX_ITERATIONS = 5_000_000;

export class VaultError extends Error {
  constructor(message) {
    super(message);
    this.name = "VaultError";
  }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export function bytesFromBase64(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function base64FromBytes(bytes) {
  // Chunked so a large blob doesn't build one enormous intermediate string,
  // and never `String.fromCharCode(...bytes)`, which blows the argument limit.
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** Lowercase hex, matching Rust's `format!("{:x}", ...)`. */
export function hexFromBytes(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function decodeUtf8(bytes) {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    // Not valid UTF-8: for a decrypted blob this means the wrong key, which is
    // one of the three accidental consistency checks SPEC.md describes.
    throw new VaultError("decrypted data is not valid text");
  }
}

// ---------------------------------------------------------------------------
// Answer normalization — port of `normalize_answer` (core/src/lib.rs)
// ---------------------------------------------------------------------------

// The Unicode White_Space property, i.e. the set Rust's `char::is_whitespace`
// uses. Deliberately not the regex `\s`, which includes U+FEFF and omits
// U+0085 and so would normalize some answers differently from the Rust core.
function isWhitespace(cp) {
  switch (cp) {
    case 0x09: // tab
    case 0x0a: // LF
    case 0x0b: // VT
    case 0x0c: // FF
    case 0x0d: // CR
    case 0x20: // space
    case 0x85: // NEL
    case 0xa0: // NBSP
    case 0x1680: // Ogham space mark
    case 0x2028: // line separator
    case 0x2029: // paragraph separator
    case 0x202f: // narrow no-break space
    case 0x205f: // medium mathematical space
    case 0x3000: // ideographic space
      return true;
    default:
      return cp >= 0x2000 && cp <= 0x200a; // en quad .. hair space
  }
}

// '-' (hyphen-minus), '–' (en dash), '—' (em dash).
function isDash(cp) {
  return cp === 0x2d || cp === 0x2013 || cp === 0x2014;
}

/** Russian/Ukrainian to Latin, BGN/PCGN — port of `core/src/translit.rs`.
 *  Input is expected already lowercased; non-Cyrillic passes through. */
const TRANSLIT = new Map(Object.entries({
  // Russian
  а: "a", б: "b", в: "v", г: "g", д: "d", е: "e", ё: "yo", ж: "zh",
  з: "z", и: "i", й: "y", к: "k", л: "l", м: "m", н: "n", о: "o",
  п: "p", р: "r", с: "s", т: "t", у: "u", ф: "f", х: "kh", ц: "ts",
  ч: "ch", ш: "sh", щ: "shch", ъ: "", ы: "y", ь: "", э: "e", ю: "yu",
  я: "ya",
  // Ukrainian
  ґ: "g", є: "ye", і: "i", ї: "yi",
}));

export function transliterate(input) {
  let out = "";
  for (const ch of input) {
    const mapped = TRANSLIT.get(ch);
    out += mapped === undefined ? ch : mapped; // ъ/ь map to "" and are dropped
  }
  return out;
}

export function normalizeAnswer(answer, translit) {
  let stripped = "";
  for (const ch of answer) {
    const cp = ch.codePointAt(0);
    if (isWhitespace(cp) || isDash(cp)) continue;
    stripped += ch;
  }
  const lowered = stripped.toLowerCase();
  return translit ? transliterate(lowered) : lowered;
}

// ---------------------------------------------------------------------------
// Hashing, key derivation, AES — Web Crypto
// ---------------------------------------------------------------------------

/** `sha256(data + salt)` as a 64-character lowercase hex string.
 *
 *  Critical, and easy to get wrong: this hex *string* is what PBKDF2 takes as
 *  its secret, not the 32 raw digest bytes. `salt` is `params.salt` — the
 *  base64 *text* of salt0, not its bytes. */
export async function sha256Hex(data, salt) {
  const digest = await crypto.subtle.digest("SHA-256", utf8.encode(data + salt));
  return hexFromBytes(new Uint8Array(digest));
}

/** PBKDF2-HMAC-SHA256. `secret` is a string (hashed as its UTF-8 bytes),
 *  `salt` is raw bytes, and the result is 32 bytes — an AES-256 key. */
export async function pbkdf2(secret, salt, iterations, bits = 256) {
  const key = await crypto.subtle.importKey(
    "raw", utf8.encode(secret), "PBKDF2", false, ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, bits,
  );
  return new Uint8Array(derived);
}

// Web Crypto applies PKCS#7 itself for AES-CBC, both directions, so nothing
// here pads or strips by hand.
async function aesKey(raw, usage) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-CBC" }, false, [usage]);
}

export async function aesCbcDecrypt(ciphertext, key, iv) {
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv }, await aesKey(key, "decrypt"), ciphertext,
    );
    return new Uint8Array(plain);
  } catch {
    // Bad PKCS#7 padding. Almost always the wrong answer; possibly a file that
    // was altered, which this format cannot tell apart (SPEC, "Integrity").
    throw new VaultError("could not decrypt");
  }
}

export async function aesCbcEncrypt(plaintext, key, iv) {
  const out = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv }, await aesKey(key, "encrypt"), plaintext,
  );
  return new Uint8Array(out);
}

/** Cryptographically strong random bytes. Exported because `randomBytes` is a
 *  primitive of the same standing as [`pbkdf2`] and [`aesCbcEncrypt`], and
 *  `vault-smartlock.js` needs the salt and IVs its bundle carries. */
export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** A fresh master key — the port of `MasterSecret::generate`.
 *
 *  Minting deliberately lives *outside* [`createVault`], which keeps refusing
 *  to write without a key: a vault's master key is a property of the vault and
 *  not of a particular write (SPEC.md, "Master key lifetime"), so a save must
 *  never be able to mint one by accident. Calling this is what brings a vault
 *  into existence, and `vault-open.js` does it in exactly one place — the
 *  mirror of `RekeyInputs::run` being the desktop app's only mint. */
export function generateMasterKey() {
  return randomBytes(32);
}

// ---------------------------------------------------------------------------
// ZIP container — one member, `askrypt.json`
// ---------------------------------------------------------------------------

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;

/** Indexes a ZIP archive's central directory: name -> where and how to read it.
 *
 *  Split out of `readZipEntry` because a vault is no longer a one-member
 *  archive: attachments are members of their own, and the caller has to be able
 *  to *enumerate* them (their names are random ids, so it cannot guess them).
 *
 *  No ZIP64: `large_file` is off in every writer that produces a vault. */
export function readZipIndex(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // The end-of-central-directory record sits at the tail, after a comment of
  // at most 65535 bytes, so scan backwards for its signature.
  let eocd = -1;
  const floor = Math.max(0, bytes.length - (22 + 0xffff));
  for (let i = bytes.length - 22; i >= floor; i -= 1) {
    if (view.getUint32(i, true) === SIG_EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new VaultError("not a ZIP archive");

  const count = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  if (cdOffset === 0xffffffff || count === 0xffff) {
    throw new VaultError("ZIP64 archives are not supported");
  }

  const index = new Map();
  let at = cdOffset;
  for (let i = 0; i < count; i += 1) {
    if (at + 46 > bytes.length || view.getUint32(at, true) !== SIG_CENTRAL) {
      throw new VaultError("damaged ZIP central directory");
    }
    const method = view.getUint16(at + 10, true);
    const compressedSize = view.getUint32(at + 20, true);
    const uncompressedSize = view.getUint32(at + 24, true);
    const nameLen = view.getUint16(at + 28, true);
    const extraLen = view.getUint16(at + 30, true);
    const commentLen = view.getUint16(at + 32, true);
    const localOffset = view.getUint32(at + 42, true);
    const name = decodeUtf8(bytes.subarray(at + 46, at + 46 + nameLen));
    if (!index.has(name)) {
      index.set(name, { method, compressedSize, uncompressedSize, localOffset });
    }
    at += 46 + nameLen + extraLen + commentLen;
  }
  return index;
}

/** Reads one member out of an archive already indexed by `readZipIndex`.
 *
 *  `limit` is the caller's ceiling on the inflated size, and it is the caller's
 *  because the two kinds of member differ by three orders of magnitude: the
 *  vault JSON is tens of KB against `MAX_JSON_BYTES`, an attachment is whatever
 *  someone attached. Both are bounds on what a *crafted* archive can make this
 *  page allocate, not statements about the format.
 *
 *  Method 8 (deflate) is the common case: the Rust and Dart cores write every
 *  member that way and this module writes attachments that way. Method 0
 *  (stored) is handled too — this module stores `askrypt.json`, and a writer
 *  with no deflate implementation to hand may store an attachment. */
export async function readZipMember(bytes, index, name, limit = MAX_JSON_BYTES) {
  const entry = index.get(name);
  if (entry === undefined) throw new VaultError(`archive is missing ${name}`);
  if (entry.uncompressedSize > limit) {
    throw new VaultError(`${name} is implausibly large`);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const offset = entry.localOffset;
  if (offset + 30 > bytes.length || view.getUint32(offset, true) !== SIG_LOCAL) {
    throw new VaultError("damaged ZIP local header");
  }
  // The local header's name and extra lengths may differ from the central
  // directory's, so they are read again here rather than reused.
  const nameLen = view.getUint16(offset + 26, true);
  const extraLen = view.getUint16(offset + 28, true);
  const start = offset + 30 + nameLen + extraLen;
  const data = bytes.subarray(start, start + entry.compressedSize);

  const out = entry.method === 0
    ? data
    : entry.method === 8
      ? await inflateRaw(data)
      : null;
  if (out === null) {
    throw new VaultError(`unsupported ZIP compression (${entry.method})`);
  }
  return capped(out, name, limit);
}

/** Reads one named member out of a ZIP archive, indexing it first.
 *
 *  Kept for callers that want exactly one member and nothing else. */
export async function readZipEntry(bytes, name, limit = MAX_JSON_BYTES) {
  return readZipMember(bytes, readZipIndex(bytes), name, limit);
}

function capped(bytes, name, limit) {
  if (bytes.length > limit) {
    throw new VaultError(`${name} is implausibly large`);
  }
  return bytes;
}

/** Raw-deflate, the mirror of `inflateRaw`.
 *
 *  `CompressionStream` is native in every browser that has the
 *  `DecompressionStream` the reader already depends on, so writing deflated
 *  members costs no library, no CDN and no change to the page's CSP.
 *
 *  Answers `null` rather than throwing when the platform lacks it: the ZIP
 *  method is recorded per member, so a stored member is still a perfectly good
 *  archive that every implementation reads. Refusing to save at all would be a
 *  far worse outcome than saving a slightly larger file. */
async function deflateRaw(data) {
  if (typeof CompressionStream !== "function") return null;
  const stream = new Blob([data]).stream().pipeThrough(
    new CompressionStream("deflate-raw"),
  );
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function inflateRaw(data) {
  if (typeof DecompressionStream !== "function") {
    throw new VaultError("this browser cannot decompress ZIP archives");
  }
  const stream = new Blob([data]).stream().pipeThrough(
    new DecompressionStream("deflate-raw"),
  );
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

// CRC-32, the one thing a ZIP writer cannot get away without.
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Writes an archive from `[name, contents, deflate]` members.
 *
 *  `deflate` is per member because the two kinds differ: `askrypt.json` is tens
 *  of KB and is stored, while an attachment is deflated so that every writer of
 *  the format agrees on how a `files/` member is written. Deflating ciphertext
 *  buys no space — it cannot compress, and falls back to stored blocks costing
 *  a few bytes per 64 KB — so this is uniformity rather than economy.
 *
 *  Async because deflating is `CompressionStream`, which is a stream. When the
 *  platform has none, the member is written stored instead: the method is
 *  recorded per member, so the archive stays readable everywhere.
 *
 *  Two fields make this multi-member rather than one-member-repeated, and both
 *  are silent when wrong: the central directory's **relative offset of local
 *  header** (offset 42), which a single-member archive gets right by being
 *  zero, and the EOCD's counts and sizes, which are sums over the members. */
export async function writeZip(members, at = new Date()) {
  const { time, date } = dosTimestamp(at);
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const [name, contents, deflate = false] of members) {
    const nameBytes = utf8.encode(name);
    // Always over the *uncompressed* bytes, whichever method is used.
    const crc = crc32(contents);
    const packed = deflate ? await deflateRaw(contents) : null;
    const body = packed ?? contents;
    const method = packed ? 8 : 0;

    const local = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, SIG_LOCAL, true);
    lv.setUint16(4, 20, true); // version needed to extract: 2.0
    lv.setUint16(6, 0, true); // flags
    lv.setUint16(8, method, true);
    lv.setUint16(10, time, true);
    lv.setUint16(12, date, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, body.length, true); // compressed size
    lv.setUint32(22, contents.length, true); // uncompressed size
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true); // extra length
    local.set(nameBytes, 30);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, SIG_CENTRAL, true);
    cv.setUint16(4, 20, true); // version made by
    cv.setUint16(6, 20, true); // version needed
    cv.setUint16(8, 0, true);
    cv.setUint16(10, method, true);
    cv.setUint16(12, time, true);
    cv.setUint16(14, date, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, body.length, true);
    cv.setUint32(24, contents.length, true);
    cv.setUint16(28, nameBytes.length, true);
    // Where this member's local header starts. Zero is only right for the
    // first member; without this every later one reads as garbage.
    cv.setUint32(42, offset, true);
    central.set(nameBytes, 46);

    locals.push(local, body);
    centrals.push(central);
    offset += local.length + body.length;
  }

  const cdOffset = offset;
  const cdSize = centrals.reduce((n, c) => n + c.length, 0);

  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, SIG_EOCD, true);
  ev.setUint16(8, members.length, true); // entries on this disk
  ev.setUint16(10, members.length, true); // entries total
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, cdOffset, true);

  const out = new Uint8Array(cdOffset + cdSize + eocd.length);
  let cursor = 0;
  for (const chunk of locals) { out.set(chunk, cursor); cursor += chunk.length; }
  for (const chunk of centrals) { out.set(chunk, cursor); cursor += chunk.length; }
  out.set(eocd, cursor);
  return out;
}

/** Writes a single stored member. A thin wrapper over `writeZip`. */
export async function writeZipEntry(name, contents, at = new Date()) {
  return writeZip([[name, contents]], at);
}

function dosTimestamp(at) {
  // MS-DOS packed date/time, whose epoch is 1980. Anything earlier is clamped
  // rather than wrapped into a nonsense date.
  const year = Math.max(1980, at.getFullYear());
  return {
    time: (at.getHours() << 11) | (at.getMinutes() << 5) | (at.getSeconds() >> 1),
    date: ((year - 1980) << 9) | ((at.getMonth() + 1) << 5) | at.getDate(),
  };
}

// ---------------------------------------------------------------------------
// Entries — the shape `core/src/types.rs` serializes
// ---------------------------------------------------------------------------

/** The six card keys, as they appear in the JSON. There is no `card` object on
 *  the wire: `SecretEntry::card` is `#[serde(flatten)]`ed. They carry meaning
 *  only for entries whose `type` is `Card`, compared case-insensitively
 *  because the three clients spell types differently. */
export const CARD_KEYS = [
  "card_holder", "card_brand", "card_number",
  "card_expiry", "card_cvv", "card_pin",
];

export function isCard(entry) {
  return (entry.type || "").toLowerCase() === "card";
}

function text(value) {
  return typeof value === "string" ? value : "";
}

function entryFromJson(raw) {
  if (raw === null || typeof raw !== "object") {
    throw new VaultError("entry is not an object");
  }
  const entry = {
    name: text(raw.name),
    user_name: text(raw.user_name),
    secret: text(raw.secret),
    url: text(raw.url),
    notes: text(raw.notes),
    type: text(raw.type),
    tags: Array.isArray(raw.tags) ? raw.tags.filter((t) => typeof t === "string") : [],
    created: Number.isFinite(raw.created) ? raw.created : 0,
    modified: Number.isFinite(raw.modified) ? raw.modified : 0,
    hidden: raw.hidden === true,
  };
  for (const key of CARD_KEYS) entry[key] = text(raw[key]);
  entry.attachments = Array.isArray(raw.attachments)
    ? raw.attachments.map(attachmentFromJson).filter((a) => a.id !== "")
    : [];
  return entry;
}

/** One `attachments[]` element, normalized. Everything in here came out of a
 *  file anybody could have written, so nothing is trusted to be the right type
 *  — and an element with no id names no ZIP member, so it is dropped. */
function attachmentFromJson(raw) {
  if (raw === null || typeof raw !== "object") return { id: "" };
  return {
    id: text(raw.id),
    name: text(raw.name),
    size: Math.max(0, Math.trunc(Number(raw.size) || 0)),
    added: Math.trunc(Number(raw.added) || 0),
    iv: text(raw.iv),
  };
}

/** The inverse, matching serde exactly.
 *
 *  The first nine fields have no `#[serde(default)]` in `SecretEntry`, so the
 *  Rust core *requires* them and every one is always written; `hidden` always
 *  is too. The six card keys carry `skip_serializing_if = "String::is_empty"`,
 *  so an entry that is not a card must serialize exactly as it did before they
 *  existed — which is also why `version` can stay `"0.9"`. */
function entryToJson(entry) {
  const out = {
    name: text(entry.name),
    user_name: text(entry.user_name),
    secret: text(entry.secret),
    url: text(entry.url),
    notes: text(entry.notes),
    type: text(entry.type),
    tags: Array.isArray(entry.tags) ? entry.tags.slice() : [],
    // Unix seconds, as integers: serde reads these into `i64`, and a fractional
    // value would be rejected by the very build that has to open the file.
    created: Math.trunc(Number(entry.created) || 0),
    modified: Math.trunc(Number(entry.modified) || 0),
    hidden: entry.hidden === true,
  };
  for (const key of CARD_KEYS) {
    const value = text(entry[key]);
    if (value !== "") out[key] = value;
  }
  // Omitted when empty, like the card keys: an entry with no attachments must
  // serialize exactly as it did before they existed.
  if (Array.isArray(entry.attachments) && entry.attachments.length > 0) {
    out.attachments = entry.attachments.map((a) => ({
      id: text(a.id),
      name: text(a.name),
      size: Math.max(0, Math.trunc(Number(a.size) || 0)),
      added: Math.trunc(Number(a.added) || 0),
      iv: text(a.iv),
    }));
  }
  return out;
}

export function blankEntry() {
  const now = Math.floor(Date.now() / 1000);
  const entry = {
    name: "", user_name: "", secret: "", url: "", notes: "",
    type: "Login", tags: [], created: now, modified: now, hidden: false,
    attachments: [],
  };
  for (const key of CARD_KEYS) entry[key] = "";
  return entry;
}

// ---------------------------------------------------------------------------
// The vault file
// ---------------------------------------------------------------------------

/** Parses vault bytes into the unencrypted header plus the three blobs.
 *
 *  Everything this returns is readable without any answer: `question0` and
 *  `params` are stored in the clear, which is what lets the first unlock step
 *  render before a single derivation has run. */
export async function parseVault(bytes) {
  if (bytes.length > MAX_VAULT_BYTES) {
    throw new VaultError("that file is too large to be a vault");
  }
  const index = readZipIndex(bytes);
  const json = JSON.parse(decodeUtf8(await readZipMember(bytes, index, ZIP_ENTRY)));
  const params = json.params;
  if (params === null || typeof params !== "object") {
    throw new VaultError("vault is missing its parameters");
  }
  // Hard-rejected rather than best-effort: a silent downgrade would be worse
  // than a clear failure. See SPEC.md, "TODO: authenticated encryption".
  if (json.version !== VERSION) {
    throw new VaultError(`unsupported vault version: ${json.version}`);
  }
  const iterations = params.iterations;
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
    // `params` is unauthenticated, so this is a bound on what a crafted file
    // can make the browser spend, not a statement about the format.
    throw new VaultError("vault declares an unusable work factor");
  }
  return {
    version: json.version,
    question0: text(json.question0),
    // Kept verbatim and written back unchanged: `kdf` is read by no
    // decryption path in any implementation, `iterations` is this vault's own
    // work factor, and `translit` changes how answers normalize.
    kdf: text(params.kdf) || DEFAULT_KDF,
    iterations,
    salt0B64: text(params.salt),
    translit: params.translit === true,
    host: typeof params.host === "string" ? params.host : null,
    updatedAt: typeof params.updated_at === "string" ? params.updated_at : null,
    qs: text(json.qs),
    master: text(json.master),
    data: text(json.data),
    // Every `files/` member is an attachment's ciphertext, named by its id.
    // Read here because the entry list is still encrypted at this point, so the
    // names have to come off the archive rather than off the references. The
    // ceiling is the vault's own: a single attachment cannot be larger than the
    // file it lives in.
    attachments: await readAttachments(bytes, index),
  };
}

/** The `files/` members of an archive, as a `Map` of id -> ciphertext. */
async function readAttachments(bytes, index) {
  const blobs = new Map();
  let total = 0;
  for (const [name, entry] of index) {
    if (!name.startsWith(ATTACHMENT_PREFIX)) continue;
    const id = name.slice(ATTACHMENT_PREFIX.length);
    if (id === "") continue;
    // Checked against the declared size before inflating, so a bomb is refused
    // rather than expanded and then measured.
    total += entry.uncompressedSize;
    if (total > MAX_ATTACHMENT_BYTES) {
      throw new VaultError("vault attachments are implausibly large");
    }
    blobs.set(id, await readZipMember(bytes, index, name, MAX_ATTACHMENT_BYTES));
  }
  return blobs;
}

/** Layer 1: the first answer decrypts the remaining questions and salt1. */
export async function getQuestionsData(file, firstAnswer) {
  const salt0 = bytesFromBase64(file.salt0B64);
  const hashed = await sha256Hex(
    normalizeAnswer(firstAnswer, file.translit), file.salt0B64,
  );
  const firstKey = await pbkdf2(hashed, salt0, file.iterations);
  // salt0 doubles as this layer's IV.
  const plain = await aesCbcDecrypt(bytesFromBase64(file.qs), firstKey, salt0);
  const json = JSON.parse(decodeUtf8(plain));
  const questions = Array.isArray(json.questions) ? json.questions : null;
  if (!questions || typeof json.salt !== "string") {
    throw new VaultError("could not read the remaining questions");
  }
  return { questions, salt1B64: json.salt };
}

/** Layers 2 and 3: the remaining answers unwrap the master key, which decrypts
 *  the entries.
 *
 *  Hands the master key back, because anything that will save the vault again
 *  must feed that same key into `createVault`. It is minted once, when the
 *  vault is created, and preserved for the life of the vault — see SPEC.md,
 *  "Master key lifetime". Recovering it costs nothing: it falls out of the
 *  derivation that opens the vault anyway. */
export async function decryptWithMaster(file, questionsData, answers) {
  if (answers.length === 0) throw new VaultError("at least one answer is required");
  if (questionsData.questions.length !== answers.length) {
    throw new VaultError("questions/answers count mismatch");
  }
  const salt1 = bytesFromBase64(questionsData.salt1B64);
  // The answers from the second to the last, joined with no separator. Note
  // the SHA-256 salt is still salt0's base64 text, not salt1's.
  const combined = answers.map((a) => normalizeAnswer(a, file.translit)).join("");
  const secondKey = await pbkdf2(
    await sha256Hex(combined, file.salt0B64), salt1, file.iterations,
  );

  const masterJson = JSON.parse(decodeUtf8(
    await aesCbcDecrypt(bytesFromBase64(file.master), secondKey, salt1),
  ));
  if (typeof masterJson.masterKey !== "string" || typeof masterJson.iv !== "string") {
    throw new VaultError("could not read the master key");
  }
  const masterKey = bytesFromBase64(masterJson.masterKey);
  const iv = bytesFromBase64(masterJson.iv);
  if (masterKey.length !== 32) throw new VaultError("master key must be 32 bytes");

  const dataJson = JSON.parse(decodeUtf8(
    await aesCbcDecrypt(bytesFromBase64(file.data), masterKey, iv),
  ));
  if (!Array.isArray(dataJson)) throw new VaultError("vault data is not a list");
  return { entries: dataJson.map(entryFromJson), masterKey };
}

/** Rebuilds a vault file. Mirrors `AskryptFile::create` in `core/src/lib.rs`.
 *
 *  `masterKey` is **required** here, unlike in the Rust and Dart cores, whose
 *  `create` mints one when handed none: a brand-new vault gets its key from
 *  [`generateMasterKey`] before it ever reaches this function, so there is no
 *  mint-on-write branch here to get wrong. Everything encrypted under that key
 *  — the entry list and every file attachment — survives a write only
 *  because it is re-wrapped rather than rotated.
 *
 *  `attachments` is a `Map` of id -> ciphertext, as `parseVault` returns. It
 *  must be handed back on every save for the same reason `masterKey` must; the
 *  blobs no entry refers to are dropped here rather than written.
 *
 *  `salt0`, `salt1` and the data IV *are* drawn fresh every time, and the IV
 *  especially: AES-CBC under a repeated key and IV encrypts identical
 *  plaintext identically, so anyone holding two versions of a vault could read
 *  off how long a prefix of the entry list went unchanged. */
export async function createVault({
  questions, answers, entries, iterations, translit, kdf, masterKey,
  attachments = null,
  host = null, updatedAt = new Date(),
}) {
  if (questions.length < 2) throw new VaultError("at least 2 questions are required");
  if (questions.length !== answers.length) {
    throw new VaultError("questions/answers count mismatch");
  }
  if (questions.some((q) => utf8.encode(q).length > 500)) {
    throw new VaultError("a question may not exceed 500 bytes");
  }
  if (!(masterKey instanceof Uint8Array) || masterKey.length !== 32) {
    throw new VaultError("saving requires the vault's existing master key");
  }

  const normalized = answers.map((a) => normalizeAnswer(a, translit));
  const salt0 = randomBytes(16);
  const salt1 = randomBytes(16);
  const iv = randomBytes(16);
  const salt0B64 = base64FromBytes(salt0);

  // Layer 1: first answer -> first key -> the remaining questions.
  const firstKey = await pbkdf2(
    await sha256Hex(normalized[0], salt0B64), salt0, iterations,
  );
  const qs = base64FromBytes(await aesCbcEncrypt(
    jsonBytes({ questions: questions.slice(1), salt: base64FromBytes(salt1) }),
    firstKey, salt0,
  ));

  // Layer 2: the remaining answers -> second key -> the master key and IV.
  const secondKey = await pbkdf2(
    await sha256Hex(normalized.slice(1).join(""), salt0B64), salt1, iterations,
  );
  const master = base64FromBytes(await aesCbcEncrypt(
    jsonBytes({ masterKey: base64FromBytes(masterKey), iv: base64FromBytes(iv) }),
    secondKey, salt1,
  ));

  // Layer 3: the master key -> the entries.
  const data = base64FromBytes(await aesCbcEncrypt(
    jsonBytes(entries.map(entryToJson)), masterKey, iv,
  ));

  const params = { kdf, iterations, salt: salt0B64, translit };
  // Omitted rather than blanked when unknown, so a pre-stamp vault round-trips
  // unchanged and no reader is handed a placeholder to believe.
  if (host) params.host = host;
  params.updated_at = formatUtcStamp(updatedAt);

  const json = { version: VERSION, question0: questions[0], params, qs, master, data };

  // Carry the attachment blobs across, less any the entries being written no
  // longer refer to. `SPEC.md` makes that a rule rather than an optimization:
  // deleting an attachment has to actually shrink the vault. Sorted by id so
  // two saves of an unchanged vault do not differ for no reason.
  const referenced = new Set(
    entries.flatMap((e) => (e.attachments ?? []).map((a) => a.id)),
  );
  const members = [[ZIP_ENTRY, jsonBytes(json)]];
  for (const id of [...(attachments?.keys() ?? [])].sort()) {
    // Deflated, like every other writer of the format writes a `files/` member.
    if (referenced.has(id)) {
      members.push([ATTACHMENT_PREFIX + id, attachments.get(id), true]);
    }
  }
  return writeZip(members, updatedAt);
}

/** Encrypt one file's bytes as a vault attachment, minting its id and IV.
 *  Mirrors `seal_attachment` in `core/src/lib.rs`.
 *
 *  The id is 16 random bytes as 32 hex characters and is the whole of the ZIP
 *  member's name, so the archive listing never says what the file is called.
 *  The IV is drawn fresh every time: reusing one under a key that never
 *  rotates would let anyone holding two versions of a vault read off how much
 *  of an attachment went unchanged.
 *
 *  The returned metadata carries an empty `name` — this function deals in
 *  bytes and has no opinion about what the file is called. */
export async function sealAttachment(plaintext, masterKey) {
  const iv = randomBytes(16);
  return {
    attachment: {
      id: hexFromBytes(randomBytes(16)),
      name: "",
      size: plaintext.length,
      added: Math.floor(Date.now() / 1000),
      iv: base64FromBytes(iv),
    },
    ciphertext: await aesCbcEncrypt(plaintext, masterKey, iv),
  };
}

/** Decrypt one attachment's bytes. Mirrors `open_attachment` in
 *  `core/src/lib.rs`.
 *
 *  `attachment.size` is deliberately not checked against the result: the format
 *  offers no integrity (SPEC.md, "Integrity: not provided"), so a mismatch
 *  would be a hint rather than a verdict. */
export async function openAttachment(ciphertext, attachment, masterKey) {
  const iv = bytesFromBase64(attachment.iv);
  if (iv.length !== 16) throw new VaultError("invalid attachment IV");
  return aesCbcDecrypt(ciphertext, masterKey, iv);
}

/** The master key the next write of this vault must use — the port of
 *  `master_for_write` in `core/src/lib.rs`, and SPEC.md, "Master key
 *  lifetime".
 *
 *  A vault holding **no attachments** is written under a fresh key every time:
 *  only the entry list lives under the key, and that is re-encrypted from
 *  plaintext on every save anyway, so rotating costs one random draw and means
 *  a key recovered from one version does not open the next.
 *
 *  A vault holding **at least one attachment** keeps `current`. Its blobs are
 *  sealed under that key and are carried across a save untouched; minting a new
 *  one would mean re-encrypting every attached file on every save.
 *
 *  `current` may be null for a vault that has never been written — there is
 *  nothing to decide, and it gets a key of its own.
 *
 *  The entries decide it rather than the blob map, and the test is "does any
 *  entry refer to a file": a blob no entry refers to is pruned by
 *  `createVault`, so a vault whose last reference was just removed rotates on
 *  the save that drops it. A dangling reference counts as an attachment and
 *  keeps the key — the conservative way round, since keeping a key can never
 *  make a file unreadable and minting one can. */
export function masterForWrite(entries, current) {
  if (!current) return generateMasterKey();
  const holdsFiles = entries.some((e) => (e.attachments ?? []).length > 0);
  return holdsFiles ? current : generateMasterKey();
}

function jsonBytes(value) {
  return utf8.encode(JSON.stringify(value));
}

/** RFC 3339 UTC with second precision — the `params.updated_at` shape
 *  `AskryptFile::touch` writes. */
export function formatUtcStamp(at) {
  return `${at.toISOString().slice(0, 19)}Z`;
}
