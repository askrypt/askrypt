#!/usr/bin/env node
// Byte-parity gate for the browser crypto (`server/static/vault-format.js`)
// against the Rust core, using the same golden vectors the Dart port uses.
//
//   node scripts/vault-js-parity.mjs
//
// Zero npm dependencies: Node's built-in WebCrypto and DecompressionStream are
// the same APIs the browser gives the page, so this exercises the shipped file
// unchanged rather than a copy of it. Regenerate the vectors after any change
// to the format or to normalization:
//
//   cargo run -p askrypt-core --example gen_vectors
//
// Deliberately not wired into CI, for the reason `server/PLAN.md` gives: there
// is no Node, npm or bundler anywhere in the build. Run it by hand alongside
// `cd app && flutter test`, which is not in CI either.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vault = await import(join(root, "server/static/vault-format.js"));
const smartlock = await import(join(root, "server/static/vault-smartlock.js"));
const passgen = await import(join(root, "server/static/vault-passgen.js"));

const vectors = JSON.parse(
  await readFile(join(root, "app/test/fixtures/vectors.json"), "utf8"),
);

let checked = 0;
let failed = 0;

// Key order is not part of the format — `serde_json` writes object keys
// alphabetically and JavaScript writes them in insertion order — so compare
// canonically rather than asserting on `JSON.stringify` directly.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function check(label, actual, expected) {
  checked += 1;
  const a = canonical(actual);
  const e = canonical(expected);
  if (a === e) return true;
  failed += 1;
  console.error(`FAIL  ${label}\n        expected ${e}\n        actual   ${a}`);
  return false;
}

function group(name, fn) {
  const before = failed;
  const countedBefore = checked;
  return Promise.resolve(fn()).then((value) => {
    // A group that checked nothing is a group that silently did not run, which
    // is worse than one that failed: it prints `ok` either way. This caught the
    // round-trip group being skipped for want of the return value below.
    if (checked === countedBefore) {
      failed += 1;
      console.error(`FAIL  ${name}\n        the group ran no checks at all`);
    }
    const mark = failed === before ? "ok  " : "FAIL";
    console.log(`${mark}  ${name}`);
    // Forwarded, so a group can hand its result to the next one. Without this
    // every `const x = await group(...)` is `undefined`.
    return value;
  });
}

// --- the format version the vectors were generated for --------------------

await group("format version", () => {
  check("format_version", vectors.format_version, "0.9");
});

// --- pure string stages ----------------------------------------------------

await group("normalize", () => {
  for (const c of vectors.normalize) {
    check(
      `normalize(${JSON.stringify(c.input)}, translit=${c.translit})`,
      vault.normalizeAnswer(c.input, c.translit),
      c.expected,
    );
  }
});

await group("transliterate", () => {
  for (const c of vectors.transliterate) {
    check(`transliterate(${JSON.stringify(c.input)})`,
      vault.transliterate(c.input), c.expected);
  }
});

await group("sha256(data + salt) as hex", async () => {
  for (const c of vectors.sha256) {
    check(
      `sha256(${JSON.stringify(c.data)}, ${JSON.stringify(c.salt)})`,
      await vault.sha256Hex(c.data, c.salt),
      c.expected_hex,
    );
  }
});

// --- key derivation --------------------------------------------------------

await group("pbkdf2-hmac-sha256", async () => {
  for (const c of vectors.pbkdf2) {
    const key = await vault.pbkdf2(
      c.secret, vault.bytesFromBase64(c.salt_b64), c.iterations,
    );
    check(
      `pbkdf2(${JSON.stringify(c.secret)}, ${c.iterations} iterations)`,
      vault.hexFromBytes(key),
      c.key_hex,
    );
  }
});

// --- AES-256-CBC + PKCS#7, both directions ---------------------------------

await group("aes-256-cbc + pkcs7", async () => {
  for (const c of vectors.aes_cbc_pkcs7) {
    const key = vault.bytesFromBase64(c.key_b64);
    const iv = vault.bytesFromBase64(c.iv_b64);
    const plaintext = vault.bytesFromBase64(c.plaintext_b64);

    check(
      `encrypt(${c.plaintext_b64 || "<empty>"})`,
      vault.base64FromBytes(await vault.aesCbcEncrypt(plaintext, key, iv)),
      c.ciphertext_b64,
    );
    check(
      `decrypt(${c.ciphertext_b64})`,
      vault.base64FromBytes(
        await vault.aesCbcDecrypt(vault.bytesFromBase64(c.ciphertext_b64), key, iv),
      ),
      c.plaintext_b64,
    );
  }
});

// --- the whole format: open the known-good vault ---------------------------

const golden = vectors.vault;
const goldenBytes = vault.bytesFromBase64(golden.vault_b64);

const opened = await group("open the golden vault", async () => {
  const file = await vault.parseVault(goldenBytes);

  check("question0", file.question0, golden.questions[0]);
  check("iterations", file.iterations, golden.iterations);
  check("translit", file.translit, golden.translit);
  // The write stamp is unencrypted, so it reads without any answer at all.
  check("params.host", file.host, golden.expected_host);
  check("params.updated_at", file.updatedAt, golden.expected_updated_at);

  const qd = await vault.getQuestionsData(file, golden.answers[0]);
  check("remaining questions", qd.questions, golden.questions.slice(1));

  const { entries, masterKey } = await vault.decryptWithMaster(
    file, qd, golden.answers.slice(1),
  );
  check("master key length", masterKey.length, 32);
  check("entries", entries.map(serialized), golden.expected_entries);

  // The attachment: not merely carried, but decrypted. The blob is a ZIP member
  // of its own, so this is the one check that pins the multi-member reader.
  const blob = file.attachments.get(golden.expected_attachment_id);
  check("attachment blob is present", blob !== undefined, true);
  if (blob) {
    const meta = entries.at(-1).attachments[0];
    const plaintext = await vault.openAttachment(blob, meta, masterKey);
    check(
      "attachment decrypts under the master key",
      new TextDecoder().decode(plaintext),
      golden.expected_attachment_plaintext,
    );
    check("attachment size matches its metadata", plaintext.length, meta.size);
    // The random id is the whole of the member's name, so a vault handed to
    // someone else says how many files it holds but never what they are called.
    check(
      "the file name is not in the archive listing",
      [...vault.readZipIndex(goldenBytes).keys()].some((n) => n.includes("passport.txt")),
      false,
    );
  }
  return { file, entries, masterKey };
});

// --- and write one back ----------------------------------------------------
//
// The reader alone cannot catch a broken writer, and a broken writer is the
// failure that costs someone their vault. Re-save the golden entries under the
// *recovered* master key, then reopen the result: that pins the ZIP writer,
// the entry serialization, and — because the key is compared afterwards — the
// preservation rule in SPEC.md's "Master key lifetime".

await group("save and reopen (round trip)", async () => {
  if (!opened) return;
  const { file, entries, masterKey } = opened;

  const rewritten = await vault.createVault({
    questions: golden.questions,
    answers: golden.answers,
    entries,
    iterations: file.iterations,
    translit: file.translit,
    kdf: file.kdf,
    masterKey,
    attachments: file.attachments,
    host: "parity@web",
    updatedAt: new Date("2026-03-04T05:06:07Z"),
  });

  const reread = await vault.parseVault(rewritten);
  check("re-read host", reread.host, "parity@web");
  check("re-read updated_at", reread.updatedAt, "2026-03-04T05:06:07Z");
  check("re-read kdf", reread.kdf, file.kdf);
  check("re-read iterations", reread.iterations, file.iterations);
  // Fresh salts and IV on every write, or two versions of a vault would leak
  // how long a prefix of the entry list went unchanged.
  check("salt0 was regenerated", reread.salt0B64 !== file.salt0B64, true);

  const qd = await vault.getQuestionsData(reread, golden.answers[0]);
  const reopened = await vault.decryptWithMaster(reread, qd, golden.answers.slice(1));
  check("round-tripped entries", reopened.entries.map(serialized), golden.expected_entries);
  check(
    "master key was preserved, not rotated",
    vault.hexFromBytes(reopened.masterKey),
    vault.hexFromBytes(masterKey),
  );

  // The writer's multi-member half. `writeZip` has to set each member's
  // relative local-header offset, a field a one-member archive gets right by
  // being zero — so a vault with an attachment is the only thing that catches
  // it, and the failure is silent.
  //
  // Attachments are written deflated, like the Rust and Dart cores write every
  // member, so this also pins `CompressionStream` producing something the
  // reader's `DecompressionStream` takes back.
  check(
    "the attachment was written deflated",
    vault.readZipIndex(rewritten).get(`files/${golden.expected_attachment_id}`)?.method,
    8,
  );
  const carried = reread.attachments.get(golden.expected_attachment_id);
  check("attachment survived the round trip", carried !== undefined, true);
  if (carried) {
    const meta = reopened.entries.at(-1).attachments[0];
    check(
      "round-tripped attachment still decrypts",
      new TextDecoder().decode(await vault.openAttachment(carried, meta, reopened.masterKey)),
      golden.expected_attachment_plaintext,
    );
  }

  // A writer must not emit a blob no entry refers to: deleting an attachment
  // has to actually shrink the vault (SPEC.md, "File attachments").
  const stripped = entries.map((e) => ({ ...e, attachments: [] }));
  const pruned = await vault.parseVault(await vault.createVault({
    questions: golden.questions,
    answers: golden.answers,
    entries: stripped,
    iterations: file.iterations,
    translit: file.translit,
    kdf: file.kdf,
    masterKey,
    attachments: file.attachments,
  }));
  check("an unreferenced blob is dropped on write", pruned.attachments.size, 0);
});

// --- Which key the next write uses -----------------------------------------
//
// SPEC.md, "Master key lifetime": a vault with no attachments is written under
// a fresh key every time, one holding a file keeps the key its blobs are
// sealed under. `createVault` still re-wraps whatever key it is handed — the
// group above pins that — so what this checks is the decision the callers make
// first, and the edges `core/src/lib.rs` states as rules.

await group("the write key depends on whether a file is attached", async () => {
  if (!opened) return;
  const { entries, masterKey } = opened;

  // The golden vault's last entry is the one carrying the attachment.
  const withFile = entries.at(-1);
  check(
    "the fixture entry really does carry one",
    (withFile.attachments ?? []).length,
    1,
  );
  check(
    "a vault holding a file keeps its key",
    vault.hexFromBytes(vault.masterForWrite([withFile], masterKey)),
    vault.hexFromBytes(masterKey),
  );

  const plain = entries.filter((e) => (e.attachments ?? []).length === 0);
  check("the fixture has attachment-free entries too", plain.length > 0, true);
  const first = vault.masterForWrite(plain, masterKey);
  check(
    "a vault with no files is written under a new key",
    vault.hexFromBytes(first) !== vault.hexFromBytes(masterKey),
    true,
  );
  check("and the new key is 32 bytes", first.length, 32);
  // Per write, not once: two calls must not agree either.
  check(
    "every write mints its own",
    vault.hexFromBytes(vault.masterForWrite(plain, masterKey))
      !== vault.hexFromBytes(first),
    true,
  );

  // Dropping the last reference is what lets the next write rotate — the blob
  // is pruned by that same write.
  const stripped = entries.map((e) => ({ ...e, attachments: [] }));
  check(
    "dropping the last reference lets the next write rotate",
    vault.hexFromBytes(vault.masterForWrite(stripped, masterKey))
      !== vault.hexFromBytes(masterKey),
    true,
  );

  // A vault that has never been written gets a key of its own.
  check("an unwritten vault is a plain mint", vault.masterForWrite([], null).length, 32);
});

// --- Smart Lock ------------------------------------------------------------
//
// Not part of the format — nothing here is ever written to a file, and no
// other implementation reads it — so there are no golden vectors to compare
// against, and none are needed: the derivation is the format's own answer key
// at a different work factor, and every primitive under it is already pinned
// above. What this checks is the shape `src/smartlock.rs` gives the bundle.
//
// Three 2,000,000-iteration derivations, so this group is the slow one.

await group("Smart Lock arms and re-opens under one answer", async () => {
  const answers = golden.answers;
  const bundle = await smartlock.createSmartLock({
    answer0: answers[0],
    answers: answers.slice(1),
    questions: golden.questions.slice(1),
    translit: golden.translit,
  });

  // Never the first answer: that one is the layer the whole scheme rests on,
  // and keying the bundle on it would put the questions and the answers behind
  // the same secret.
  check(
    "the key answer is never the first one",
    bundle.keyAnswerIndex >= 1 && bundle.keyAnswerIndex <= answers.length - 1,
    true,
  );
  check(
    "key question is the one that answer belongs to",
    bundle.keyQuestion,
    golden.questions[bundle.keyAnswerIndex],
  );
  // Two ciphertexts sharing a key must not share an IV.
  check(
    "each ciphertext has its own IV",
    vault.hexFromBytes(bundle.ivAnswer0) !== vault.hexFromBytes(bundle.ivAnswers),
    true,
  );
  // Nothing in the bundle is plaintext, and no master key is in it at all:
  // recovering the vault still means the ordinary layered unlock.
  check("bundle holds no master key", "masterKey" in bundle, false);
  const blob = Buffer.from([
    ...bundle.encryptedAnswer0, ...bundle.encryptedAnswers,
    ...bundle.salt, ...bundle.ivAnswer0, ...bundle.ivAnswers,
  ]);
  check(
    "no answer appears in the clear",
    // Short answers are left out: a byte or two turning up inside ciphertext
    // is coincidence, and would make this flaky rather than strict.
    answers.filter((a) => a.length >= 4)
      .some((a) => blob.includes(Buffer.from(a, "utf8"))),
    false,
  );

  // The key answer, typed with different spacing and capitals: normalization
  // is the format's, so it opens the bundle all the same.
  const typed = ` ${golden.answers[bundle.keyAnswerIndex].toUpperCase()} `;
  const recovered = await smartlock.recoverSmartLock(bundle, typed, golden.translit);
  check("answer0 recovered", recovered.answer0, answers[0]);
  check("remaining answers recovered", recovered.answers, answers.slice(1));

  let refused = false;
  try {
    await smartlock.recoverSmartLock(bundle, "not the answer", golden.translit);
  } catch {
    refused = true;
  }
  check("any other answer is refused", refused, true);

  const left = smartlock.smartLockRemaining(bundle);
  check(
    "the eight-hour ceiling is running",
    left > 0 && left <= smartlock.SMART_LOCK_TIMEOUT_MS,
    true,
  );
});

// --- The password generator ------------------------------------------------
//
// Not part of the format either, and its output is random, so there is nothing
// to compare byte for byte. What this checks is the rules `core/src/passgen.rs`
// states: the defaults, the clamp, the character sets, and the refusal.

await group("the password generator follows core/src/passgen.rs", () => {
  const config = passgen.defaultConfig();
  check("default length", config.length, 20);
  check(
    "every set on by default",
    [config.useUppercase, config.useLowercase, config.useNumbers, config.useSymbols],
    [true, true, true, true],
  );
  check("MIN_LENGTH", passgen.MIN_LENGTH, 8);
  check("MAX_LENGTH", passgen.MAX_LENGTH, 100);
  // `PasswordGenConfig::set_length` clamps rather than refusing.
  check("length clamps up", passgen.clampLength(5), 8);
  check("length clamps down", passgen.clampLength(150), 100);
  check("length in range is kept", passgen.clampLength(37), 37);

  check("default charset size", passgen.charsetFor(config).length, 26 + 26 + 10 + 26);
  check("requested length is honoured",
    passgen.generatePassword({ ...config, length: 64 }).length, 64);

  // Each set on its own: a password may only contain what was asked for.
  for (const [set, chars] of Object.entries(passgen.CHARSETS)) {
    const only = {
      length: 100,
      useUppercase: set === "uppercase",
      useLowercase: set === "lowercase",
      useNumbers: set === "numbers",
      useSymbols: set === "symbols",
    };
    const password = passgen.generatePassword(only);
    check(
      `${set} only draws from its own set`,
      [...password].every((c) => chars.includes(c)),
      true,
    );
  }

  let refused = false;
  try {
    passgen.generatePassword({
      length: 20,
      useUppercase: false,
      useLowercase: false,
      useNumbers: false,
      useSymbols: false,
    });
  } catch (err) {
    refused = err instanceof vault.VaultError;
  }
  check("no character type selected is refused", refused, true);
});

// The entry as the Rust core serializes it: the six card keys and `attachments`
// are omitted when empty, so a non-card entry with no files must compare equal
// to one written before either existed.
//
// **Every new per-entry key has to be added here.** This function is a
// whitelist, so one that is missing is invisible to the gate — a port that
// dropped it would pass while quietly deleting data on every save.
function serialized(entry) {
  const out = {
    name: entry.name,
    user_name: entry.user_name,
    secret: entry.secret,
    url: entry.url,
    notes: entry.notes,
    type: entry.type,
    tags: entry.tags,
    created: entry.created,
    modified: entry.modified,
    hidden: entry.hidden,
  };
  for (const key of vault.CARD_KEYS) {
    if (entry[key] !== "") out[key] = entry[key];
  }
  if (entry.attachments?.length) out.attachments = entry.attachments;
  return out;
}

console.log(`\n${checked - failed}/${checked} checks passed`);
if (failed > 0) {
  console.error(`${failed} check(s) failed — the browser crypto has drifted from core/`);
  process.exit(1);
}
