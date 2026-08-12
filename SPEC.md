# Askrypt format specification v0.9

This document specifies the JSON format used by Askrypt to store passwords/secrets. 
The format is designed to be simple and human-readable. The JSON file (askrypt.json)
contains the main encrypted data, questions, and parameters required for decryption. 
This file is compressed into a ZIP archive (vault.askrypt) along with additional attachments (files).

## File Structure (askrypt.json)
An Askrypt file is a JSON with the following fields:
* `version` - version of the Askrypt format (currently "0.9"; loading rejects any other value)
* `question0` - first question (string)
* `params` (first-level kdf parameters):
  * `kdf` - key derivation function used (string, default: "pbkdf2")
  * `iterations` - iterations count (integer, default: 600000)
  * `salt` - base64 encoded salt (**salt0**), 16 bytes (string)
  * `translit` - whether to apply Russian/Ukrainian transliteration to answers
    during normalization (boolean, default: `false`; absent in older files)
  * `host` - label for the machine that last wrote the vault, `os@host` (string,
    optional; omitted when unknown and absent in older files)
  * `updated_at` - when the vault was last written, RFC 3339 UTC with second
    precision, e.g. `"2026-08-02T10:15:30Z"` (string, optional; absent in older
    files)
* `qs` - base64 encoded encrypted data (string, json), encrypted by the first answer:
  * `questions` - the rest of the questions
  * `salt` - base64 encoded salt (**salt1**), 16 bytes (string)
* `master` - base64 encoded encrypted master key (string, json), which includes:
  * `masterKey` - base64 encoded encrypted master key (string), used to encrypt/decrypt data
  * `iv` - base64 encoded initialization vector (string)
* `data` - base64 encoded encrypted main secret (string, json), which includes a list of user items:
  * `name` - entry title/label (string)
  * `user_name` - username (string)
  * `secret` - password/secret (string)
  * `url` - url (string)
  * `notes` - notes (string)
  * `type` - type of the entry (string, e.g. "password", "note", etc.)
  * `tags` - list of tags (array of strings)
  * `created` - creation timestamp (**integer**, Unix time in seconds)
  * `modified` - last modified timestamp (**integer**, Unix time in seconds)
  * `hidden` - whether the entry is hidden in the UI (boolean, default: `false`)
  * The six `card_*` keys below carry meaning only for entries whose `type` is
    `"Card"` (compared case-insensitively). Each is **omitted when empty**, so an
    entry that is not a card serializes exactly as it did before these existed,
    and a file written by an older build parses with all six blank:
    * `card_holder` - name embossed on the card (string, optional)
    * `card_brand` - card network, e.g. `"Visa"` (string, optional; free-form,
      clients offer a list but the format does not constrain it)
    * `card_number` - card number as typed, spaces and all (string, optional)
    * `card_expiry` - expiry as `MM/YY`, stored as typed and never parsed
      (string, optional)
    * `card_cvv` - card security code (string, optional)
    * `card_pin` - card PIN (string, optional)

```json
{
    "version": "0.9",
    "question0": "What is your mother's maiden name?",
    "params" : {
      "kdf": "pbkdf2",
      "iterations": 600000,
      "salt": "base64-encoded-salt",
      "translit": false,
      "host": "ubuntu@my-laptop",
      "updated_at": "2026-08-02T10:15:30Z"
    },
    "qs": "base64-encoded-encrypted-questions",
    "master": "base64-encoded-encrypted-master-key",
    "data": "base64-encoded-encrypted-main-secret"
}
```
`host` and `updated_at` are **write metadata**, not inputs to any derivation:
they are refreshed on every save and are stored unencrypted, so they are
readable without any answer. Writers that cannot determine one of them omit the
field entirely rather than writing a placeholder.

`host` is `<os>@<host name>` — `ubuntu@my-laptop`, `windows@workps`,
`android@pixel-8`. The OS half is a coarse lowercase name (on Linux, the
`ID=` value from `/etc/os-release`, e.g. `ubuntu`, so `linux` is only the
fallback); a writer that knows only one half writes that half alone, never a
dangling `ubuntu@`. Readers must treat the whole value as **opaque display
text** — vaults written before this convention carry a bare host name with no
OS half — and must sanitize it before display, since it is attacker-controlled
in a file that anyone can craft.

The maximum question length is **500 bytes** (UTF-8). Each question is human-readable text. 
The answer is a secret known only to the user. Questions can include spaces and special characters.

Example question:
```
What is your mother's maiden name? (bad question)
What was the name of your first pet? (should be non-common name)
What is the name of the street you grew up on?
What book were you reading when you broke your leg? (Original title)
Who taught you to play chess? (First name Last name)
You first kiss (Name)
You first kiss (City)
```

## Algorithm

The answers themselves are never stored in the file. Keys are derived from the
answers each time the vault is opened.

### Answer normalization

Before any key derivation, each answer is normalized:

1. Remove all whitespace characters (spaces, tabs, newlines).
2. Remove all dash characters: `-` (hyphen), `–` (en dash) and `—` (em dash).
3. Lowercase every letter.
4. If `params.translit` is `true`, transliterate the result from
   Russian/Ukrainian to Latin (QWERTY-only) using BGN/PCGN romanization
   (e.g. `ё→yo`, `е→e`, `ц→ts`, `ъ/ь` dropped; Ukrainian `ґ→g`, `є→ye`,
   `і→i`, `ї→yi`). Non-Cyrillic characters pass through unchanged.

### Key derivation (KDF)

Keys are **not** derived from the raw normalized answer. Each answer string is
first hashed with SHA-256 and the lowercase hex digest is used as the PBKDF2
input. The SHA-256 salt is the **base64 string** of `salt0` (i.e. `params.salt`),
appended to the answer before hashing:

```
hash(s) = lowercase_hex( SHA-256( s + base64(salt0) ) )
```

PBKDF2 uses **HMAC-SHA-256** and produces a **32-byte** key, run for
`params.iterations` iterations (default 600000).

### Encryption steps

At creation time `salt0`, `salt1`, `masterKey` (32 random bytes) and `iv` are
generated. On every **later** write, `salt0`, `salt1` and `iv` are generated
afresh but `masterKey` is **not** — see [Master key lifetime](#master-key-lifetime).

1. **first-key** (32 bytes) = `PBKDF2( hash(answer0), salt0, iterations )`,
   where `answer0` is the normalized first answer.
   The remaining questions plus `salt1` (the `qs` JSON) are encrypted with
   `encrypt_with_aes` (AES-256-CBC) using **first-key** and **salt0 as the IV**,
   and stored base64-encoded in `qs`.

2. **second-key** (32 bytes) = `PBKDF2( hash(concat), salt1, iterations )`,
   where `concat` is the concatenation of all normalized answers from the
   second to the last (no separator). Note the SHA-256 salt is still
   `base64(salt0)`.
   The `masterKey` and `iv` (the `master` JSON) are encrypted with AES-256-CBC
   using **second-key** and **salt1 as the IV**, and stored base64-encoded in
   `master`.

3. The main secret data (the list of secret entries) is encrypted with
   AES-256-CBC using **masterKey** and **iv**, and stored base64-encoded in
   `data`.

All AES-256-CBC encryption uses PKCS#7 padding.

### Master key lifetime

The master key indirection (encrypting a random `masterKey` rather than the data
directly) means the answers can be changed by re-encrypting only the small
`master` blob rather than everything the master key covers.

**A vault's `masterKey` is minted once, when the vault is created, and is
preserved for the life of the vault.** Every write re-wraps that same key under
whatever the answers currently are — an ordinary save, a save to a new location,
and a change of the questions and answers alike. It is a property of the vault,
not of a particular file on disk: a client that saves a vault must recover the
existing key first and hand it back, never mint a new one. (Clients recover it as
a side effect of unlocking, which already decrypts `master`.)

This is what will let encrypted file attachments live under the master key: were
it rotated on every save, each save would have to decrypt and re-encrypt every
attachment.

Two things are **not** preserved. `salt0` and `salt1` are regenerated on every
write, so the answer-derived keys are never reused. So is `iv`, and that one is
load-bearing: AES-CBC under a repeated key *and* IV encrypts identical plaintext
identically, so anyone holding two versions of a vault could read off how long a
prefix of the entry list went unchanged between them.

One consequence is worth stating plainly: because changing the answers keeps the
key, an attacker who learned the old answers *and* kept a copy of the old file
can derive the master key, and that key still opens copies of the vault written
after the change. Changing the answers protects a vault whose answers might leak
in future; it does not undo a leak that already happened.

### Integrity: not provided

**Format v0.9 offers confidentiality but no integrity.** All three blobs — `qs`,
`master` and `data` — are unauthenticated AES-256-CBC: there is no MAC, no AEAD,
and nothing anywhere in the file authenticates any other part of it. A reader
cannot distinguish a vault it wrote from one that has been altered in transit or
at rest.

This matters because the file is designed to be handed to parties that are not
trusted with its contents — the Askrypt server stores it as an opaque blob, and
it also lives in cloud folders and backups. Those parties cannot *read* a vault,
but nothing in the format stops them from *changing* one.

What a reader actually has today are three accidental consistency checks, none of
which is an integrity check: PKCS#7 padding must be well-formed, the plaintext
must be valid UTF-8, and it must parse as the expected JSON. They reject most
damage, which is why corruption usually surfaces as "wrong answer". They are
heuristics, and a spec must not be read as promising more than it does.

Concretely, in CBC, `Pᵢ = D_k(Cᵢ) ⊕ Cᵢ₋₁`. Flipping a bit in ciphertext block
`Cᵢ₋₁` flips the same bit in plaintext block `Pᵢ` while turning `Pᵢ₋₁` into
random bytes. So a targeted single-bit edit is possible at the cost of destroying
one preceding block. Against these JSON payloads that almost always breaks
parsing — it survives only if the garbled block falls wholly inside a long string
value (a `notes` field) *and* happens to contain no quote, no backslash, no
control byte and no invalid UTF-8 sequence.

Two things limit this in practice, and both should be understood as circumstance
rather than as design:

- **The IVs are not independently malleable.** `data`'s IV is sealed inside
  `master`, `master`'s IV (`salt1`) is sealed inside `qs`, and `qs`'s IV
  (`salt0`) is in the clear but is *also* the PBKDF2 and SHA-256 salt, so
  changing it destroys the key rather than shifting the plaintext. Otherwise the
  first block of each blob would be malleable with no collateral damage at all.
- **There is no padding oracle**, because decryption happens entirely on the
  client and no signal about its outcome is returned to whoever supplied the
  bytes. An attacker is blind and cannot iterate. This is a property of how the
  clients and server are deployed today, **not of the format** — any future
  feature that reports a decryption result back over the network would create
  one.

Separately, `params` is both unencrypted and unauthenticated, and its fields fall
into three groups. `salt`, `iterations` and `translit` are KDF inputs, so
altering one breaks unlocking rather than weakening it — a changed work factor
yields a *different* key, not an easier one, so there is no downgrade attack
here. `kdf` is written but read by no decryption path in any implementation, so
altering it does nothing at all. And `host`/`updated_at` feed no derivation
either: **the write stamp is unauthenticated and must be treated as a hint, never
as evidence** of when or where a vault was last written. That last one is the
only part of `params` an attacker can change to any effect, and the effect is a
lie in a UI — including the `Saved` column of the server's web file manager.

The fix is [TODO: authenticated encryption](#todo-authenticated-encryption-format-v10) below.

---

## TODO: authenticated encryption (format v1.0)

Replacing unauthenticated CBC is the one known gap in this format that requires a
**breaking version bump**, so it is written down here rather than left as a code
comment. Nothing below is implemented.

### Why it cannot be a v0.9 addition

`version` is hard-rejected when it is not the expected value — `AskryptFile::from_bytes`
in `core/src/lib.rs` and `AskryptFile.fromBytes` in `app/lib/crypto/vault.dart` both
do this. Any file carrying a MAC is therefore unreadable by every shipped build,
which is exactly the behaviour we want (a silent downgrade to an unauthenticated
read would be worse than a hard failure) but does make this a coordinated
release: `version` becomes `"1.0"`, and readers must learn to accept **both**
`"0.9"` and `"1.0"`, upgrading a v0.9 vault to v1.0 on the next save.

### Preferred shape

Use an AEAD — **AES-256-GCM** — for all three blobs rather than bolting
encrypt-then-MAC onto CBC. One primitive, one key per blob, no room for the
key-separation and comparison mistakes that hand-rolled MAC composition invites.
ChaCha20-Poly1305 is an acceptable alternative if a target platform lacks
hardware AES; the Dart port is the constraint to check.

Requirements, in rough order of how easy each is to get wrong:

1. **Nonce discipline is now the critical invariant, and it is stricter than
   CBC's.** Reusing a GCM nonce under one key is catastrophic in a way CBC IV
   reuse is not: it leaks the authentication subkey and permits forgery, not just
   a plaintext-prefix comparison. This interacts directly with
   [Master key lifetime](#master-key-lifetime) — the master key is deliberately
   long-lived, so it is the *nonce* that must carry all the uniqueness. Draw 96
   fresh random bits on every single write. Never derive a nonce from anything
   stable (the vault id, a counter persisted in the file, a timestamp), and never
   reuse one across two blobs in the same file.
2. **Cover every blob**: `qs`, `master`, `data` — and each file attachment, which
   is the whole reason the master key is preserved in the first place. An
   attachment scheme designed before this lands should leave room for a per-blob
   nonce and tag.
3. **Bind `params` as associated data.** `params` stays unencrypted (readers need
   `salt`/`iterations` before they have any key), but passing it as AAD to the
   outermost blob makes it unmodifiable, which closes the `host`/`updated_at`
   forgery noted above and pins the KDF parameters to the file they belong to.
4. **Decide what a failed tag means to the user.** Today a bad answer and a
   corrupted file both surface as "wrong answer". With a MAC the two become
   distinguishable, and they deserve different words: one is "try again", the
   other is "this file has been altered — do not trust it". This is a UI change
   in `src/`, `gui/` and `app/`, not just a crypto change.
5. **Keep the three implementations in lock-step.** Rust core, the Dart port, and
   new golden vectors: regenerate `app/test/fixtures/vectors.json` via
   `cargo run -p askrypt-core --example gen_vectors`, and keep a v0.9 fixture
   alongside the v1.0 one so the read-old/write-new path stays covered.
6. **The server needs no change and must not get one.** It stores opaque bytes;
   `server/src/vaultfile.rs` reads `params` only, and must keep working against
   both versions. It must never be given the ability to verify a tag — that would
   be a step toward it understanding vault contents.

### Explicitly out of scope

Authenticating the *ZIP container* rather than the blobs inside it. The archive
is a transport detail, the blobs are the format, and a container-level MAC would
have to be re-verified by anything that repacks the archive.
