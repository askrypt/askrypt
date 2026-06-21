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

```json
{
    "version": "0.9",
    "question0": "What is your mother's maiden name?",
    "params" : {
      "kdf": "pbkdf2",
      "iterations": 600000,
      "salt": "base64-encoded-salt",
      "translit": false
    },
    "qs": "base64-encoded-encrypted-questions",
    "master": "base64-encoded-encrypted-master-key",
    "data": "base64-encoded-encrypted-main-secret"
}
```
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
generated.

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

The master key indirection (encrypting a random `masterKey` rather than the data
directly) means the answers can be changed by re-encrypting only the small
`master` blob, without re-encrypting all of `data` (useful for large vaults in
the future).
