# Decrypting an Askrypt vault by hand (`askrypt-bash.sh`)

This document explains, step by step, how an Askrypt vault is decrypted using
only standard Linux tools. It accompanies [`askrypt-bash.sh`](./askrypt-bash.sh)
and exists for **algorithm transparency**: you should be able to read this,
reproduce every step yourself, and convince yourself that the format does
exactly what it claims — no hidden backdoor, no secret key escrow. It also works
as a recovery tool that does not depend on the Rust desktop app or the Flutter
mobile app.

The script is **strictly read-only**: it never writes to disk, never creates
temporary files, and never modifies the vault. It reads the vault with
`unzip -p` (straight to a pipe), keeps every intermediate value in shell
variables, and prints the decrypted entries to standard output only.

> The crypto core in [`core/src/lib.rs`](./core/src/lib.rs) is the source of
> truth; this is a faithful re-implementation of its decryption path, and the
> format itself is specified in [`SPEC.md`](./SPEC.md).

## Dependencies

| Tool | Used for |
|------|----------|
| `bash` | the script |
| coreutils: `base64`, `od`, `tr`, `cut`, `printf`, `sha256sum`, `sed` | encoding, hashing, text munging |
| `jq` | parsing the JSON inside the vault |
| `unzip` | reading `askrypt.json` out of the vault ZIP (`unzip -p`, to stdout) |
| `openssl` **3.0+** | PBKDF2 (`openssl kdf`) and AES-256-CBC (`openssl enc`) |

The only non-obvious requirement is **OpenSSL 3.0 or newer**, because the
`openssl kdf … PBKDF2` subcommand was added in 3.0. If you are stuck on an older
OpenSSL, you can replace the PBKDF2 helper with a one-liner using Python's
standard library (it is present on virtually every Linux system):

```sh
# PBKDF2-HMAC-SHA256, 32-byte key, printed as hex.
python3 - "$pass" "$salt_hex" "$iter" <<'PY'
import sys, hashlib, binascii
pwd, salt_hex, it = sys.argv[1], sys.argv[2], int(sys.argv[3])
key = hashlib.pbkdf2_hmac("sha256", pwd.encode(), binascii.unhexlify(salt_hex), it, 32)
print(key.hex())
PY
```

## The vault file

A vault (`*.askrypt`) is a plain **ZIP archive** containing a single file,
`askrypt.json`. That JSON looks like:

```json
{
  "version": "0.9",
  "question0": "What is your mother's maiden name?",
  "params": { "kdf": "pbkdf2", "iterations": 600000,
              "salt": "<base64 of salt0, 16 bytes>", "translit": false },
  "qs":     "<base64: encrypted remaining questions + salt1>",
  "master": "<base64: encrypted master key + data IV>",
  "data":   "<base64: encrypted list of secret entries>"
}
```

Decryption peels three layers. The answers themselves are **never stored** — they
only exist as the keys that unlock each layer.

## Building blocks

Three primitives are reused at every layer. Two of them have subtle details that
are easy to get wrong, so read these carefully.

### Normalization

Before an answer is used, it is normalized so that small typing differences do
not change the key:

> remove all whitespace, remove every kind of dash (`-`, `–`, `—`), then
> lowercase the rest.

So `"  Smith-Jones  "` becomes `smithjones`. Vaults created with
`translit: true` additionally **transliterate** Russian/Ukrainian text after
lowercasing — see [Transliteration](#transliteration-translit-true).

### Transliteration (`translit: true`)

If the vault's `params.translit` is `true`, the normalized (lowercased) answer is
then **transliterated** from Russian/Ukrainian to Latin using BGN/PCGN
romanization, matching [`core/src/translit.rs`](./core/src/translit.rs). Each
Cyrillic letter maps independently to 0–4 Latin letters — there is no
context/digraph logic — so a flat list of literal substitutions reproduces it
exactly. The script lowercases first (like the Rust core), but to be safe it also
maps uppercase Cyrillic directly to the same lowercase Latin:

```sh
translit_filter() {
  sed -e 's/щ/shch/g' -e 's/ё/yo/g' -e 's/ж/zh/g' -e 's/х/kh/g' \
      -e 's/ц/ts/g'   -e 's/ч/ch/g' -e 's/ш/sh/g' -e 's/ю/yu/g' \
      -e 's/я/ya/g'   -e 's/є/ye/g' -e 's/ї/yi/g' \
      -e 's/ъ//g' -e 's/ь//g'  \
      -e 's/а/a/g' -e 's/б/b/g' -e 's/в/v/g' -e 's/г/g/g' -e 's/ґ/g/g' \
      # … one rule per Cyrillic letter (and its uppercase form); see the script
}
```

Order is irrelevant because every pattern is Cyrillic and every replacement is
Latin, so substitutions never cascade. Examples: `москва → moskva`,
`пётр → pyotr`, `щука → shchuka`, `київ → kiyiv`, `ґанок → ganok`; the hard and
soft signs `ъ`/`ь` are dropped (`объект → obekt`).

### `sha256(data, salt)`

This is **lowercase-hex SHA-256 of the two strings concatenated**:
`sha256(data, salt) = hex( SHA256( data ++ salt ) )`.

> **Subtle point #1:** the `salt` here is always `params.salt` — the **base64
> *string*** exactly as it appears in the JSON, *not* its decoded bytes. We
> append the base64 text and hash that.

```sh
sha() { printf '%s' "$1$2" | sha256sum | cut -d' ' -f1; }
```

### PBKDF2 → 32-byte key

```sh
kdf() {   # $1=password (ASCII)  $2=salt as hex  $3=iterations
  openssl kdf -keylen 32 -kdfopt digest:SHA2-256 \
    -kdfopt "pass:$1" -kdfopt "hexsalt:$2" -kdfopt "iter:$3" PBKDF2 \
    | tr -d ':\n' | tr 'A-F' 'a-f'
}
```

> **Subtle point #2:** the PBKDF2 *password* is the 64-character **hex string**
> produced by `sha256(...)`, fed in as ASCII text — not the 32 raw hash bytes.
> The PBKDF2 *salt* is the raw decoded salt bytes (passed here as hex).

### AES-256-CBC decrypt

```sh
b64hex() { base64 -d | od -An -tx1 | tr -d ' \n'; }   # base64 -> hex
aesdec() { openssl enc -d -aes-256-cbc -K "$1" -iv "$2"; }   # key hex, iv hex
```

PKCS#7 padding is handled by OpenSSL automatically.

## The three layers

Let `salt0` = `base64decode(params.salt)` (16 bytes) and `iter` =
`params.iterations`.

### Layer 1 — unlock the remaining questions (`qs`)

Only the *first* question is stored in clear text. The rest are encrypted with a
key derived from the **first answer**.

```
first_hash = sha256( normalize(answer0), params.salt )
first_key  = PBKDF2( first_hash, salt0, iter )           # 32 bytes
qs_json    = AES-256-CBC-decrypt( base64decode(qs),
                                  key = first_key,
                                  iv  = salt0 )            # salt0 doubles as IV
```

`qs_json` is `{ "questions": [...], "salt": "<base64 of salt1>" }`. Now you know
the other questions, and `salt1` for the next layer.

### Layer 2 — unlock the master key (`master`)

The remaining answers, **concatenated together** (after normalization, with no
separator), derive the key that unlocks the master key.

```
combined    = normalize(answer1) ++ normalize(answer2) ++ … ++ normalize(answerN)
second_hash = sha256( combined, params.salt )            # note: params.salt again
second_key  = PBKDF2( second_hash, salt1, iter )
master_json = AES-256-CBC-decrypt( base64decode(master),
                                   key = second_key,
                                   iv  = salt1 )           # salt1 doubles as IV
```

`master_json` is `{ "masterKey": "<base64, 32 bytes>", "iv": "<base64, 16 bytes>" }`.

> Why a separate master key at all? It lets you change your answers (re-encrypt
> only the small `master` blob) without re-encrypting all of your data.

### Layer 3 — decrypt the secrets (`data`)

```
master_key = base64decode(master_json.masterKey)         # 32 bytes
data_iv    = base64decode(master_json.iv)                # 16 bytes
data_json  = AES-256-CBC-decrypt( base64decode(data),
                                  key = master_key,
                                  iv  = data_iv )
```

`data_json` is a JSON array of entries:
`{ name, user_name, secret, url, notes, type, tags, created, modified, hidden }`.

### About the salts and IVs

- `salt0` is used **both** as the PBKDF2 salt for the first key **and** as the
  AES IV in Layer 1.
- `salt1` is used **both** as the PBKDF2 salt for the second key **and** as the
  AES IV in Layer 2.
- Layer 3 uses an **independent**, randomly generated IV (`master_json.iv`),
  separate from the master key.

## Running it

```sh
./askrypt-bash.sh /path/to/vault.askrypt
```

It prints `question0`, reads your answer with echo disabled, prints the remaining
questions it recovered, asks each one, then prints the decrypted entries to
stdout. A wrong answer makes the corresponding AES step fail ("bad decrypt") and
the script exits non-zero with a clear message — it never reveals which answer
was wrong beyond which layer failed.

## Verify it yourself

The repository ships golden test vectors. You can decrypt the bundled test vault
with known answers and check the result — no real secrets involved:

```sh
# Reconstruct the test vault from the fixtures (this writes a temp file ONLY for
# the demo; the script itself never writes anything):
tmp=$(mktemp /tmp/askrypt-demo.XXXXXX.askrypt)
jq -r '.vault.vault_b64' app/test/fixtures/vectors.json | base64 -d > "$tmp"

printf 'Smith\nFluffy\nNew York\n' | ./askrypt-bash.sh "$tmp"
rm -f "$tmp"
```

Expected: the recovered questions are *"What was your first pet's name?"* and
*"What city were you born in?"*, and the two entries decrypt to secrets
`p@ssw0rd123` and `hidden secret пароль` (the Cyrillic value also confirms UTF-8
round-trips correctly).

## Security notes

- Answers are read with `read -rs` (echo disabled) and the script drops its
  references to them on exit. Bash gives no guarantee that string memory is
  wiped, so treat this as a recovery/audit tool, not a hardened daemon.
- The script writes **nothing** to disk and uses no temp files, so plaintext
  never lands on the filesystem unless *you* redirect its stdout.
- Avoid passing answers on the command line of any tool — argv is visible to
  other processes. This script prompts interactively instead.

## Limitations

- **Non-ASCII uppercase folding (`translit:false` only).** When a vault does
  *not* use transliteration, answers are lowercased by `tr`, which folds only
  ASCII A–Z, so an uppercase non-ASCII letter (e.g. `É`, `Ä`, or a Cyrillic
  capital) could normalize differently from Rust's Unicode-aware lowercasing.
  This does **not** affect `translit:true` vaults (the transliteration map
  handles both cases of every Cyrillic letter) nor plain ASCII answers, which
  are by far the common case.
- Only the secret entries in `askrypt.json` are decrypted. The format reserves
  room for file attachments, but the current entry schema has no attachment
  field, so there is nothing else to extract.
