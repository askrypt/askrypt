#!/usr/bin/env bash
#
# askrypt-bash.sh — a transparent, read-only Askrypt vault decryptor.
#
# This script decrypts an Askrypt vault (.askrypt) using only standard Linux
# tools. It exists for *algorithm transparency*: every cryptographic step is
# plain and auditable, and it doubles as a recovery tool independent of the
# Rust/Dart apps. See askrypt-bash.md for a step-by-step explanation.
#
# STRICTLY READ-ONLY: it never writes to disk, never creates temp files, and
# never modifies the vault. The vault is read via `unzip -p` (to stdout) and all
# work happens in shell variables and pipes. Decrypted secrets are printed to
# stdout only.
#
# Dependencies: bash, coreutils (base64, od, tr, cut, printf, sha256sum),
#               jq, unzip, openssl 3.0+.
#
# Usage: ./askrypt-bash.sh <vault.askrypt>

set -euo pipefail

# --- Wipe answer-bearing variables on exit (best effort; bash strings are not
#     guaranteed wiped from memory, but we at least drop our references). -------
ANSWER=""
ANSWERS_REST=()
cleanup() { ANSWER=""; ANSWERS_REST=(); }
trap cleanup EXIT

die() { printf 'Error: %s\n' "$1" >&2; exit 1; }

# --- 0. Preflight ------------------------------------------------------------
[ $# -eq 1 ] || die "usage: $0 <vault.askrypt>"
VAULT="$1"
[ -r "$VAULT" ] || die "cannot read vault file: $VAULT"

for tool in jq unzip openssl base64 sha256sum od tr cut; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

# openssl 'kdf' subcommand (PBKDF2) requires OpenSSL >= 3.0.
ossl_major="$(openssl version | sed -E 's/^OpenSSL ([0-9]+).*/\1/')"
[ "${ossl_major:-0}" -ge 3 ] 2>/dev/null \
  || die "OpenSSL 3.0+ required for 'openssl kdf' (found: $(openssl version))"

# --- Crypto helpers (mirror core/src/lib.rs) ---------------------------------

# Decode base64 (stdin) to a lowercase hex string (no spaces/newlines).
b64hex() { base64 -d | od -An -tx1 | tr -d ' \n'; }

# sha256(data, salt) = lowercase hex of SHA256(data ++ salt). NOTE: in Askrypt
# the salt argument is always params.salt — the base64 *string*, not its bytes.
sha() { printf '%s' "$1$2" | sha256sum | cut -d' ' -f1; }

# PBKDF2-HMAC-SHA256 -> 32-byte key as lowercase hex.
#   $1 = password (ASCII; here the 64-char hex sha256 string)
#   $2 = salt as hex (raw decoded salt bytes)
#   $3 = iteration count
kdf() {
  openssl kdf -keylen 32 -kdfopt digest:SHA2-256 \
    -kdfopt "pass:$1" -kdfopt "hexsalt:$2" -kdfopt "iter:$3" PBKDF2 \
    | tr -d ':\n' | tr 'A-F' 'a-f'
}

# AES-256-CBC decrypt (PKCS7), ciphertext on stdin, plaintext to stdout.
#   $1 = key hex (64 chars), $2 = iv hex (32 chars)
aesdec() { openssl enc -d -aes-256-cbc -K "$1" -iv "$2"; }

# Transliterate Russian/Ukrainian to Latin (BGN/PCGN), mirroring
# core/src/translit.rs. Each Cyrillic letter maps independently to 0..4 Latin
# letters, so a sequence of literal substitutions reproduces it exactly. Rust
# lowercases before transliterating, so we map uppercase Cyrillic too (to the
# same lowercase Latin) and order is irrelevant (patterns are Cyrillic, outputs
# are Latin — they never cascade).
translit_filter() {
  sed \
    -e 's/щ/shch/g' -e 's/Щ/shch/g' \
    -e 's/ё/yo/g'   -e 's/Ё/yo/g' \
    -e 's/ж/zh/g'   -e 's/Ж/zh/g' \
    -e 's/х/kh/g'   -e 's/Х/kh/g' \
    -e 's/ц/ts/g'   -e 's/Ц/ts/g' \
    -e 's/ч/ch/g'   -e 's/Ч/ch/g' \
    -e 's/ш/sh/g'   -e 's/Ш/sh/g' \
    -e 's/ю/yu/g'   -e 's/Ю/yu/g' \
    -e 's/я/ya/g'   -e 's/Я/ya/g' \
    -e 's/є/ye/g'   -e 's/Є/ye/g' \
    -e 's/ї/yi/g'   -e 's/Ї/yi/g' \
    -e 's/а/a/g'    -e 's/А/a/g' \
    -e 's/б/b/g'    -e 's/Б/b/g' \
    -e 's/в/v/g'    -e 's/В/v/g' \
    -e 's/г/g/g'    -e 's/Г/g/g' \
    -e 's/ґ/g/g'    -e 's/Ґ/g/g' \
    -e 's/д/d/g'    -e 's/Д/d/g' \
    -e 's/е/e/g'    -e 's/Е/e/g' \
    -e 's/э/e/g'    -e 's/Э/e/g' \
    -e 's/з/z/g'    -e 's/З/z/g' \
    -e 's/и/i/g'    -e 's/И/i/g' \
    -e 's/і/i/g'    -e 's/І/i/g' \
    -e 's/й/y/g'    -e 's/Й/y/g' \
    -e 's/ы/y/g'    -e 's/Ы/y/g' \
    -e 's/к/k/g'    -e 's/К/k/g' \
    -e 's/л/l/g'    -e 's/Л/l/g' \
    -e 's/м/m/g'    -e 's/М/m/g' \
    -e 's/н/n/g'    -e 's/Н/n/g' \
    -e 's/о/o/g'    -e 's/О/o/g' \
    -e 's/п/p/g'    -e 's/П/p/g' \
    -e 's/р/r/g'    -e 's/Р/r/g' \
    -e 's/с/s/g'    -e 's/С/s/g' \
    -e 's/т/t/g'    -e 's/Т/t/g' \
    -e 's/у/u/g'    -e 's/У/u/g' \
    -e 's/ф/f/g'    -e 's/Ф/f/g' \
    -e 's/ъ//g'     -e 's/Ъ//g' \
    -e 's/ь//g'     -e 's/Ь//g'
}

# Normalize an answer: drop whitespace and dashes (- – —), lowercase, and
# transliterate when the vault was created with params.translit == true.
# Mirrors normalize_answer() in core/src/lib.rs.
normalize() {
  local s
  s="$(printf '%s' "$1" \
    | tr -d '[:space:]' \
    | sed 's/-//g; s/–//g; s/—//g' \
    | tr '[:upper:]' '[:lower:]')"
  if [ "$TRANSLIT" = "true" ]; then
    printf '%s' "$s" | translit_filter
  else
    printf '%s' "$s"
  fi
}

# --- 1. Read the vault (read-only, via stdout) -------------------------------
AJ="$(unzip -p "$VAULT" askrypt.json)" || die "could not extract askrypt.json from $VAULT"

QUESTION0="$(jq -r '.question0' <<<"$AJ")"
SALT0_B64="$(jq -r '.params.salt' <<<"$AJ")"
ITER="$(jq -r '.params.iterations' <<<"$AJ")"
TRANSLIT="$(jq -r '.params.translit // false' <<<"$AJ")"
QS_B64="$(jq -r '.qs' <<<"$AJ")"
MASTER_B64="$(jq -r '.master' <<<"$AJ")"
DATA_B64="$(jq -r '.data' <<<"$AJ")"

SALT0_HEX="$(printf '%s' "$SALT0_B64" | b64hex)"

# --- 2. Layer 1: first answer -> recover the remaining questions -------------
printf '%s\n' "$QUESTION0" >&2
read -rsp "Answer: " ANSWER; echo >&2

N_ANS0="$(normalize "$ANSWER")"
FIRST_HASH="$(sha "$N_ANS0" "$SALT0_B64")"
FIRST_KEY="$(kdf "$FIRST_HASH" "$SALT0_HEX" "$ITER")"

QS_JSON="$(printf '%s' "$QS_B64" | base64 -d | aesdec "$FIRST_KEY" "$SALT0_HEX" 2>/dev/null)" \
  || die "wrong answer to the first question (could not decrypt questions)"

SALT1_B64="$(jq -r '.salt' <<<"$QS_JSON")"
SALT1_HEX="$(printf '%s' "$SALT1_B64" | b64hex)"
mapfile -t QUESTIONS < <(jq -r '.questions[]' <<<"$QS_JSON")

# --- 3. Layer 2: remaining answers -> recover the master key -----------------
COMBINED=""
for q in "${QUESTIONS[@]}"; do
  printf '%s\n' "$q" >&2
  read -rsp "Answer: " a; echo >&2
  COMBINED="${COMBINED}$(normalize "$a")"
  a=""
done

SECOND_HASH="$(sha "$COMBINED" "$SALT0_B64")"
COMBINED=""
SECOND_KEY="$(kdf "$SECOND_HASH" "$SALT1_HEX" "$ITER")"

MASTER_JSON="$(printf '%s' "$MASTER_B64" | base64 -d | aesdec "$SECOND_KEY" "$SALT1_HEX" 2>/dev/null)" \
  || die "wrong answer(s) — could not decrypt the master key"

MASTER_KEY_HEX="$(jq -r '.masterKey' <<<"$MASTER_JSON" | b64hex)"
DATA_IV_HEX="$(jq -r '.iv' <<<"$MASTER_JSON" | b64hex)"

# --- 4. Layer 3: decrypt the secret entries ---------------------------------
DATA_JSON="$(printf '%s' "$DATA_B64" | base64 -d | aesdec "$MASTER_KEY_HEX" "$DATA_IV_HEX" 2>/dev/null)" \
  || die "could not decrypt the secret data"

# --- 5. Print entries to stdout ---------------------------------------------
jq -r '
  .[] |
  "──────────────────────────────────────────",
  "name:     \(.name)",
  "user:     \(.user_name)",
  "secret:   \(.secret)",
  "url:      \(.url)",
  "notes:    \(.notes)",
  "type:     \(.type)",
  "tags:     \(.tags | join(", "))",
  "hidden:   \(.hidden)"
' <<<"$DATA_JSON"
