#!/usr/bin/env bash
# Run the server conformance suite (core/examples/server_roundtrip) end to end.
#
# Starts a throwaway `askrypt-server`, registers the two accounts the run needs
# — the first account ever registered becomes the administrator, so the order
# matters — and runs the suite twice: once as an administrator (which exercises
# the Users and Settings pages) and once as a plain account (which proves that
# surface is unreachable). Stops the server again on the way out, whatever
# happened.
#
# The suite itself refuses any host that is not loopback, and this script only
# ever starts one locally: it bans accounts, deletes accounts and flips the
# registration switch, so it must never point at a real deployment.
#
# Usage:
#   scripts/server-roundtrip.sh                    # both roles, memory backend
#   scripts/server-roundtrip.sh --backend sqlite   # exercise the real stores
#   scripts/server-roundtrip.sh --role admin       # just the administrator run
#   scripts/server-roundtrip.sh --port 8123
#   scripts/server-roundtrip.sh --keep             # leave the server running
#   scripts/server-roundtrip.sh -- --only vaults   # pass options to the suite
#
# The admin run pauses for the server's 20/minute rate limiter, so expect it to
# take a couple of minutes.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

BACKEND=memory
PORT=8099
ROLE=both
KEEP=false
SUITE_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend) BACKEND="${2:?--backend needs memory or sqlite}"; shift 2 ;;
    --port) PORT="${2:?--port needs a number}"; shift 2 ;;
    --role) ROLE="${2:?--role needs admin, plain or both}"; shift 2 ;;
    --keep) KEEP=true; shift ;;
    --) shift; SUITE_ARGS=("$@"); break ;;
    # The comment block at the top, up to the first line that is not one.
    -h|--help) sed -n '2,${/^#/!q;p;}' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
done

case "$BACKEND" in memory|sqlite) ;; *) echo "error: --backend must be memory or sqlite" >&2; exit 2 ;; esac
case "$ROLE" in admin|plain|both) ;; *) echo "error: --role must be admin, plain or both" >&2; exit 2 ;; esac

BASE="http://127.0.0.1:$PORT"
PASSWORD=correct-horse
ADMIN_EMAIL=admin@roundtrip.invalid
PLAIN_EMAIL=plain@roundtrip.invalid

# A fresh directory per run, so a sqlite run never inherits another's accounts
# and nothing lands in the repo's own gitignored `data/`.
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/askrypt-roundtrip.XXXXXX")"
LOG="$DATA_DIR/server.log"
SERVER_PID=

cleanup() {
  local status=$?
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    if [[ "$KEEP" == true ]]; then
      echo
      echo "--keep: server still running on $BASE (pid $SERVER_PID, data in $DATA_DIR)"
      echo "        stop it with: kill $SERVER_PID"
      return $status
    fi
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  # The log is worth keeping when something went wrong and nothing otherwise.
  if [[ $status -ne 0 ]]; then
    echo
    echo "server log: $LOG"
  elif [[ "$KEEP" != true ]]; then
    rm -rf "$DATA_DIR"
  fi
  return $status
}
trap cleanup EXIT

if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
  echo "error: something is already listening on port $PORT (try --port)" >&2
  exit 2
fi

echo "building"
cargo build -q -p askrypt-server
cargo build -q -p askrypt-core --features server-storage --example server_roundtrip

echo "starting a $BACKEND-backed server on $BASE"
ASKRYPT_BIND="127.0.0.1:$PORT" \
ASKRYPT_BACKEND="$BACKEND" \
ASKRYPT_DATA_DIR="$DATA_DIR/data" \
ASKRYPT_LOG_DIR= \
RUST_LOG="${RUST_LOG:-warn}" \
  cargo run -q -p askrypt-server >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  curl -sf "$BASE/healthz" >/dev/null 2>&1 && break
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "error: the server exited at startup" >&2; cat "$LOG" >&2; exit 1; }
  sleep 1
done
curl -sf "$BASE/healthz" >/dev/null || { echo "error: the server never answered /healthz" >&2; exit 1; }

register() {
  curl -sf -X POST "$BASE/api/v1/auth/register" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$PASSWORD\"}" >/dev/null
}

# First one registered is the administrator (`admin::bootstrap_first_admin`).
echo "registering $ADMIN_EMAIL (becomes the administrator) and $PLAIN_EMAIL"
register "$ADMIN_EMAIL"
register "$PLAIN_EMAIL"

run_suite() {
  local label=$1 email=$2
  echo
  echo "############ suite as the $label account ############"
  cargo run -q -p askrypt-core --features server-storage --example server_roundtrip \
    -- "$BASE" "$email" "$PASSWORD" ${SUITE_ARGS[@]+"${SUITE_ARGS[@]}"}
}

failed=0
if [[ "$ROLE" == admin || "$ROLE" == both ]]; then
  run_suite administrator "$ADMIN_EMAIL" || failed=1
fi
if [[ "$ROLE" == plain || "$ROLE" == both ]]; then
  run_suite plain "$PLAIN_EMAIL" || failed=1
fi

echo
if [[ $failed -ne 0 ]]; then
  echo "FAILED — see the run above"
  exit 1
fi
echo "all runs passed"
