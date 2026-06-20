#!/usr/bin/env bash
# Update all Rust dependency version requirements in the workspace.
#
# Rewrites the dependency version requirements in every Cargo.toml to the
# newest releases, *including* semver-breaking major versions (e.g. 6 -> 7),
# then syncs Cargo.lock. It does not build or test — review the diff and run
# `cargo build --workspace` / `cargo test --workspace` yourself afterwards.
#
# Requires the `cargo upgrade` subcommand from cargo-edit:
#   cargo install cargo-edit
#
# Usage:
#   scripts/update-deps.sh             # upgrade manifests + sync Cargo.lock
#   scripts/update-deps.sh --dry-run   # preview version bumps, write nothing
set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown argument '$arg' (try --dry-run or --help)" >&2
      exit 2
      ;;
  esac
done

# Run from the repo root, derived from this script's location, so it works
# regardless of the current working directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found on PATH. Install Rust from https://rustup.rs" >&2
  exit 1
fi

if ! cargo upgrade --help >/dev/null 2>&1; then
  echo "error: the 'cargo upgrade' subcommand is missing." >&2
  echo "       Install cargo-edit, then re-run this script:" >&2
  echo "         cargo install cargo-edit" >&2
  exit 1
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Previewing dependency upgrades (no files will be written)..."
  cargo upgrade --incompatible --dry-run
  echo
  echo "Dry run complete. Re-run without --dry-run to apply."
  exit 0
fi

echo "Upgrading dependency requirements to latest (including major versions)..."
cargo upgrade --incompatible

echo "Syncing Cargo.lock..."
cargo update

echo
echo "Done. Dependency requirements updated in every Cargo.toml and Cargo.lock."
echo "Next: review 'git diff', then run 'cargo build --workspace' and"
echo "'cargo test --workspace' — breaking major bumps may need code changes."
