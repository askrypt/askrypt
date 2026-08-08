#!/usr/bin/env bash
# Deploy askrypt-server to a spot.yml target: ./deploy.sh dev|prod [spot flags...]
# e.g. ./deploy.sh dev --dry -v
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-}"
case "$TARGET" in
    dev|prod) shift ;;
    *) echo "Usage: $0 dev|prod [extra spot flags...]" >&2; exit 1 ;;
esac

if [ "$TARGET" = "prod" ]; then
    read -r -p "Deploy to PROD? [y/N] " answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

exec spot -p spot.yml -t "$TARGET" "$@"
