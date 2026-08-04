#!/usr/bin/env bash
# Snapshot the Askrypt server's state: the SQLite database and the vault
# blobs.
#
#   server/deploy/backup.sh /var/backups/askrypt
#   server/deploy/backup.sh /var/backups/askrypt --quiesce
#
# Order matters. `askrypt-server` writes vault bytes before their metadata
# row, so snapshotting the database FIRST can only ever produce a blob with
# no row (an invisible orphan, harmless). The reverse order could produce a
# row with no bytes, which reads back as a 500. Deletes go the other way, so
# no order is safe against a concurrent delete: pass --quiesce to stop the
# service for an exact snapshot. Without it the inconsistency window is one
# HTTP request wide.
#
# Never `cp` the live askrypt.db: it runs in WAL mode, so the .db file alone
# can be stale or torn. `askrypt-server backup` uses VACUUM INTO, which is
# safe against a running server.
set -euo pipefail

DEST=${1:?usage: backup.sh <destination-dir> [--quiesce]}
QUIESCE=${2:-}

DATA_DIR=${ASKRYPT_DATA_DIR:-/var/lib/askrypt}
SERVER_BIN=${ASKRYPT_SERVER_BIN:-/usr/local/bin/askrypt-server}
SERVICE=${ASKRYPT_SERVICE:-askrypt-server}
KEEP_DAYS=${ASKRYPT_BACKUP_KEEP_DAYS:-30}

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$DEST"

stopped=0
cleanup() {
	if [ "$stopped" = 1 ]; then
		systemctl start "$SERVICE"
	fi
}
trap cleanup EXIT

if [ "$QUIESCE" = "--quiesce" ]; then
	echo "stopping $SERVICE for an exact snapshot"
	systemctl stop "$SERVICE"
	stopped=1
fi

echo "1/2 database -> $DEST/askrypt-$STAMP.db"
ASKRYPT_DATA_DIR="$DATA_DIR" "$SERVER_BIN" backup "$DEST/askrypt-$STAMP.db"

echo "2/2 vault blobs -> $DEST/vaults-$STAMP.tar.gz"
if [ -d "$DATA_DIR/vaults" ]; then
	# Excludes the temp files an interrupted upload can leave behind.
	tar -C "$DATA_DIR" --exclude='.*.tmp' -czf "$DEST/vaults-$STAMP.tar.gz" vaults
else
	echo "  (no vaults directory yet — skipping)"
fi

echo "pruning snapshots older than $KEEP_DAYS days"
find "$DEST" -maxdepth 1 -name 'askrypt-*.db' -mtime "+$KEEP_DAYS" -delete
find "$DEST" -maxdepth 1 -name 'vaults-*.tar.gz' -mtime "+$KEEP_DAYS" -delete

echo "backup complete: $STAMP"
