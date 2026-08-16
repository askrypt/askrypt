#!/usr/bin/env bash
#
# Archive the whole deployment directory — the database, the vault blobs, the
# logs, the .env, the compose file and the Caddyfile — into the off-host spool.
# Meant for cron, as root: the data directory is mode 0700 owned by uid 10001.
#
# The database is *not* copied as it lies. It runs in WAL mode, so the .db file
# on its own can be stale or torn; the snapshot below is `VACUUM INTO`, which
# is safe against the running server. It is taken inside the container because
# that is where the binary is, written into the data directory because the bind
# mount gives it the same path on both sides, and picked up by the copy that
# follows. The live .db/-wal/-shm are then dropped from the copy, so the
# archive holds exactly one database and it is the consistent one.
set -euo pipefail

SRC="/home/askrypt-server"
DEST_DIR="/home/backup/dropbox/askrypt-server"
STAMP="$(date +%Y%m%d_%H%M%S)"
TMP_DIR="/tmp/askrypt-server_${STAMP}"
ARCHIVE="${TMP_DIR}.tar.gz"
SNAPSHOT="${SRC}/data/snap-${STAMP}.db"

echo "Backing up Askrypt server to ${DEST_DIR}..."

# `docker exec` ignores the image's ENTRYPOINT, hence the binary named twice;
# it runs as the image's own uid 10001, which is what may write in data/.
if ! docker exec askrypt-server askrypt-server backup "$SNAPSHOT"; then
    echo "ERROR: could not snapshot the database — is the askrypt-server" >&2
    echo "container running? (docker compose ps in ${SRC})" >&2
    exit 1
fi

cp -a "$SRC" "$TMP_DIR"
rm -f "$SNAPSHOT"

# Only in the copy: the live database and the write-ahead log belonging to it.
# The snapshot stays, and a restore is `cp snap-<stamp>.db <data>/askrypt.db`.
rm -f "$TMP_DIR/data/askrypt.db" \
      "$TMP_DIR/data/askrypt.db-wal" \
      "$TMP_DIR/data/askrypt.db-shm"

tar -czf "$ARCHIVE" -C /tmp "$(basename "$TMP_DIR")"
rm -rf "$TMP_DIR"

mkdir -p "$DEST_DIR"
cp "$ARCHIVE" "$DEST_DIR/"
rm -f "$ARCHIVE"

echo "Backup complete: ${DEST_DIR}/$(basename "$ARCHIVE")"
