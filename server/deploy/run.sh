#!/usr/bin/env bash
# Bring the askrypt stack up, from wherever this script lives.
#
# This is the one entry point: spot.yml's `run` task calls it on the server
# (where it sits in /home/askrypt-server next to the compose file), and it is
# also what to type by hand there or locally. It exists because
# `docker compose up` on its own is not enough any more — the server's data
# and logs are bind mounts, and a bind mount keeps the *host* directory's
# ownership instead of inheriting the image's the way a named volume does.
# Without the chown below the container's unprivileged user cannot create the
# database, and the failure reads as a permissions error deep in sqlx rather
# than as "the directory belongs to root".
#
# The image must already be loaded: the compose file has no `build:` section
# and `pull_policy: never`. Build it with ./docker-build.sh.
set -euo pipefail
cd "$(dirname "$0")"

# The image's `askrypt` service user (server/Dockerfile). Keep in step.
SERVICE_UID=10001

for dir in data logs; do
    mkdir -p "$dir"
    # Nothing to do in the ordinary case, which is also what lets this run
    # unprivileged once the directories are right: `vaults/` grows a file per
    # stored vault plus its version history, and walking all of it on every
    # deploy would cost more with each release.
    if [ "$(stat -c '%u %a' "$dir")" != "$SERVICE_UID 700" ]; then
        # Owner only: the group inside the image is `askrypt`'s own, whose gid
        # is whatever useradd picked, and mode 0700 makes it irrelevant.
        if ! chown -R "$SERVICE_UID" "$dir" || ! chmod 700 "$dir"; then
            echo "ERROR: $PWD/$dir must be owned by uid $SERVICE_UID (the" >&2
            echo "container's service user), mode 0700, and fixing it failed" >&2
            echo "— re-run as root, or set it by hand." >&2
            exit 1
        fi
    fi
done

docker compose up -d --remove-orphans

# Drops the image the previous deploy left untagged. Filtered by label so this
# only ever touches our own: an unfiltered prune would also collect anything
# else dangling on the host.
docker image prune -f --filter label=org.opencontainers.image.title=askrypt-server
