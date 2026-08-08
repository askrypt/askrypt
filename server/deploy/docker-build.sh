#!/usr/bin/env bash
# Build the askrypt-server Docker image (two-stage: cargo builder, Debian slim
# runtime).
#
# The build context is the *repository root*, not server/: cargo validates
# every workspace member's target paths and sqlx::migrate! embeds
# server/migrations/ at compile time. This script cds there and points docker
# at server/Dockerfile, so it can be run from anywhere.
#
# Cross-arch: the image is built for the local architecture. Deploying to a
# server with a different one needs PLATFORM=linux/amd64 (and a working
# binfmt/buildx setup), which will be a slow emulated cargo build.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE="${IMAGE:-askrypt-server}"

# Embed the current git revision so a running container can be traced back to
# a commit: it becomes an image label and the server logs it at startup.
GIT_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_COMMIT_MSG="$(git log -1 --pretty=%s 2>/dev/null || echo unknown)"

docker build -f server/Dockerfile -t "$IMAGE" \
    --build-arg GIT_HASH="$GIT_HASH" \
    --build-arg GIT_COMMIT_MSG="$GIT_COMMIT_MSG" \
    ${PLATFORM:+--platform "$PLATFORM"} \
    .
