# syntax=docker/dockerfile:1.7
#
# Build from the *repository root*, not from server/:
#     docker build -f server/Dockerfile -t askrypt-server .
#
# server/deploy/docker-build.sh does that, and passes the git revision in.
#
# The whole repo is copied because the root Cargo.toml is both the workspace
# root and a package: cargo validates every member's explicitly-pathed
# targets (root `[[bin]] path = "src/main.rs"`, core's `[lib] path =
# "src/lib.rs"`) even for `-p askrypt-server`, and `sqlx::migrate!` embeds
# server/migrations/ at compile time. The desktop app's heavy dependencies
# (iced, dbus, ...) are never in this build's unit graph, so they cost
# nothing here; .dockerignore keeps the context small.

FROM rust:1-trixie AS builder
WORKDIR /src
COPY . .
# The cache mounts don't survive into the image layer, so the binary has to
# be copied out inside the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p askrypt-server \
    && mkdir -p /out \
    && cp target/release/askrypt-server /out/

FROM debian:trixie-slim
# The service user's home is the deployment directory, and it is the *same*
# path the compose file bind-mounts from the host — /home/askrypt-server/data
# and .../logs mean one thing whether you read them in a log line, in a
# backup command or in `ls` on the server.
#
# No ca-certificates needed: the Google ID-token verifier and the SMTP mailer
# both use rustls with webpki-roots compiled in. Switching either to
# native-tls would need ca-certificates and libssl installed here.
RUN useradd --system --uid 10001 --home-dir /home/askrypt-server askrypt \
    && mkdir -p /home/askrypt-server/data /home/askrypt-server/logs \
    && chown askrypt:askrypt /home/askrypt-server \
                             /home/askrypt-server/data /home/askrypt-server/logs \
    && chmod 755 /home/askrypt-server \
    && chmod 700 /home/askrypt-server/data /home/askrypt-server/logs
COPY --from=builder /out/askrypt-server /usr/local/bin/askrypt-server
COPY server/static /srv/askrypt/static
USER askrypt
WORKDIR /home/askrypt-server
ENV ASKRYPT_BIND=0.0.0.0:8080 \
    ASKRYPT_DATA_DIR=/home/askrypt-server/data \
    # The default (`server/static`) is relative to the working directory,
    # which holds no source tree.
    ASKRYPT_STATIC_DIR=/srv/askrypt/static \
    # This image is meant to sit behind the reverse proxy in
    # server/deploy/docker-compose.yml, which is the only route to the port.
    ASKRYPT_TRUST_PROXY=1 \
    ASKRYPT_HSTS=1 \
    ASKRYPT_LOG_FORMAT=json \
    # Daily files, two weeks kept. Both this and the data dir are set
    # explicitly rather than left to the WORKDIR-relative defaults, so moving
    # the working directory cannot quietly move the state; set it empty to log
    # only to stdout and let the container runtime collect it.
    ASKRYPT_LOG_DIR=/home/askrypt-server/logs \
    RUST_LOG=askrypt_server=info,info
# Which commit this image was built from. Declared here, at the end, so a
# fresh revision doesn't invalidate the cached build layers above; the server
# logs both at startup, so a container can be traced back to a commit without
# `docker inspect`. Left as "unknown" when built by hand.
ARG GIT_HASH=unknown
ARG GIT_COMMIT_MSG=unknown
ENV ASKRYPT_BUILD_REV=$GIT_HASH \
    ASKRYPT_BUILD_MSG=$GIT_COMMIT_MSG
LABEL org.opencontainers.image.title="askrypt-server" \
      org.opencontainers.image.revision="$GIT_HASH" \
      org.opencontainers.image.description="$GIT_COMMIT_MSG"
VOLUME ["/home/askrypt-server/data", "/home/askrypt-server/logs"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/askrypt-server"]
