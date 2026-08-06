# syntax=docker/dockerfile:1.7
#
# Build from the *repository root*, not from server/:
#     docker build -f server/Dockerfile -t askrypt-server .
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
# No ca-certificates needed: the Google ID-token verifier and the SMTP mailer
# both use rustls with webpki-roots compiled in. Switching either to
# native-tls would need ca-certificates and libssl installed here.
RUN useradd --system --uid 10001 --home-dir /var/lib/askrypt askrypt \
    && mkdir -p /var/lib/askrypt /var/log/askrypt \
    && chown askrypt:askrypt /var/lib/askrypt /var/log/askrypt \
    && chmod 700 /var/lib/askrypt /var/log/askrypt
COPY --from=builder /out/askrypt-server /usr/local/bin/askrypt-server
COPY server/static /srv/askrypt/static
USER askrypt
ENV ASKRYPT_BIND=0.0.0.0:8080 \
    ASKRYPT_DATA_DIR=/var/lib/askrypt \
    # The default is relative to the working directory, which does not exist
    # in this image.
    ASKRYPT_STATIC_DIR=/srv/askrypt/static \
    # This image is meant to sit behind the reverse proxy in
    # server/deploy/docker-compose.yml, which is the only route to the port.
    ASKRYPT_TRUST_PROXY=1 \
    ASKRYPT_HSTS=1 \
    ASKRYPT_LOG_FORMAT=json \
    # Daily files, two weeks kept. The default is relative to the working
    # directory, which this image's user cannot write to; set it empty to log
    # only to stdout and let the container runtime collect it.
    ASKRYPT_LOG_DIR=/var/log/askrypt \
    RUST_LOG=askrypt_server=info,info
VOLUME ["/var/lib/askrypt", "/var/log/askrypt"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/askrypt-server"]
