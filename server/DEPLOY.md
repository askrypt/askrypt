# Deploying askrypt-server

The server stores accounts and **opaque encrypted vault files**. It never
sees security questions, answers, keys, or vault contents — a compromise
exposes encrypted blobs and account metadata, never plaintext. That property
is structural (the server never links `askrypt-core`), so hardening here is
about protecting accounts and availability, not vault secrets.

Everything ships in one binary: the website's templates, the migrations and
the API. The only loose files are the static assets in `server/static/` — a
stylesheet and a vendored copy of **htmx 2.0.10**, served at `/assets`. There
is no JavaScript toolchain anywhere in the build; `cargo build` produces the
whole product.

---

## 1. Prerequisites

- A TLS terminator in front. **This is required, not optional**: sessions are
  bearer tokens, and the web UI sets `Secure` cookies — without TLS, browsers
  will refuse to send them back and nobody will stay signed in. (Browsers
  make an exception for `localhost`, which is why `cargo run` works in
  development.) Do not expose the server's own port.
- A data directory on persistent storage. It holds `askrypt.db` (SQLite, WAL
  mode) and `vaults/<account-id>/<vault-id>.askrypt`.

---

## 2. Configuration

All settings are environment variables; all are optional.

| Variable | Default | Meaning |
|---|---|---|
| `ASKRYPT_BIND` | `127.0.0.1:8080` | Listen address. Keep it on loopback (or a private network) behind the proxy |
| `ASKRYPT_DATA_DIR` | `data` | SQLite db + vault blobs. Set an absolute path in production |
| `ASKRYPT_BACKEND` | `sqlite` | `sqlite` or `memory` (nothing persisted — dev only) |
| `ASKRYPT_STATIC_DIR` | `server/static` | Assets served at `/assets` (stylesheet + vendored htmx). The default is relative to the working directory |
| `ASKRYPT_GOOGLE_CLIENT_IDS` | *(empty)* | Comma-separated OAuth client ids accepted as ID-token audiences. Empty disables Google sign-in (501) |
| `ASKRYPT_TRUST_PROXY` | `false` | Believe `X-Real-IP` / `X-Forwarded-For`. **Only when the proxy is the sole route in** |
| `ASKRYPT_HSTS` | `false` | Send `Strict-Transport-Security`. Enable once TLS is confirmed |
| `ASKRYPT_REQUEST_TIMEOUT_SECS` | `60` | Handler timeout (`0` disables) |
| `ASKRYPT_MAX_CONCURRENT` | `256` | In-flight requests before shedding with 503 (`0` disables) |
| `ASKRYPT_MAX_BODY_BYTES` | `65536` | Body limit outside the vault routes |
| `ASKRYPT_ARGON2_PARALLELISM` | *(cpu count)* | Concurrent argon2 hashes. Each holds ~19 MiB; this is the memory ceiling under a login flood |
| `ASKRYPT_LOG_FORMAT` | `text` | `text` or `json` |
| `RUST_LOG` | `askrypt_server=debug,info` | Log filter. **Keep `askrypt_server` at `info` or lower** — the audit log rides that target |

### Sizing note

Peak argon2 memory is roughly `ASKRYPT_ARGON2_PARALLELISM × 19 MiB`. On a
small VPS, set it explicitly (e.g. `4`) rather than inheriting the CPU count.

---

## 3. Install

### Docker (recommended)

```sh
# From the repository root — the image builds the whole workspace.
docker compose -f server/deploy/docker-compose.yml up -d --build
```

Edit `server/deploy/Caddyfile` first and replace `askrypt.example.com` with
the real hostname. Caddy obtains certificates automatically. The server
container publishes no ports; only Caddy can reach it, which is what makes
`ASKRYPT_TRUST_PROXY=1` safe there.

To build the image alone:

```sh
docker build -f server/Dockerfile -t askrypt-server .
```

### systemd

```sh
cargo build --release -p askrypt-server
sudo useradd --system --home-dir /var/lib/askrypt askrypt
sudo install -m 755 target/release/askrypt-server /usr/local/bin/
sudo mkdir -p /usr/local/share/askrypt && sudo cp -r server/static /usr/local/share/askrypt/
sudo cp server/deploy/askrypt-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now askrypt-server
```

The unit runs sandboxed (`ProtectSystem=strict`, no capabilities, `UMask=0077`,
`StateDirectory=askrypt` at mode `0700`). Put Caddy or nginx in front; if
nginx, set both headers explicitly so the trusted hop is unambiguous:

```nginx
proxy_set_header X-Real-IP       $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;   # not $proxy_add_x_forwarded_for
```

Migrations run automatically at startup, so upgrades are: install the new
binary, `systemctl restart askrypt-server`.

---

## 4. What the server enforces

Applied to every response by `src/hardening.rs`:

- `Content-Security-Policy: default-src 'self'; script-src 'self'; …` — no
  `unsafe-inline`, no `unsafe-eval`, `frame-ancestors 'none'`. The website's
  pages are written to fit this, not the other way round.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, `Permissions-Policy`, COOP/CORP `same-origin`,
  and HSTS when enabled.
- `Cache-Control: no-store` on `/api/v1` and on every HTML page (vault
  downloads use `private, no-cache` so `ETag` revalidation still works;
  `/assets` caches normally).

The browser session:

- The web session cookie is `HttpOnly; Secure; SameSite=Lax; Path=/` and
  holds the same opaque token the API issues — one session model, so a
  browser shows up in `GET /api/v1/me/sessions` as "Web browser" and can be
  revoked from any device. Browser sessions last **7 days**; API sessions
  last 30.
- Every mutating form carries a CSRF token matching an `askrypt_csrf` cookie,
  with `Origin`/`Referer` checked as a backstop. This applies to cookie
  requests only — bearer requests are not CSRF-able.

Limits and backpressure:

- Body limits: 64 KiB by default, 10 MiB on the vault routes.
- 60 s handler timeout → 504 `timeout`. Slow *response bodies* are the
  proxy's job; set idle/response timeouts there.
- 256 in-flight requests → 503 `overloaded` with `Retry-After`. `/healthz` is
  never shed.
- 20 requests/minute per client on `/api/v1/auth/*` and on the email/password
  mutations → 429 `rate_limited` with `Retry-After`.
- Per account: 100 MiB total, 100 vaults, 10 MiB per file.

---

## 5. Audit log

Account-security events go to the `askrypt_server::audit` tracing target:
register (ok/denied), login (ok/failed with reason), Google sign-in
(ok/denied, distinguishing new accounts from newly linked ones), logout,
password set/changed, failed current-password re-auth, email change, session
revocation, and account deletion.

Each record carries the client IP (accurate only with `ASKRYPT_TRUST_PROXY`
correctly set), a truncated user agent, and the account id.

Deliberately absent: bearer tokens (sessions appear as the same SHA-256
digest the API exposes), passwords, vault bytes, and the email address on a
*failed* login — logging that would build a list of which addresses have
accounts.

With `ASKRYPT_LOG_FORMAT=json`, each event is one flat JSON object; filter on
`"target":"askrypt_server::audit"`.

---

## 6. Backup and restore

The live state is `<data>/askrypt.db` plus `<data>/vaults/`.

> **Never `cp` the live `askrypt.db`.** It runs in WAL mode, so the `.db`
> file on its own can be stale or torn.

```sh
server/deploy/backup.sh /var/backups/askrypt              # live snapshot
server/deploy/backup.sh /var/backups/askrypt --quiesce    # stops the service first
```

The script calls `askrypt-server backup <path>` (a `VACUUM INTO` snapshot,
safe against a running server) **before** archiving the blob directory, then
prunes snapshots older than `ASKRYPT_BACKUP_KEEP_DAYS` (default 30).

That order is deliberate. Uploads write vault bytes before their metadata
row, so a database-first snapshot can only ever capture a blob with no row —
an invisible orphan. The reverse order could capture a row with no bytes,
which reads back as a 500. Deletes invert the hazard, so no ordering is safe
against a concurrent delete: use `--quiesce` when an exact snapshot matters.
Without it, the inconsistency window is one HTTP request wide.

### Restore

```sh
systemctl stop askrypt-server
install -o askrypt -g askrypt -m 600 askrypt-20260804T020000Z.db /var/lib/askrypt/askrypt.db
rm -f /var/lib/askrypt/askrypt.db-wal /var/lib/askrypt/askrypt.db-shm
rm -rf /var/lib/askrypt/vaults
tar -C /var/lib/askrypt -xzf vaults-20260804T020000Z.tar.gz
chown -R askrypt:askrypt /var/lib/askrypt
systemctl start askrypt-server
```

An older database self-upgrades: migrations run on boot.

**Practise the restore.** A backup that has never been restored is a guess.

---

## 7. Deployment checklist

- [ ] TLS terminates in front; the server's own port is unreachable from
      outside. `curl https://host/healthz` answers `{"status":"ok"}`.
- [ ] `ASKRYPT_TRUST_PROXY=1` **only** with that first box ticked, and the
      proxy sets `X-Real-IP` / `X-Forwarded-For` to the observed address.
- [ ] `ASKRYPT_HSTS=1` once HTTPS is confirmed working (it commits browsers
      for a year).
- [ ] `ASKRYPT_DATA_DIR` is an absolute path on persistent storage, owned by
      the service user, mode `0700`.
- [ ] `ASKRYPT_GOOGLE_CLIENT_IDS` set if Google sign-in is wanted; otherwise
      confirm `/api/v1/auth/google` answers 501.
- [ ] `RUST_LOG` keeps `askrypt_server` at `info` or lower; logs are shipped
      somewhere durable.
- [ ] `backup.sh` runs on a timer and its output lands off-host.
- [ ] A restore has actually been performed into a scratch directory.
- [ ] `ASKRYPT_ARGON2_PARALLELISM` fits the box's RAM (~19 MiB each).
- [ ] Browser devtools show no CSP violations on the landing page.
- [ ] Response headers on a live request include `Content-Security-Policy`,
      `Strict-Transport-Security` and `X-Content-Type-Options`.

### Smoke test through the proxy

```sh
curl -si https://askrypt.example.com/healthz | head -20
curl -s  https://askrypt.example.com/api/v1/about
curl -si -X POST https://askrypt.example.com/api/v1/auth/register \
     -H 'content-type: application/json' \
     -d '{"email":"you@example.com","password":"correct horse battery"}'
```

Then confirm the audit log shows `register.ok` with the **real** client IP,
not the proxy's — if it shows the proxy's address, `ASKRYPT_TRUST_PROXY` is
off or the proxy isn't setting the headers.
