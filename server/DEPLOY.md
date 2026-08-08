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
| `ASKRYPT_LOG_DIR` | `logs` | Directory for the daily-rotated log files, written in addition to the console. **Empty disables file logging** — use that where journald or the container runtime already keeps stdout |
| `ASKRYPT_LOG_MAX_FILES` | `14` | Daily files kept; the oldest are deleted on rollover. `0` keeps every one — then rotate externally or the disk fills |
| `RUST_LOG` | `askrypt_server=debug,info` | Log filter. **Keep `askrypt_server` at `info` or lower** — the audit log rides that target |

### Email

| Variable | Default | Meaning |
|---|---|---|
| `ASKRYPT_SMTP_HOST` | *(empty)* | Relay host name. **Empty means nothing is delivered** — see the warning below |
| `ASKRYPT_SMTP_PORT` | *(per encryption)* | 587 for STARTTLS, 465 for implicit TLS, 25 for none |
| `ASKRYPT_SMTP_ENCRYPTION` | `starttls` | `starttls`, `tls` (implicit/SMTPS) or `none`. `none` only for a relay on localhost |
| `ASKRYPT_SMTP_FROM` | — | Envelope sender, e.g. `Askrypt <no-reply@example.com>`. Required once a host is set |
| `ASKRYPT_SMTP_USERNAME` | *(empty)* | Relay login. Set together with the password or not at all |
| `ASKRYPT_SMTP_PASSWORD` | *(empty)* | Relay password. Deliver it as a secret (a compose secret, or a `.env` beside the compose file) — never in a file that lands in git |
| `ASKRYPT_SMTP_TIMEOUT_SECS` | `10` | Per-operation SMTP network timeout |

> **Leaving `ASKRYPT_SMTP_HOST` unset is not "email disabled" — it is
> "email printed to the log."** The fallback mailer records each message and
> logs the recipient, subject *and full body*. Verification and reset bodies
> carry single-use tokens, so on a production box that turns your log
> aggregator into a credential store. Configure a relay, or make sure nothing
> ever asks the server to send.

Startup says which one is live — `INFO … smtp mailer enabled` with the relay,
mode and whether it authenticates, or:

```
WARN askrypt_server: no SMTP relay configured (ASKRYPT_SMTP_HOST unset);
     outgoing email will be LOGGED IN FULL instead of delivered — development only
```

Treat that warning as a deployment defect. A bad sender address or unusable
relay fails at startup, not on the first message; half-set credentials fail
`Config::from_env` before the server binds. The password is never logged — it
is redacted from every `Debug` rendering and from configuration errors.

### Sizing note

Peak argon2 memory is roughly `ASKRYPT_ARGON2_PARALLELISM × 19 MiB`. On a
small VPS, set it explicitly (e.g. `4`) rather than inheriting the CPU count.

---

## 3. Install

The supported deployment is the container. `server/deploy/docker-compose.yml`
brings up the server plus Caddy, which terminates TLS:

```sh
# From the repository root — the image builds the whole workspace.
docker compose -f server/deploy/docker-compose.yml up -d --build
```

Edit `server/deploy/Caddyfile` first and replace `askrypt.example.com` with
the real hostname. Caddy obtains certificates automatically. The server
container publishes no ports; only Caddy can reach it, which is what makes
`ASKRYPT_TRUST_PROXY=1` (baked into the image) safe there.

Two named volumes hold the state: `askrypt-data` at `/var/lib/askrypt` (the
database and the vault blobs) and `askrypt-logs` at `/var/log/askrypt`.

To build the image alone:

```sh
docker build -f server/Dockerfile -t askrypt-server .
```

Migrations run automatically at startup, so an upgrade is a rebuild:

```sh
docker compose -f server/deploy/docker-compose.yml up -d --build askrypt-server
```

### Another proxy in front

Caddy is a convenience, not a requirement — anything that terminates TLS
works, as long as it is the *only* route to the port. Set both client-address
headers explicitly so the trusted hop is unambiguous; with nginx:

```nginx
proxy_set_header X-Real-IP       $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;   # not $proxy_add_x_forwarded_for
```

---

## 4. What the server enforces

Applied to every response by `src/hardening.rs`:

- `Content-Security-Policy: default-src 'self'; script-src 'self'; …` — no
  `unsafe-inline`, no `unsafe-eval`, `frame-ancestors 'none'`. The website's
  pages are written to fit this, not the other way round.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`
  (**not** `no-referrer`, which would make browsers stamp same-origin form
  posts `Origin: null` and get them refused by the CSRF check),
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

### Where it lands

Every event goes to the console *and* to a file in `ASKRYPT_LOG_DIR`, named
`askrypt-server.<YYYY-MM-DD>.log`. A new file starts at each UTC midnight and
the oldest are removed once there are more than `ASKRYPT_LOG_MAX_FILES`;
nothing is compressed. Writes go through a background thread, so a slow disk
delays log lines rather than request handlers.

The directory is created at startup if missing. If it cannot be created or
written the server prints a warning to stderr and keeps serving with console
logging only — a broken log path never takes the service down. The image
points this at `/var/log/askrypt`, kept in the `askrypt-logs` volume; set
`ASKRYPT_LOG_DIR=` (empty) instead if you collect the container's stdout and
want no files at all.

Because the audit trail lives in these files, back them up (or ship them)
alongside the database if you need account-security history to survive the
host — the snapshot below does not archive them.

---

## 6. Backup and restore

The live state is `<data>/askrypt.db` plus `<data>/vaults/`.

> **Never `cp` the live `askrypt.db`.** It runs in WAL mode, so the `.db`
> file on its own can be stale or torn.

Take the database snapshot with the binary's own `backup` subcommand — a
`VACUUM INTO` copy, safe against a running server — and archive the blobs
afterwards:

```sh
COMPOSE="docker compose -f server/deploy/docker-compose.yml"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

# 1. database, written inside the data volume, then pulled out
$COMPOSE exec -T askrypt-server askrypt-server backup /var/lib/askrypt/snap-$STAMP.db
$COMPOSE cp askrypt-server:/var/lib/askrypt/snap-$STAMP.db askrypt-$STAMP.db
$COMPOSE exec -T askrypt-server rm /var/lib/askrypt/snap-$STAMP.db

# 2. then the blobs (--exclude drops the temp files an interrupted upload leaves)
$COMPOSE exec -T askrypt-server \
    tar -C /var/lib/askrypt --exclude='.*.tmp' -cz vaults > vaults-$STAMP.tar.gz
```

`exec -T` matters: without it compose allocates a TTY and the tar stream is
corrupted on its way to the file. Run this from cron, ship both files
off-host, and prune old ones there.

That order is deliberate. Uploads write vault bytes before their metadata
row, so a database-first snapshot can only ever capture a blob with no row —
an invisible orphan. The reverse order could capture a row with no bytes,
which reads back as a 500. Deletes invert the hazard, so no ordering is safe
against a concurrent delete. When an exact snapshot matters, stop the server
first and take it with a one-off container:

```sh
$COMPOSE stop askrypt-server
$COMPOSE run --rm -T askrypt-server backup /var/lib/askrypt/snap-$STAMP.db
# ... copy out and archive as above ...
$COMPOSE start askrypt-server
```

Without that, the inconsistency window is one HTTP request wide.

### Restore

Restoring writes into the data volume, so do it with a throwaway container
rather than through the (stopped) server. Check the volume's real name first
with `docker volume ls` — compose prefixes it with the project name, which
defaults to the compose file's directory (`deploy_askrypt-data`).

```sh
$COMPOSE stop askrypt-server
docker run --rm -v deploy_askrypt-data:/data -v "$PWD":/restore:ro debian:trixie-slim sh -c '
  set -e
  rm -f /data/askrypt.db /data/askrypt.db-wal /data/askrypt.db-shm
  rm -rf /data/vaults
  cp /restore/askrypt-20260804T020000Z.db /data/askrypt.db
  tar -C /data -xzf /restore/vaults-20260804T020000Z.tar.gz
  chown -R 10001:10001 /data && chmod 700 /data'
$COMPOSE start askrypt-server
```

The `-wal`/`-shm` files must go: they belong to the old database and SQLite
would try to replay them over the restored one. `10001` is the image's
`askrypt` uid. An older database self-upgrades: migrations run on boot.

**Practise the restore.** A backup that has never been restored is a guess.

---

## 7. Deployment checklist

- [ ] TLS terminates in front; the server's own port is unreachable from
      outside. `curl https://host/healthz` answers `{"status":"ok"}`.
- [ ] `ASKRYPT_TRUST_PROXY=1` **only** with that first box ticked, and the
      proxy sets `X-Real-IP` / `X-Forwarded-For` to the observed address.
- [ ] `ASKRYPT_HSTS=1` once HTTPS is confirmed working (it commits browsers
      for a year).
- [ ] `ASKRYPT_DATA_DIR` is an absolute path on persistent storage (the
      `askrypt-data` volume), owned by the service user, mode `0700`.
- [ ] `ASKRYPT_GOOGLE_CLIENT_IDS` set if Google sign-in is wanted; otherwise
      confirm `/api/v1/auth/google` answers 501.
- [ ] `ASKRYPT_SMTP_HOST` + `ASKRYPT_SMTP_FROM` set, and the startup log says
      `smtp mailer enabled`. Without them the server logs message bodies —
      tokens included — instead of sending them.
- [ ] `ASKRYPT_SMTP_PASSWORD` comes from a secret or a `.env` beside the
      compose file, not from a file under version control.
- [ ] `RUST_LOG` keeps `askrypt_server` at `info` or lower; logs are shipped
      somewhere durable.
- [ ] The backup commands above run on a timer and their output lands
      off-host.
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
