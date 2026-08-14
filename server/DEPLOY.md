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
  mode) and `vaults/<account-id>/<vault-id>.askrypt`, with the generations
  those files replaced alongside them in
  `vaults/<account-id>/versions/<version-id>.askrypt`.
- On the server: docker (with the compose plugin), and a user in the `docker`
  group. On your machine: docker to build the image and
  [spot](https://github.com/umputun/spot) to ship it — see §3.

---

## 2. Configuration

All settings are environment variables; all are optional.

| Variable | Default | Meaning |
|---|---|---|
| `ASKRYPT_BIND` | `127.0.0.1:8080` | Listen address. Keep it on loopback (or a private network) behind the proxy |
| `ASKRYPT_DOMAIN` | *(empty)* | The public host name. Caddy requests its certificate for this; the server only *reports* it, in the startup email — no routing, no redirect, no cookie domain depends on it |
| `ASKRYPT_ADMIN_EMAIL` | *(the SMTP sender)* | Recipient of the startup notice. Unset sends it to `ASKRYPT_SMTP_FROM`, which is usually a mailbox you already own |
| `ASKRYPT_DATA_DIR` | `data` | SQLite db + vault blobs. Set an absolute path in production |
| `ASKRYPT_BACKEND` | `sqlite` | `sqlite` or `memory` (nothing persisted — dev only) |
| `ASKRYPT_STATIC_DIR` | `server/static` | Assets served at `/assets` (stylesheet + vendored htmx). The default is relative to the working directory |
| `ASKRYPT_GOOGLE_CLIENT_IDS` | *(empty)* | Comma-separated OAuth client ids accepted as ID-token audiences. Empty disables Google sign-in (501). **The first is also the website's own "Sign in with Google" button**, so it must be a *Web application* client whose authorized JavaScript origins include `https://<your domain>`; list the native ones after it |
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

### Bot protection (reCAPTCHA v3)

| Variable | Default | Meaning |
|---|---|---|
| `ASKRYPT_RECAPTCHA_SITE_KEY` | *(empty)* | Public **v3** site key from the [reCAPTCHA admin console](https://www.google.com/recaptcha/admin). Empty = no captcha |
| `ASKRYPT_RECAPTCHA_SECRET` | — | The matching secret. Required once a site key is set — startup fails without it, rather than serving a captcha that verifies nothing |
| `ASKRYPT_RECAPTCHA_MIN_SCORE` | `0.5` | Lowest accepted score, `0.0` (bot) to `1.0` (human). Google's own suggested cut is `0.5` |

Register the site as **reCAPTCHA v3** and list your domain; v2 keys will not
work. Three consequences worth knowing before you turn this on:

- It covers the **website's** `/login` and `/register` only. The JSON API at
  `/api/v1/auth` is deliberately untouched — the desktop and mobile clients
  cannot mint a token, and the desktop signs in through the browser anyway.
- Those two pages then **require JavaScript**. A v3 token is minted in the
  page; without scripts the form submits an empty one and is refused with a
  message saying so. The rest of the site still works with scripts off.
- Those two pages send a **widened Content-Security-Policy** naming
  `www.google.com` and `www.gstatic.com` (and allowing inline styles, for
  reCAPTCHA's badge). Every other route keeps the strict policy byte for byte.

If Google is unreachable or the secret is wrong, sign-in **fails closed** —
nobody gets in, and the log carries `captcha verification unavailable` at
`error`. Unset the site key to turn the whole thing off again.

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

#### The startup notice

With a relay configured, every start sends one email — to `ASKRYPT_ADMIN_EMAIL`
if set, otherwise to the `ASKRYPT_SMTP_FROM` address:

```
Subject: Askrypt server started on askrypt.example.com

askrypt-server has started.

Domain:      askrypt.example.com
Listening:   0.0.0.0:8080
Backend:     sqlite
Data dir:    /home/askrypt-server/data
Build:       9f2c1ab
Server time: 2026-08-13 09:12:44 +00:00 (09:12:44 UTC)

Memory:      4.0 GiB used of 16.0 GiB (12.0 GiB free)
Disk:        12.0 GiB used of 40.0 GiB (26.0 GiB free) on the data directory's filesystem
```

Read it as a **restart alarm**: a deploy explains one, and anything else — an
OOM kill, a host reboot, a container the supervisor is recycling — is a mail
you did not expect. The two capacity figures are there so the mail that arrives
at 3 a.m. already says whether the box is out of room. In a container the
memory figures are the *host's* (`/proc/meminfo` does not reflect a cgroup
limit); the disk figures are the real ones, since the data directory is a bind
mount from the host.

It carries no account data, no counts and no secrets, so a shared operations
mailbox is a fine destination. It cannot delay or fail startup — it is sent
after the socket is bound, on its own task, and a refused delivery is logged
at `warn` and forgotten. `ASKRYPT_SMTP_HOST` unset means no notice at all
rather than one printed to the log.

### Sizing note

Peak argon2 memory is roughly `ASKRYPT_ARGON2_PARALLELISM × 19 MiB`. On a
small VPS, set it explicitly (e.g. `4`) rather than inheriting the CPU count.

---

## 3. Install

The supported deployment is the container, built **locally** and pushed to the
server as an image tarball by [spot](https://github.com/umputun/spot). The
server therefore needs nothing but docker — no rust toolchain, no source
checkout, no registry account.

The deployment directory on the server is **`/home/askrypt-server`**, and it
holds everything: the compose file, the Caddyfile, the `.env`, and the data
and log directories themselves.

Five files in `server/deploy/` do it:

| File | Role |
|---|---|
| `docker-build.sh` | Builds `askrypt-server:latest` from the repo root, embedding the git revision |
| `spot.yml` | The playbook: build → ship → load → `run.sh` → verify |
| `deploy.sh` | `./deploy.sh dev\|prod [spot flags]`, with a confirmation prompt for prod |
| `run.sh` | Prepares `data/`+`logs/` and runs `docker compose up -d`; what spot calls, and what to type by hand |
| `docker-compose.yml` + `Caddyfile` | Uploaded to `/home/askrypt-server` and run there |

### One-time setup

1. Install spot locally (`brew install umputun/apps/spot`) and make sure SSH
   key access to the host works.
2. Put the real host names in `spot.yml` under `targets:` — placeholders ship
   in git.
3. On the server, create `/home/askrypt-server/.env` from `env.example`:

   ```sh
   install -D -m 600 env.example /home/askrypt-server/.env    # then edit it
   ```

   `ASKRYPT_DOMAIN` is required — Caddy's site address is `{$ASKRYPT_DOMAIN}`,
   so the checked-in `Caddyfile` carries no hostname of its own and can be
   overwritten from git on every deploy. The SMTP settings belong here too;
   the deploy never uploads or reads this file, it only checks that it exists.

### Deploying

```sh
cd server/deploy
./deploy.sh dev              # or prod, which asks for confirmation first
./deploy.sh dev --dry -v     # extra flags go straight to spot
```

The playbook checks the server's `.env` first (a missing one should not cost a
release build), then builds the image, `docker save | gzip`s it, uploads it
along with the compose file, the Caddyfile and `run.sh`, loads it, runs
`run.sh`, and waits for the container to be running **and** for `/healthz` to
answer through the compose network before printing the last 20 log lines.
Migrations run at startup, so an upgrade is just another deploy.

The image is built for the local architecture; if the server's differs, build
with `PLATFORM=linux/amd64` (slow, emulated) or move the build to that arch.

Every deploy logs which commit is running, from build args baked into the
image by `docker-build.sh`:

```
INFO askrypt_server: build revision=03f19d1 commit="feat(desktop): …" version=0.1.0
```

The same values are on the image as `org.opencontainers.image.revision` and
`…description`.

### The first administrator

**Register your own account before you tell anyone else the address.** The
first account created on a server is granted the `ADMIN` role automatically,
and that is the only automatic grant there is — a later registration is never
promoted, not even if every administrator is later deleted. Whoever registers
first gets the Users page at `/admin/users`, from which they can suspend,
promote, delete accounts and move them on and off the paid storage tier.

If a server somehow ends up with no administrator (two people registering in
the same instant, or a hand-edited database), grant the role from a shell on
the host:

```sh
docker compose exec askrypt askrypt-server grant-admin you@example.com
```

It needs `ASKRYPT_BACKEND=sqlite` and an account that already exists.

**Upgrading an existing deployment:** this feature added columns and tables to
`migrations/0002_auth.sql` rather than a new numbered migration, so a database
created before it **will not** pick them up. Back it up, delete it, and let the
server recreate it — accounts and vaults are lost, so on a server with real
data, don't upgrade past this point without a plan for it. The same applies to
the `PAYMENT_USER` role, which was added to that same script later: `sqlx`
checksums the migrations it applied and refuses to run against a database that
saw the earlier version, so the server will fail to start rather than start
without it.

### The paid storage tier

Every account gets 1 MiB of vault storage. Granting it the `PAYMENT_USER` role
from the Users page raises that to 100 MiB and changes nothing else — the role
carries no other privilege. Notes for whoever operates this:

- **The quota is checked on writes only.** An account over its limit (because
  the role was taken away, or because it was already storing more) keeps full
  access to what it has: listing, downloading and deleting all work. It simply
  cannot upload a new file or grow an existing one until it is back under.
- **Version history shares the same allowance**, so a standard-tier account
  keeps fewer generations than a paid one. Nothing is ever refused because of
  history — the oldest generations are dropped instead.
- There is no billing here. The role is the switch; collecting the money and
  granting it are yours to connect.

### State

The server's own state is two **host directories**, bind-mounted into the
container at the very same paths:

| Path (host *and* container) | Holds |
|---|---|
| `/home/askrypt-server/data` | `askrypt.db` and `vaults/` — the whole thing |
| `/home/askrypt-server/logs` | The daily log files |

Both belong to uid `10001` (the image's `askrypt` user) and are mode `0700`;
`run.sh` creates them that way and repairs the ownership if it is wrong. That
is not cosmetic — a bind mount keeps the host directory's ownership, where a
named volume would have inherited the image's, so a `data/` owned by root
means a server that cannot open its database.

Caddy keeps three named volumes, prefixed with the compose project name, which
is pinned to `askrypt` in the compose file so it does not follow the
directory: `askrypt_caddy-data` (**the certificates**), `askrypt_caddy-config`
and `askrypt_caddy-logs`.

Everything else in `/home/askrypt-server` is disposable: `docker-compose.yml`,
`Caddyfile` and `run.sh` are overwritten from git on every deploy, and the
image tarball is deleted once loaded. What must survive a rebuild of the host
is `.env`, `data/`, `logs/`, and Caddy's certificate volume.

### Running it by hand

`run.sh` is the way in — it prepares those two directories before starting
anything, which a bare `docker compose up` does not. The compose file has no
`build:` section, so build the image first; the same stack then runs anywhere,
including locally, where the bind mounts land in `server/deploy/` instead
(both are gitignored):

```sh
./server/deploy/docker-build.sh
ASKRYPT_DOMAIN=askrypt.example.com sudo -E ./server/deploy/run.sh
```

`sudo` only because of the `chown` to uid 10001; on the server spot already
runs as root. Once the directories exist and are owned correctly, ordinary
`docker compose -f /home/askrypt-server/docker-compose.yml <cmd>` works for
everything else (`logs -f`, `restart`, `down`).

Or just the image, without compose:

```sh
docker build -f server/Dockerfile -t askrypt-server .
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
  pages are written to fit this, not the other way round. `/login` and
  `/register` send a widened policy when reCAPTCHA or the Google sign-in
  button is configured — the vendor's hosts plus `'unsafe-inline'` in
  `style-src`, since both widgets style themselves in the page; `script-src`
  never widens.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`
  (**not** `no-referrer`, which would make browsers stamp same-origin form
  posts `Origin: null` and get them refused by the CSRF check),
  `X-Frame-Options: DENY`, `Permissions-Policy`, COOP/CORP `same-origin`,
  and HSTS when enabled.
- `Cache-Control: no-store` on `/api/v1` and on every HTML page (vault
  downloads use `private, no-cache` so `ETag` revalidation still works;
  `/assets` caches normally).

Accounts and roles:

- The `roles` table is seeded by the migration with two roles. `ADMIN` is
  granted automatically to the first account registered and otherwise only
  from the Users page or `grant-admin`. `PAYMENT_USER` is granted only from
  the Users page, is never automatic, and raises the storage quota — it
  confers nothing else.
- A suspended account (`banned_at` set) cannot sign in by password or by
  Google, and its existing sessions stop resolving on the very next request —
  bearer tokens and browser cookies alike. Its stored vaults are kept
  untouched, so lifting the suspension restores them.
- The server always keeps at least one administrator, and an administrator
  cannot suspend, demote or delete their own account from the Users page.

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
  mutations → 429 `rate_limited` with `Retry-After`. The admin actions share
  that second bucket.
- Per account: 100 vaults, 10 MiB per file, and 1 MiB of total storage — or
  100 MiB with the `PAYMENT_USER` role. Each vault also
  keeps the 5 generations its last saves replaced; those bytes are charged to
  the same allowance, and the oldest are dropped to make room rather than a
  save being refused. The quota is enforced on writes only.

---

## 5. Audit log

Account-security events go to the `askrypt_server::audit` tracing target:
register (ok/denied), login (ok/failed with reason), Google sign-in
(ok/denied, distinguishing new accounts from newly linked ones), logout,
password set/changed, failed current-password re-auth, email change, session
revocation, and account deletion. Administrative actions are recorded too:
`account.banned` / `account.unbanned`, `role.granted` / `role.revoked`, and
`account.deleted_by_admin`.

Each record carries the client IP (accurate only with `ASKRYPT_TRUST_PROXY`
correctly set), a truncated user agent, and the account id. On the
administrative events the account id is the account acted *on*, and the
administrator who did it is named in `detail` — so the log answers both
halves of "who did this to whom".

Deliberately absent: bearer tokens (sessions appear as the same SHA-256
digest the API exposes), passwords, vault bytes, and the email address on a
*failed* login — logging that would build a list of which addresses have
accounts.

With `ASKRYPT_LOG_FORMAT=json`, each event is one flat JSON object; filter on
`"target":"askrypt_server::audit"`.

### Vault file operations

Stored files have their own trail, on the `askrypt_server::vaults` target and
in the same files. Every operation is one line with an `op` field:
`vault.created`, `vault.overwritten`, `vault.downloaded`, `vault.renamed`,
`vault.deleted`, `vault.version.archived`, `vault.version.downloaded`,
`vault.version.restored`, `vault.versions.trimmed` at `info`, and
`vault.listed` at `debug`. Each carries `account_id`, `vault_id` (plus
`version_id` where one applies) and a byte count.

**Identifiers only.** The file *name* is never logged — it is text the account
holder typed, and it usually says what the vault is for. Neither is the ETag,
which is a hash of the stored bytes: it would let anyone reading the logs tell
when two files are identical, or when a save put back an earlier state,
without decrypting anything. The bytes and the file's write stamp
(machine name, save time) stay out for the same reason. So the log answers
"what happened to which file, and when", and nothing about what the file is.

`vault.downloaded` appears only when bytes actually leave the server: a
conditional request answered `304 Not Modified` logs nothing, and restoring an
old generation reads it internally without counting as a download.

### Where it lands

Every event goes to the console *and* to a file in `ASKRYPT_LOG_DIR`, named
`askrypt-server.<YYYY-MM-DD>.log`. A new file starts at each UTC midnight and
the oldest are removed once there are more than `ASKRYPT_LOG_MAX_FILES`;
nothing is compressed. Writes go through a background thread, so a slow disk
delays log lines rather than request handlers.

The directory is created at startup if missing. If it cannot be created or
written the server prints a warning to stderr and keeps serving with console
logging only — a broken log path never takes the service down. The image
points this at `/home/askrypt-server/logs`, which is bind-mounted from the
host directory of the same name — so `tail -f
/home/askrypt-server/logs/askrypt-server.$(date -u +%F).log` on the server
needs no container at all. Set `ASKRYPT_LOG_DIR=` (empty) instead if you
collect the container's stdout and want no files.

Because the audit trail lives in these files, back them up (or ship them)
alongside the database if you need account-security history to survive the
host — the snapshot below does not archive them.

---

## 6. Backup and restore

The live state is `<data>/askrypt.db` plus `<data>/vaults/` — which includes
each account's `versions/` subdirectory, the generations their saves replaced.
Keep those: a restore that drops them throws away the recovery path a user
reaches for after a bad save.

> **Never `cp` the live `askrypt.db`.** It runs in WAL mode, so the `.db`
> file on its own can be stale or torn.

Take the database snapshot with the binary's own `backup` subcommand — a
`VACUUM INTO` copy, safe against a running server — and archive the blobs
afterwards:

Run these **on the server**, where the data directory is:

```sh
COMPOSE="docker compose -f /home/askrypt-server/docker-compose.yml"
DATA=/home/askrypt-server/data
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

# 1. database, written into the data directory by the running server, then
#    moved out of it — the path is the same on both sides of the mount
$COMPOSE exec -T askrypt-server askrypt-server backup $DATA/snap-$STAMP.db
mv $DATA/snap-$STAMP.db askrypt-$STAMP.db

# 2. then the blobs, straight off the host (--exclude drops the temp files an
#    interrupted upload leaves)
tar -C $DATA --exclude='.*.tmp' -cz vaults > vaults-$STAMP.tar.gz
```

`exec -T` matters: without it compose allocates a TTY, which garbles the
subcommand's output. Run this from cron, ship both files off-host, and prune
old ones there.

That order is deliberate. Uploads write vault bytes before their metadata
row, so a database-first snapshot can only ever capture a blob with no row —
an invisible orphan. The reverse order could capture a row with no bytes,
which reads back as a 500. Deletes invert the hazard, so no ordering is safe
against a concurrent delete. When an exact snapshot matters, stop the server
first and take it with a one-off container:

```sh
$COMPOSE stop askrypt-server
$COMPOSE run --rm -T askrypt-server backup $DATA/snap-$STAMP.db
# ... move out and archive as above ...
$COMPOSE start askrypt-server
```

Without that, the inconsistency window is one HTTP request wide.

### Restore

The data directory is on the host, so this is plain file work with the server
stopped — no throwaway container:

```sh
$COMPOSE stop askrypt-server
rm -f  $DATA/askrypt.db $DATA/askrypt.db-wal $DATA/askrypt.db-shm
rm -rf $DATA/vaults
cp askrypt-20260804T020000Z.db $DATA/askrypt.db
tar -C $DATA -xzf vaults-20260804T020000Z.tar.gz
chown -R 10001:10001 $DATA && chmod 700 $DATA
$COMPOSE start askrypt-server
```

The `-wal`/`-shm` files must go: they belong to the old database and SQLite
would try to replay them over the restored one. The final `chown` is not
optional — restored files carry the uid of whoever unpacked them, and `10001`
is the image's `askrypt` uid (`run.sh` would repair it on the next deploy, but
the server starts before that). An older database self-upgrades: migrations
run on boot.

**Practise the restore.** A backup that has never been restored is a guess.

### Upgrading from the old volume layout

A server deployed before this directory move keeps its state in the
`askrypt_askrypt-data` / `askrypt_askrypt-logs` named volumes, which nothing
reads any more — deploying over it would come up with an empty database. Move
it across once, with the stack stopped, **before** the first deploy:

```sh
docker compose -f /opt/askrypt/docker-compose.yml down
mkdir -p /home/askrypt-server/data /home/askrypt-server/logs
docker run --rm -v askrypt_askrypt-data:/from -v /home/askrypt-server/data:/to \
    debian:trixie-slim sh -c 'cp -a /from/. /to/ && chown -R 10001:10001 /to && chmod 700 /to'
mv /opt/askrypt/.env /home/askrypt-server/.env
```

Same command with `askrypt_askrypt-logs` → `logs/` if the old log files are
worth keeping (the audit trail lives in them). Caddy's volumes are untouched
by all this, so the certificates carry over on their own. Then deploy, confirm
`/home/askrypt-server/data/askrypt.db` is there and that an existing account
can still sign in, and only afterwards remove the old volumes:

```sh
docker volume rm askrypt_askrypt-data askrypt_askrypt-logs
```

---

## 7. Deployment checklist

- [ ] TLS terminates in front; the server's own port is unreachable from
      outside. `curl https://host/healthz` answers `{"status":"ok"}`.
- [ ] `ASKRYPT_TRUST_PROXY=1` **only** with that first box ticked, and the
      proxy sets `X-Real-IP` / `X-Forwarded-For` to the observed address.
- [ ] `ASKRYPT_HSTS=1` once HTTPS is confirmed working (it commits browsers
      for a year).
- [ ] `ASKRYPT_DATA_DIR` is an absolute path on persistent storage
      (`/home/askrypt-server/data`, bind-mounted from the host), owned by uid
      `10001`, mode `0700`.
- [ ] `ASKRYPT_GOOGLE_CLIENT_IDS` set if Google sign-in is wanted; otherwise
      confirm `/api/v1/auth/google` answers 501. For the *website's* button,
      check the id the startup log prints as `website_button=` is your **Web
      application** client, with `https://<your domain>` among its authorized
      JavaScript origins — it is the first of the list, and a native client id
      there renders a button Google itself refuses.
- [ ] `ASKRYPT_RECAPTCHA_SITE_KEY` + `ASKRYPT_RECAPTCHA_SECRET` set if the
      auth forms should be captcha'd, the key is a **v3** one registered for
      this domain, and the startup log says `recaptcha enabled`. Then sign in
      once from a real browser — a wrong secret fails closed and locks
      everyone out of the website.
- [ ] `ASKRYPT_SMTP_HOST` + `ASKRYPT_SMTP_FROM` set, and the startup log says
      `smtp mailer enabled`. Without them the server logs message bodies —
      tokens included — instead of sending them.
- [ ] `ASKRYPT_SMTP_PASSWORD` comes from `/home/askrypt-server/.env` (mode
      `0600`), not from a file under version control.
- [ ] The **startup email arrived** after the first deploy, at
      `ASKRYPT_ADMIN_EMAIL` (or the sender address), and names the right
      domain. It is the cheapest end-to-end proof the relay works — and from
      then on, every one you did not expect is a restart worth explaining.
- [ ] `ASKRYPT_DOMAIN` in that `.env` is the real hostname, and its DNS A/AAAA
      record already points here — Caddy cannot get a certificate otherwise.
- [ ] `spot.yml`'s `targets:` hold the real hosts, and `./deploy.sh <target>
      --dry` runs clean before the first real deploy.
- [ ] `RUST_LOG` keeps `askrypt_server` at `info` or lower; logs are shipped
      somewhere durable.
- [ ] The backup commands above run on a timer and their output lands
      off-host.
- [ ] A restore has actually been performed into a scratch directory.
- [ ] `ASKRYPT_ARGON2_PARALLELISM` fits the box's RAM (~19 MiB each).
- [ ] **You registered the first account**, and `/admin/users` loads for it —
      whoever registers first is the administrator, and there is no second
      chance at it short of `grant-admin`.
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
