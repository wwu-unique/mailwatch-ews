# mailwatch-ews

A real-time EWS mailbox collector, archive and lightweight web workbench.

Built for mailboxes whose server keeps **IMAP / POP3 / SMTP blocked** while
**EWS (Exchange Web Services) over HTTPS** stays up — a common setup on
corporate Exchange 2013/2016/2019 deployments. The service connects over
EWS, keeps a *streaming subscription* for push-style realtime updates with a
periodic incremental fallback, stores every message it sees and exposes a
small, read-mostly HTTP API plus a single-page web UI (login, search, read,
attachments, compose/reply).

> This is the generic/open-source packaging of a mailbox workbench. Internal
> dashboards, ops board and panel synchronization are **not** part of this
> repository — only the mailbox service itself (collect / store / view /
> send).

## Features

- **EWS realtime ingest** — streaming subscription push notifications,
  automatic re-subscribe, 20-minute stream cycles
- **Fallback incremental sync** every 5 minutes (configurable) using
  change-key / sync state, surviving short outages
- **Initial backfill** of existing inbox contents on first run
- **Content-addressed archive** — raw MIME stored as `.eml.gz`, all
  attachments stored by SHA-256, deduped across messages
- **PostgreSQL storage** for metadata, full bodies, sync state and logs,
  with `pg_trgm` fuzzy search on subject / body / sender
- **Storage quota** with automatic oldest-first cleanup (default 100 GiB
  logical quota, cleaning down to 95 GiB), orphan-file sweeping and
  reference-safe deletion of deduped blobs
- **Web UI** — single `index.html`, no CDN/external assets: login,
  summary bar, paginated mailbox list with search, server-side bodies
  rendered in a sandboxed iframe, attachment download, inline image
  preview, compose / reply / dry-run sending
- **Read-only-friendly API** with token or user/password authentication
  (`X-Panel-Token` header)

## Protocol requirements

The whole design assumes the classic enterprise lock-down pattern:

| Protocol | Ports | Status in target environments |
|---|---|---|
| OWA / EWS / ActiveSync / Autodiscover | 443 | **works — only data channel used** |
| IMAP / POP3 / SMTP submission | 143/993/110/995/465/587 | usually blocked upstream |
| SMTP inbound (MX) | 25 | open (receive path) |
| SMTP AUTH sending | 25 | often rejected by mail gateway |

If your server offers IMAP cleanly, you arguably don't need this service.
If it doesn't, this is your reading tool.

## Architecture

```text
┌────────────── mailwatch-ews (single python process) ─────────────┐
│  exchangelib ─► EWS :443 (NTLM)                                  │
│   ├── streaming subscription       (push rows into event_log)    │
│   └── incremental sync every N s   (fallback + backfill)          │
│  storage                                                          │
│   ├── Postgres   messages / attachments / meta / ingest_log /     │
│   │              event_log                                        │
│   └── ../data/archive                                             │
│        ├── mime/YYYY/MM/<sha256>.eml.gz                           │
│        └── attachments/<sha2>/<sha256>  (deduped)                 │
│  HTTP API  :18661  JSON + static index.html                       │
│  cleaner    storage quota enforcement every 60 s                  │
└───────────────────────────────────────────────────────────────────┘
```

## Quick start (Docker Compose, one command)

```bash
git clone <this-repo>
cd mailwatch-ews
cp .env.example .env
$EDITOR .env          # fill mailbox, UI login and database password
docker compose up -d --build
```

Then open `http://localhost:18661/` (`MAIL_PORT`), log in with
`PANEL_USER` / `PANEL_PASSWORD`.

The compose stack runs two containers:

- `mail` — the service (exposes the configured port)
- `db` — PostgreSQL 18 with its own volume

All mail metadata lives in the `mailwatch` database; raw MIME and
attachments live in `./data/archive` (bind-mounted `./data`).

## Configuration

Configuration is resolved from an optional JSON file plus environment
overrides, in that order:

```json5
// /app/config.json (set MAILWATCH_CONFIG=/path/to/config.json to relocate)
{
  "server":   "mail.example.com",     // EWS host, https only
  "username": "DOMAIN\\user",         // NTLM login
  "password": "…",
  "mailbox":  "user@example.com"      // primary SMTP address
}
```

Everything above can be provided with environment variables instead:

| Variable | Meaning |
|---|---|
| `MAILWATCH_EWS_SERVER` | Exchange host serving EWS over https |
| `MAILWATCH_EWS_USERNAME` | NTLM user, `DOMAIN\user` |
| `MAILWATCH_EWS_PASSWORD` | NTLM password |
| `MAILWATCH_EWS_MAILBOX` | primary SMTP mailbox address |
| `MAILWATCH_EWS_BUILD` | optional server build hint, e.g. `15.2.2562` (Exchange 2019) |
| `MAILWATCH_EWS_API_PORT` | HTTP API port, default `18661` |
| `MAILWATCH_EWS_API_HOST` | bind address, default `127.0.0.1` (compose sets `0.0.0.0`) |
| `MAILWATCH_EWS_DIR` | working dir, default `/app` |
| `MAILWATCH_CONFIG` | path to config JSON, default `/app/config.json` |
| `MAILWATCH_PG_DSN` | PostgreSQL connection string (or `pg.env` file next to the code) |
| `MAILWATCH_EWS_SYNC_INTERVAL` | fallback sync period in seconds, default `300` |
| `MAILWATCH_EWS_STREAM_TIMEOUT` | streaming subscription minutes, default `20` |
| `MAILWATCH_EWS_BACKFILL` | `1` = ingest existing inbox on first start |
| `MAILWATCH_EWS_LOG_LEVEL` | log level, default `INFO` |
| `MAILWATCH_MIN_KEEP_MESSAGES` | minimum messages the cleaner must keep, default `1` |
| `MAILWATCH_CLEANUP_BATCH` | max rows deleted per cleanup batch |
| `MAILWATCH_PANEL_USER` / `MAILWATCH_PANEL_PASSWORD` | UI/API login |
| `MAILWATCH_PANEL_TOKEN` | static API token (alternative to user/password) |
| `MAILWATCH_PANEL_SESSION_TTL` | session lifetime in seconds, default 12 h |
| `MAILWATCH_MAX_STORAGE_BYTES` | logical content quota, default `100G` |
| `MAILWATCH_STORAGE_TARGET_BYTES` | cleanup target below quota, default `95G` |
| `MAILWATCH_CLEANUP_INTERVAL` | cleaner period in seconds, default `60` |

### First run

On a fresh deployment the service:

1. connects to EWS, backfills the existing inbox (one pass, ~1-2 s per
   message depending on attachments),
2. then performs a *sync-state anchoring* walk (`prime_sync_state`) which
   replays the folder once to obtain the EWS change watermark — expect
   roughly the same order of time as the backfill again for large
   mailboxes (hundreds of round-trips),
3. only afterwards starts the streaming subscription, the incremental
   sync fallback and the storage cleaner (quota metrics stay at their
   initial values until then).

All three later stages reuse the same code paths as the reference
production deployment; nothing is realm-specific.

### Storage quota semantics

When disk+DB usage counts up to `MAILWATCH_MAX_STORAGE_BYTES`, the cleaner
deletes the oldest messages in batches until usage is back at
`MAILWATCH_STORAGE_TARGET_BYTES` to avoid a thrash loop. Database rows go
first; content-addressed blobs are removed only when no message or
attachment references them. Cleanups run at startup and every
`MAILWATCH_CLEANUP_INTERVAL` seconds and are reported on `/api/summary`
under `storage_*` / `last_cleanup*`.

## HTTP API

All endpoints answer JSON unless stated otherwise. When authentication is
configured, requests must send `X-Panel-Token: <session-or-token>` or
`?token=`.

| Method | Path | Description |
|---|---|---|
| POST | `/api/login` | `{username, password}` → `{ok, token, expires_in}` |
| POST | `/api/logout` | drop current session |
| GET | `/` `/health` `/api/health` | summary + sync/stream/storage state |
| GET | `/api/summary` | mailbox totals, unread, newest message, quota use |
| GET | `/api/mails?limit&offset&q` | paginated list, `q` = full-text search |
| GET | `/api/mail/<key>` | full message: headers, bodies, attachment list |
| GET | `/api/att/<key>/<attid>` | download attachment |
| GET | `/api/img/<key>/<attid>` | inline image with friendly disposition |
| GET | `/api/mime/<key>` | raw archived `.eml.gz` content |
| GET | `/api/tags` | distinct message categories |
| GET | `/api/log?limit` | ingest log tail |
| POST | `/api/mail/<key>/read` | `{read: true|false}` mark one |
| POST | `/api/mails/read` | mark all read |
| POST | `/api/send` | compose / reply / reply_all, supports `dry_run` |

## Security notes

- The Docker image runs as root inside the container because the archive
  paths and the DSN file rely on `0600/0700` file modes as their primary
  guard (the upstream deployment kept this behavior on host supervision).
  Mount `/app/data` on a host path with restrictive permissions.
- The web UI renders HTML bodies inside a **sandboxed iframe**
  (`sandbox=""`), so mail-body scripts cannot reach the app's origin.
- Set `PANEL_USER`/`PANEL_PASSWORD` (or `PANEL_TOKEN`) in any reachable
  deployment; the API is open when neither is configured.
- Secret values are read from env or `pg.env`/`config.json` files and are
  never logged, echoed in APIs, or copied into the source.

## Development

```bash
python -m venv ./.venv && source ./.venv/bin/activate
pip install -r requirements.txt
# point MAILWATCH_PG_DSN at a local PostgreSQL
MAILWATCH_EWS_DIR=/app MAILWATCH_EWS_API_HOST=127.0.0.1 MAILWATCH_EWS_API_PORT=18661 \
  MAILWATCH_EWS_SERVER=… MAILWATCH_EWS_USERNAME=… MAILWATCH_EWS_PASSWORD=… \
  MAILWATCH_EWS_MAILBOX=… python ews_worker.py
```

## License

MIT — see `LICENSE`.
