#!/usr/bin/env python3
"""EWS realtime collector with mail archive, attachment vault and a small
read-only API + web UI. Designed for mailboxes that only expose EWS/OWA
over HTTPS (IMAP/POP/SMTP blocked upstream)."""

from __future__ import annotations

import gzip
import hashlib
import hmac
import html
import json
import logging
import mimetypes
import os
import re
import secrets
import signal
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable


BASE_DIR = Path(os.environ.get("MAILWATCH_EWS_DIR", "/app"))
CONFIG_PATH = Path(os.environ.get("MAILWATCH_CONFIG", str(BASE_DIR / "config.json")))
DATA_DIR = BASE_DIR / "data"
PG_ENV_PATH = BASE_DIR / "pg.env"
ARCHIVE_DIR = DATA_DIR / "archive"
MIME_DIR = ARCHIVE_DIR / "mime"
ATTACHMENT_DIR = ARCHIVE_DIR / "attachments"
PANEL_PATH = BASE_DIR / "index.html"

# Mail account settings as loaded at startup (used by /api/summary).
MAIL_SETTINGS: dict[str, Any] = {}

API_HOST = os.environ.get("MAILWATCH_EWS_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("MAILWATCH_EWS_API_PORT", "18661"))
PANEL_TOKEN = os.environ.get("MAILWATCH_PANEL_TOKEN", "").strip()
PANEL_USER = os.environ.get("MAILWATCH_PANEL_USER", "").strip()
PANEL_PASSWORD = os.environ.get("MAILWATCH_PANEL_PASSWORD", "")
PANEL_SESSION_TTL_SECONDS = int(
    os.environ.get("MAILWATCH_PANEL_SESSION_TTL", str(12 * 60 * 60))
)
STREAM_TIMEOUT_MINUTES = int(os.environ.get("MAILWATCH_EWS_STREAM_TIMEOUT", "20"))
FALLBACK_SYNC_SECONDS = int(os.environ.get("MAILWATCH_EWS_SYNC_INTERVAL", "300"))
INITIAL_BACKFILL = os.environ.get("MAILWATCH_EWS_BACKFILL", "1") not in {
    "0",
    "false",
    "no",
}

def parse_size(value: Any, default: int | None = None) -> int:
    """Parse a byte size such as 100G, 95GiB, or 107374182400."""
    if isinstance(value, bool):
        raise ValueError("boolean is not a byte size")
    if isinstance(value, (int, float)):
        size = int(value)
    else:
        text = str(value).strip().upper().replace(" ", "")
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGT]I?B?)?", text)
        if not match:
            if default is not None:
                return default
            raise ValueError(f"invalid byte size: {value!r}")
        number = float(match.group(1))
        unit = (match.group(2) or "").rstrip("IB")
        scale = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
        size = int(number * scale[unit])
    if size < 0:
        raise ValueError("byte size cannot be negative")
    return size


def env_size(name: str, default: str) -> int:
    return parse_size(os.environ.get(name, default), parse_size(default))


STORAGE_LIMIT_BYTES = env_size("MAILWATCH_MAX_STORAGE_BYTES", "100G")
STORAGE_TARGET_BYTES = env_size("MAILWATCH_STORAGE_TARGET_BYTES", "95G")
if STORAGE_TARGET_BYTES >= STORAGE_LIMIT_BYTES:
    STORAGE_TARGET_BYTES = int(STORAGE_LIMIT_BYTES * 0.95)
CLEANUP_INTERVAL_SECONDS = max(
    10, int(os.environ.get("MAILWATCH_CLEANUP_INTERVAL", "60"))
)
CLEANUP_BATCH_SIZE = max(1, int(os.environ.get("MAILWATCH_CLEANUP_BATCH", "20")))
MIN_KEEP_MESSAGES = max(1, int(os.environ.get("MAILWATCH_MIN_KEEP_MESSAGES", "1")))


FETCH_FIELDS = (
    "id",
    "changekey",
    "mime_content",
    "subject",
    "sender",
    "to_recipients",
    "cc_recipients",
    "bcc_recipients",
    "message_id",
    "conversation_id",
    "datetime_sent",
    "datetime_received",
    "datetime_created",
    "size",
    "is_read",
    "has_attachments",
    "importance",
    "categories",
    "text_body",
    "body",
    "attachments",
)

STREAM_EVENT_TYPES = (
    "NewMailEvent",
    "CreatedEvent",
    "ModifiedEvent",
    "MovedEvent",
    "DeletedEvent",
)

STOP_EVENT = threading.Event()
SYNC_EVENT = threading.Event()
STATE_LOCK = threading.Lock()
STORAGE_LOCK = threading.Lock()
SEND_LOCK = threading.Lock()
PANEL_EWS_LOCK = threading.Lock()
EWS_ACCOUNT: Any = None
STATE: dict[str, Any] = {
    "phase": "starting",
    "last_ok": None,
    "last_attempt": None,
    "last_error": None,
    "consecutive_fail": 0,
    "stream_status": "starting",
    "stream_last_event": None,
    "stream_error": None,
    "backfill_done": False,
    "storage_limit_bytes": STORAGE_LIMIT_BYTES,
    "storage_target_bytes": STORAGE_TARGET_BYTES,
    "storage_used_bytes": None,
    "storage_archive_bytes": None,
    "storage_database_bytes": None,
    "storage_database_content_bytes": None,
    "last_cleanup": None,
    "last_cleanup_deleted": 0,
    "last_cleanup_error": None,
}

LOG = logging.getLogger("mailwatch-ews")


class ApiError(Exception):
    """API error carrying the HTTP status to return to the client."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def token_ok(expected: str, provided: str | None) -> bool:
    if not expected:
        return True
    return hmac.compare_digest(expected, provided or "")


PANEL_SESSIONS: dict[str, float] = {}
PANEL_SESSION_LOCK = threading.Lock()


def panel_auth_enabled() -> bool:
    return bool(PANEL_TOKEN or (PANEL_USER and PANEL_PASSWORD))


def panel_session_ok(provided: str | None) -> bool:
    if not provided:
        return False
    now = time.monotonic()
    with PANEL_SESSION_LOCK:
        expired = [key for key, expires in PANEL_SESSIONS.items() if expires <= now]
        for key in expired:
            PANEL_SESSIONS.pop(key, None)
        return any(
            hmac.compare_digest(key, provided)
            for key, expires in PANEL_SESSIONS.items()
            if expires > now
        )


def panel_login(username: Any, password: Any) -> str:
    if not PANEL_USER or not PANEL_PASSWORD:
        raise ApiError(503, "panel login is not configured")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ApiError(400, "username and password are required")
    user_ok = hmac.compare_digest(PANEL_USER, username.strip())
    password_ok = hmac.compare_digest(PANEL_PASSWORD, password)
    if not user_ok or not password_ok:
        raise ApiError(401, "invalid username or password")
    session = secrets.token_urlsafe(32)
    expires = time.monotonic() + PANEL_SESSION_TTL_SECONDS
    with PANEL_SESSION_LOCK:
        PANEL_SESSIONS[session] = expires
    return session


def panel_logout(provided: str | None) -> None:
    if not provided:
        return
    with PANEL_SESSION_LOCK:
        for key in list(PANEL_SESSIONS):
            if hmac.compare_digest(key, provided):
                PANEL_SESSIONS.pop(key, None)


def json_list(value: Any) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def prefixed_subject(prefix: str, subject: str | None) -> str:
    clean = (subject or "").strip() or "(无主题)"
    if re.match(rf"(?i)^{re.escape(prefix)}\s*:", clean):
        return clean
    return f"{prefix}: {clean}"


EMAIL_RE = re.compile(r"[^@\s,;<>]+@[^@\s,;<>]+")


def address_list(value: Any) -> list[str]:
    """Extract e-mail addresses from a comma separated string or list.

    Tolerates pasted display names such as ``张三 <a@b.com>``.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        text = ",".join(str(v) for v in value)
    else:
        text = str(value)
    found: list[str] = []
    seen: set[str] = set()
    for match in EMAIL_RE.findall(text):
        addr = match.strip().strip("<>").strip()
        if not addr or addr.lower() in seen:
            continue
        seen.add(addr.lower())
        found.append(addr)
    if text.strip() and not found:
        raise ValueError(f"无效的收件人地址: {text.strip()[:80]}")
    return found


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dirs() -> None:
    for path in (BASE_DIR, DATA_DIR, ARCHIVE_DIR, MIME_DIR, ATTACHMENT_DIR):
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def load_config() -> dict[str, Any]:
    """Load account settings from an optional JSON file, then env overrides."""
    config: dict[str, Any] = {}
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open(encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            config.update(loaded)
    env_overrides = {
        "username": "MAILWATCH_EWS_USERNAME",
        "password": "MAILWATCH_EWS_PASSWORD",
        "mailbox": "MAILWATCH_EWS_MAILBOX",
        "server": "MAILWATCH_EWS_SERVER",
    }
    for key, env_name in env_overrides.items():
        value = os.environ.get(env_name)
        if value:
            config[key] = value
    missing = [
        key
        for key in ("username", "password", "mailbox", "server")
        if not config.get(key)
    ]
    if missing:
        raise RuntimeError(
            f"missing mail account settings ({CONFIG_PATH} file or env): "
            + ", ".join(missing)
        )
    return config


def ews_build() -> Any:
    """Explicit server build hint (exchangelib skips autodiscover versioning)."""
    from exchangelib.version import Build

    raw = os.environ.get("MAILWATCH_EWS_BUILD", "15.2.2562")
    parts = tuple(int(item) for item in raw.split(".") if item.isdigit())
    if not parts:
        parts = (15, 2, 2562)
    return Build(*parts)


def load_pg_dsn() -> str:
    """Read the PostgreSQL DSN from env or a root-only file (mode 0600)."""
    dsn = os.environ.get("MAILWATCH_PG_DSN", "").strip()
    if dsn:
        return dsn
    if PG_ENV_PATH.exists():
        for raw in PG_ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("MAILWATCH_PG_DSN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError(
        f"PostgreSQL DSN not configured: set MAILWATCH_PG_DSN or create {PG_ENV_PATH}"
    )

def db():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError(
            "psycopg is not installed; run pip install -r requirements.txt"
        ) from exc
    return psycopg.connect(
        load_pg_dsn(),
        row_factory=dict_row,
        connect_timeout=10,
    )


SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    rowid BIGSERIAL PRIMARY KEY,
    exchange_id TEXT NOT NULL UNIQUE,
    change_key TEXT,
    message_id TEXT,
    conversation_id TEXT,
    folder TEXT NOT NULL DEFAULT 'INBOX',
    sender TEXT,
    sender_name TEXT,
    sender_email TEXT,
    recipients_json TEXT,
    cc_json TEXT,
    bcc_json TEXT,
    subject TEXT,
    body_text TEXT,
    body_html TEXT,
    datetime_sent TEXT,
    datetime_received TEXT,
    datetime_created TEXT,
    size INTEGER,
    is_read INTEGER NOT NULL DEFAULT 0,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    importance TEXT,
    categories_json TEXT,
    mime_sha256 TEXT,
    mime_path TEXT,
    raw_size INTEGER,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_new INTEGER NOT NULL DEFAULT 1,
    is_deleted INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_message_id
    ON messages(message_id) WHERE message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_received
    ON messages(datetime_received DESC);
CREATE INDEX IF NOT EXISTS idx_messages_seen
    ON messages(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_messages_mime_sha
    ON messages(mime_sha256);

CREATE TABLE IF NOT EXISTS attachments (
    id BIGSERIAL PRIMARY KEY,
    message_rowid BIGINT NOT NULL REFERENCES messages(rowid) ON DELETE CASCADE,
    part_index INTEGER NOT NULL,
    filename TEXT,
    content_type TEXT,
    content_id TEXT,
    size INTEGER,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    is_inline INTEGER NOT NULL DEFAULT 0,
    UNIQUE(message_rowid, part_index)
);

CREATE INDEX IF NOT EXISTS idx_attachments_sha
    ON attachments(sha256);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS ingest_log (
    id BIGSERIAL PRIMARY KEY,
    ts TEXT NOT NULL,
    ok INTEGER NOT NULL,
    action TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE TABLE IF NOT EXISTS event_log (
    id BIGSERIAL PRIMARY KEY,
    ts TEXT NOT NULL,
    event_type TEXT,
    exchange_id TEXT,
    processed INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

"""


def init_db() -> None:
    ensure_dirs()
    conn = db()
    try:
        for statement in SCHEMA.split(";"):
            if statement.strip():
                conn.execute(statement)
        conn.commit()
    finally:
        conn.close()
    ensure_search_index()


def ensure_search_index() -> None:
    """Best-effort trigram indexes for ILIKE search; non-fatal if unavailable."""
    conn = db()
    try:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        for column in ("subject", "body_text", "sender"):
            conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_messages_{column}_trgm "
                f"ON messages USING gin ({column} gin_trgm_ops)"
            )
        conn.commit()
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        LOG.warning("search index not created (search still works): %s", exc)
    finally:
        conn.close()


def meta_get(key: str, default: str | None = None) -> str | None:
    conn = db()
    try:
        row = conn.execute("SELECT value FROM meta WHERE key=%s", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def meta_set(key: str, value: str | None) -> None:
    conn = db()
    try:
        if value is None:
            conn.execute("DELETE FROM meta WHERE key=%s", (key,))
        else:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(%s, %s) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        conn.commit()
    finally:
        conn.close()


def log_ingest(ok: bool, action: str, count: int = 0, error: str | None = None) -> None:
    conn = db()
    try:
        conn.execute(
            "INSERT INTO ingest_log(ts, ok, action, count, error) VALUES(%s, %s, %s, %s, %s)",
            (utc_now(), int(ok), action, count, (error or "")[:500] or None),
        )
        conn.commit()
    finally:
        conn.close()


def update_state(**values: Any) -> None:
    with STATE_LOCK:
        STATE.update(values)


def record_attempt(ok: bool, error: Exception | str | None = None) -> None:
    now = utc_now()
    with STATE_LOCK:
        STATE["last_attempt"] = now
        if ok:
            STATE["last_ok"] = now
            STATE["last_error"] = None
            STATE["consecutive_fail"] = 0
        else:
            STATE["last_error"] = str(error)[:500] if error else "unknown error"
            STATE["consecutive_fail"] = int(STATE.get("consecutive_fail", 0)) + 1


def archive_usage_bytes() -> int:
    """Return the actual size of MIME and attachment files on disk."""
    total = 0
    if not ARCHIVE_DIR.exists():
        return total
    for path in ARCHIVE_DIR.rglob("*"):
        if not path.is_file() or path.name.startswith(".tmp-"):
            continue
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


def database_metrics(conn: Any) -> tuple[int, int]:
    """Return physical database size and a conservative content estimate."""
    physical = int(
        conn.execute("SELECT pg_database_size(current_database()) AS bytes")
        .fetchone()["bytes"]
    )
    content = int(
        conn.execute(
            """
            SELECT
                (
                    SELECT COALESCE(SUM(
                        COALESCE(raw_size, 0)
                        + octet_length(COALESCE(body_text, ''))
                        + octet_length(COALESCE(body_html, ''))
                        + octet_length(COALESCE(subject, ''))
                        + octet_length(COALESCE(sender, ''))
                        + octet_length(COALESCE(recipients_json, ''))
                        + octet_length(COALESCE(cc_json, ''))
                        + octet_length(COALESCE(bcc_json, ''))
                        + octet_length(COALESCE(categories_json, ''))
                    ), 0)
                    FROM messages
                )
                + (
                    SELECT COALESCE(SUM(
                        octet_length(COALESCE(filename, ''))
                        + octet_length(COALESCE(content_type, ''))
                        + octet_length(COALESCE(path, ''))
                        + octet_length(COALESCE(sha256, ''))
                    ), 0)
                    FROM attachments
                ) AS bytes
            """
        )
        .fetchone()["bytes"]
    )
    return physical, content


def storage_metrics() -> dict[str, int]:
    archive = archive_usage_bytes()
    conn = db()
    try:
        database_physical, database_content = database_metrics(conn)
    finally:
        conn.close()
    used = archive + database_content
    update_state(
        storage_used_bytes=used,
        storage_archive_bytes=archive,
        storage_database_bytes=database_physical,
        storage_database_content_bytes=database_content,
    )
    return {
        "used": used,
        "archive": archive,
        "database_physical": database_physical,
        "database_content": database_content,
        "limit": STORAGE_LIMIT_BYTES,
        "target": STORAGE_TARGET_BYTES,
    }


def _archive_path(relative: str) -> Path:
    path = (ARCHIVE_DIR / relative).resolve()
    root = ARCHIVE_DIR.resolve()
    if os.path.commonpath((str(path), str(root))) != str(root):
        raise ValueError("path outside archive")
    return path


def _remove_unreferenced_files(
    conn: Any,
    mime_paths: set[str],
    attachment_paths: set[str],
) -> None:
    for relative in sorted(mime_paths):
        if not relative:
            continue
        referenced = conn.execute(
            "SELECT 1 FROM messages WHERE mime_path=%s LIMIT 1",
            (relative,),
        ).fetchone()
        if referenced:
            continue
        try:
            _archive_path(relative).unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            LOG.warning("unable to remove MIME file %s: %s", relative, exc)

    for relative in sorted(attachment_paths):
        if not relative:
            continue
        referenced = conn.execute(
            "SELECT 1 FROM attachments WHERE path=%s LIMIT 1",
            (relative,),
        ).fetchone()
        if referenced:
            continue
        try:
            _archive_path(relative).unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            LOG.warning("unable to remove attachment file %s: %s", relative, exc)


def sweep_orphan_archive_files(conn: Any) -> int:
    """Remove files left behind by an interrupted cleanup."""
    referenced_mime = {
        row["mime_path"]
        for row in conn.execute(
            "SELECT mime_path FROM messages WHERE mime_path IS NOT NULL"
        ).fetchall()
    }
    referenced_attachments = {
        row["path"]
        for row in conn.execute(
            "SELECT path FROM attachments WHERE path IS NOT NULL"
        ).fetchall()
    }
    removed = 0
    if not ARCHIVE_DIR.exists():
        return removed
    for path in ARCHIVE_DIR.rglob("*"):
        if not path.is_file() or path.name.startswith(".tmp-"):
            continue
        relative = path.relative_to(ARCHIVE_DIR).as_posix()
        if relative.startswith("mime/"):
            referenced = relative in referenced_mime
        elif relative.startswith("attachments/"):
            referenced = relative in referenced_attachments
        else:
            continue
        if referenced:
            continue
        try:
            path.unlink()
            removed += 1
        except OSError as exc:
            LOG.warning("unable to remove orphan archive file %s: %s", relative, exc)
    return removed


def _delete_storage_batch(conn: Any, rowids: list[int]) -> None:
    mime_paths = {
        row["mime_path"]
        for row in conn.execute(
            "SELECT mime_path FROM messages WHERE rowid = ANY(%s)",
            (rowids,),
        ).fetchall()
        if row["mime_path"]
    }
    attachment_paths = {
        row["path"]
        for row in conn.execute(
            "SELECT path FROM attachments WHERE message_rowid = ANY(%s)",
            (rowids,),
        ).fetchall()
        if row["path"]
    }
    conn.execute(
        "DELETE FROM attachments WHERE message_rowid = ANY(%s)",
        (rowids,),
    )
    conn.execute("DELETE FROM messages WHERE rowid = ANY(%s)", (rowids,))
    conn.commit()
    _remove_unreferenced_files(conn, mime_paths, attachment_paths)


def vacuum_storage_tables() -> None:
    """Best-effort reclaim of PostgreSQL pages after a cleanup batch."""
    conn = db()
    try:
        conn.autocommit = True
        conn.execute("VACUUM (ANALYZE) messages")
        conn.execute("VACUUM (ANALYZE) attachments")
    except Exception as exc:
        LOG.warning("storage vacuum failed: %s", exc)
    finally:
        conn.close()


def enforce_storage_limit(force: bool = False) -> dict[str, int]:
    """Delete oldest messages until the configured content quota is met."""
    metrics = storage_metrics()
    if not force and metrics["used"] <= STORAGE_LIMIT_BYTES:
        return metrics
    if not STORAGE_LOCK.acquire(blocking=False):
        return storage_metrics()

    deleted = 0
    try:
        while True:
            metrics = storage_metrics()
            if metrics["used"] <= STORAGE_TARGET_BYTES:
                break
            conn = db()
            try:
                count = int(
                    conn.execute("SELECT COUNT(*) AS n FROM messages").fetchone()["n"]
                )
                if count <= MIN_KEEP_MESSAGES:
                    break
                limit = min(CLEANUP_BATCH_SIZE, count - MIN_KEEP_MESSAGES)
                rows = conn.execute(
                    """
                    SELECT rowid
                    FROM messages
                    ORDER BY is_deleted DESC,
                             COALESCE(datetime_received, first_seen) ASC,
                             rowid ASC
                    LIMIT %s
                    """,
                    (limit,),
                ).fetchall()
                if not rows:
                    break
                rowids = [int(row["rowid"]) for row in rows]
                _delete_storage_batch(conn, rowids)
                deleted += len(rowids)
            finally:
                conn.close()

        conn = db()
        try:
            removed_files = sweep_orphan_archive_files(conn)
        finally:
            conn.close()
        if removed_files:
            LOG.info("storage cleanup removed orphan files=%s", removed_files)
        if deleted:
            vacuum_storage_tables()
        metrics = storage_metrics()
        update_state(
            last_cleanup=utc_now(),
            last_cleanup_deleted=deleted,
            last_cleanup_error=(
                "storage remains above target after cleanup"
                if metrics["used"] > STORAGE_TARGET_BYTES
                else None
            ),
        )
        if deleted:
            log_ingest(True, "storage_cleanup", deleted)
            LOG.info(
                "storage cleanup deleted=%s used=%s target=%s limit=%s",
                deleted,
                metrics["used"],
                STORAGE_TARGET_BYTES,
                STORAGE_LIMIT_BYTES,
            )
        return metrics
    except Exception as exc:
        update_state(
            last_cleanup=utc_now(),
            last_cleanup_error=str(exc)[:500],
        )
        raise
    finally:
        STORAGE_LOCK.release()


def cleanup_worker() -> None:
    while not STOP_EVENT.is_set():
        try:
            enforce_storage_limit()
        except Exception:
            LOG.exception("storage cleanup failed")
        STOP_EVENT.wait(CLEANUP_INTERVAL_SECONDS)


def safe_filename(name: str | None, fallback: str) -> str:
    value = name or fallback
    value = value.replace("\\", "/").split("/")[-1]
    value = re.sub(r'[\\/:*?"<>|]', "_", value).strip()
    return value or fallback


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_mime(mime_bytes: bytes) -> tuple[str, str, int]:
    digest = sha256_bytes(mime_bytes)
    now = datetime.now(timezone.utc)
    relative = Path("mime") / f"{now:%Y}" / f"{now:%m}" / f"{digest}.eml.gz"
    path = ARCHIVE_DIR / relative
    if not path.exists():
        compressed = gzip.compress(mime_bytes, compresslevel=6, mtime=0)
        atomic_write(path, compressed)
    return digest, relative.as_posix(), len(mime_bytes)


def save_attachment(data: bytes) -> tuple[str, str]:
    digest = sha256_bytes(data)
    relative = Path("attachments") / digest[:2] / digest
    path = ARCHIVE_DIR / relative
    if not path.exists():
        atomic_write(path, data)
    return digest, relative.as_posix()


def decode_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def part_text(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            return content.decode("utf-8", "replace")
        return str(content)
    except Exception:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, "replace")
            except LookupError:
                return payload.decode("utf-8", "replace")
        return decode_text(part.get_payload())


def html_to_text(value: str) -> str:
    value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def mailbox_json(items: Iterable[Any] | None) -> list[dict[str, str]]:
    result = []
    for item in items or []:
        if isinstance(item, dict):
            result.append(
                {
                    "name": str(item.get("name") or ""),
                    "email": str(item.get("email") or ""),
                }
            )
            continue
        result.append(
            {
                "name": str(getattr(item, "name", "") or ""),
                "email": str(
                    getattr(item, "email_address", "")
                    or getattr(item, "email", "")
                    or ""
                ),
            }
        )
    return result


def addresses_from_header(value: str | None) -> list[dict[str, str]]:
    return [
        {"name": name, "email": address}
        for name, address in getaddresses([value or ""])
        if address
    ]


def mailbox_display(item: Any) -> tuple[str, str, str]:
    if item is None:
        return "", "", ""
    name = str(getattr(item, "name", "") or "")
    email = str(
        getattr(item, "email_address", "")
        or getattr(item, "email", "")
        or ""
    )
    combined = f"{name} <{email}>" if name and email else (email or name)
    return combined, name, email


def iso_value(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    return str(value)


def parse_mime(mime_bytes: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(mime_bytes)

    plain_part = message.get_body(preferencelist=("plain",))
    html_part = message.get_body(preferencelist=("html",))
    body_text = part_text(plain_part) if plain_part else ""
    body_html = part_text(html_part) if html_part else ""
    if not body_text and body_html:
        body_text = html_to_text(body_html)
    if not body_html and body_text:
        body_html = ""

    from_name, from_email = parseaddr(message.get("From", ""))
    to_values = addresses_from_header(message.get("To"))
    cc_values = addresses_from_header(message.get("Cc"))
    bcc_values = addresses_from_header(message.get("Bcc"))

    attachments: list[dict[str, Any]] = []
    part_index = 0
    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_id = part.get("Content-ID")
        is_body_part = (
            content_type in {"text/plain", "text/html"}
            and disposition is None
            and not filename
            and not content_id
        )
        if is_body_part:
            continue
        if not (filename or disposition in {"attachment", "inline"} or content_id):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            raw_payload = part.get_payload()
            if isinstance(raw_payload, str):
                payload = raw_payload.encode("utf-8", "replace")
            elif isinstance(raw_payload, bytes):
                payload = raw_payload
            else:
                payload = part.as_bytes()
        if not isinstance(payload, bytes):
            payload = decode_text(payload).encode("utf-8", "replace")
        original_name = filename or f"attachment-{part_index:03d}"
        attachments.append(
            {
                "part_index": part_index,
                "filename": safe_filename(original_name, f"attachment-{part_index:03d}"),
                "original_filename": original_name,
                "content_type": content_type,
                "content_id": (str(content_id).strip("<>") if content_id else None),
                "is_inline": int(bool(content_id) or disposition == "inline"),
                "data": payload,
            }
        )
        part_index += 1

    return {
        "message_id": (message.get("Message-ID") or "").strip() or None,
        "subject": str(message.get("Subject") or ""),
        "from_name": from_name,
        "from_email": from_email,
        "to": to_values,
        "cc": cc_values,
        "bcc": bcc_values,
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments,
    }


def item_mime(item: Any) -> bytes | None:
    value = getattr(item, "mime_content", None)
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    return None


def _store_item_unlocked(item: Any) -> bool:
    mime_bytes = item_mime(item)
    if not mime_bytes:
        raise RuntimeError(f"item {getattr(item, 'id', '')} has no MIME content")

    parsed = parse_mime(mime_bytes)
    mime_sha, mime_path, raw_size = save_mime(mime_bytes)
    exchange_id = str(getattr(item, "id", "") or "")
    if not exchange_id:
        raise RuntimeError("item has no Exchange id")

    sender_combined, sender_name, sender_email = mailbox_display(
        getattr(item, "sender", None)
    )
    if not sender_combined:
        sender_combined = (
            f"{parsed['from_name']} <{parsed['from_email']}>"
            if parsed["from_name"] and parsed["from_email"]
            else (parsed["from_email"] or parsed["from_name"])
        )
        sender_name = parsed["from_name"]
        sender_email = parsed["from_email"]

    recipients = mailbox_json(getattr(item, "to_recipients", None)) or parsed["to"]
    cc = mailbox_json(getattr(item, "cc_recipients", None)) or parsed["cc"]
    bcc = mailbox_json(getattr(item, "bcc_recipients", None)) or parsed["bcc"]
    subject = str(getattr(item, "subject", "") or parsed["subject"] or "")
    body_text = decode_text(getattr(item, "text_body", "")) or parsed["body_text"]
    body_value = getattr(item, "body", None)
    body_html = parsed["body_html"]
    if not body_html and body_value and "<" in str(body_value):
        body_html = str(body_value)
    if not body_text and body_html:
        body_text = html_to_text(body_html)

    message_id = str(getattr(item, "message_id", "") or parsed["message_id"] or "")
    conversation_id = str(getattr(item, "conversation_id", "") or "")
    now = utc_now()
    received = iso_value(getattr(item, "datetime_received", None))
    sent = iso_value(getattr(item, "datetime_sent", None))
    created = iso_value(getattr(item, "datetime_created", None))
    size_value = getattr(item, "size", None)
    try:
        size = int(size_value) if size_value is not None else raw_size
    except (TypeError, ValueError):
        size = raw_size
    categories = list(getattr(item, "categories", []) or [])

    attachment_paths: list[dict[str, Any]] = []
    for attachment in parsed["attachments"]:
        digest, relative_path = save_attachment(attachment.pop("data"))
        attachment["sha256"] = digest
        attachment["path"] = relative_path
        attachment["size"] = len(
            (ARCHIVE_DIR / relative_path).read_bytes()
        )
        attachment_paths.append(attachment)

    conn = db()
    try:
        existing = conn.execute(
            "SELECT rowid, first_seen, exchange_id FROM messages"
            " WHERE exchange_id=%s OR (message_id IS NOT NULL AND message_id=%s)"
            " ORDER BY CASE WHEN exchange_id=%s THEN 0 ELSE 1 END LIMIT 1",
            (exchange_id, message_id or None, exchange_id),
        ).fetchone()
        first_seen = existing["first_seen"] if existing else now
        is_new = 0 if existing else 1
        # 迁移/重扫场景：同一封邮件可能带新的 exchange_id 回来（EWS ItemId 会重发），
        # 而 message_id 上有唯一索引 → 先把既有行归位到新 exchange_id，避免唯一键冲突
        if existing is not None and str(existing["exchange_id"]) != str(exchange_id):
            conn.execute(
                "UPDATE messages SET exchange_id=%s WHERE rowid=%s",
                (exchange_id, existing["rowid"]),
            )
        conn.execute(
            """
            INSERT INTO messages(
                exchange_id, change_key, message_id, conversation_id, folder,
                sender, sender_name, sender_email, recipients_json, cc_json,
                bcc_json, subject, body_text, body_html, datetime_sent,
                datetime_received, datetime_created, size, is_read,
                has_attachments, importance, categories_json, mime_sha256,
                mime_path, raw_size, first_seen, last_seen, is_new, is_deleted
            ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                     %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(exchange_id) DO UPDATE SET
                change_key=excluded.change_key,
                message_id=excluded.message_id,
                conversation_id=excluded.conversation_id,
                folder=excluded.folder,
                sender=excluded.sender,
                sender_name=excluded.sender_name,
                sender_email=excluded.sender_email,
                recipients_json=excluded.recipients_json,
                cc_json=excluded.cc_json,
                bcc_json=excluded.bcc_json,
                subject=excluded.subject,
                body_text=excluded.body_text,
                body_html=excluded.body_html,
                datetime_sent=excluded.datetime_sent,
                datetime_received=excluded.datetime_received,
                datetime_created=excluded.datetime_created,
                size=excluded.size,
                is_read=excluded.is_read,
                has_attachments=excluded.has_attachments,
                importance=excluded.importance,
                categories_json=excluded.categories_json,
                mime_sha256=excluded.mime_sha256,
                mime_path=excluded.mime_path,
                raw_size=excluded.raw_size,
                last_seen=excluded.last_seen,
                is_deleted=0
            """,
            (
                exchange_id,
                str(getattr(item, "changekey", "") or ""),
                message_id or None,
                conversation_id or None,
                "INBOX",
                sender_combined,
                sender_name,
                sender_email,
                json.dumps(recipients, ensure_ascii=False),
                json.dumps(cc, ensure_ascii=False),
                json.dumps(bcc, ensure_ascii=False),
                subject,
                body_text,
                body_html,
                sent,
                received,
                created,
                size,
                int(bool(getattr(item, "is_read", False))),
                int(bool(getattr(item, "has_attachments", False) or attachment_paths)),
                str(getattr(item, "importance", "") or ""),
                json.dumps(categories, ensure_ascii=False),
                mime_sha,
                mime_path,
                raw_size,
                first_seen,
                now,
                is_new,
                0,
            ),
        )
        rowid = conn.execute(
            "SELECT rowid FROM messages WHERE exchange_id=%s",
            (exchange_id,),
        ).fetchone()["rowid"]
        conn.execute("DELETE FROM attachments WHERE message_rowid=%s", (rowid,))
        for attachment in attachment_paths:
            conn.execute(
                """
                INSERT INTO attachments(
                    message_rowid, part_index, filename, content_type,
                    content_id, size, sha256, path, is_inline
                ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    rowid,
                    attachment["part_index"],
                    attachment["filename"],
                    attachment["content_type"],
                    attachment["content_id"],
                    attachment["size"],
                    attachment["sha256"],
                    attachment["path"],
                    attachment["is_inline"],
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return not bool(existing)


def store_item(item: Any) -> bool:
    with STORAGE_LOCK:
        return _store_item_unlocked(item)


def update_read_state(exchange_id: str, is_read: bool) -> None:
    conn = db()
    try:
        conn.execute(
            "UPDATE messages SET is_read=%s, last_seen=%s WHERE exchange_id=%s",
            (int(bool(is_read)), utc_now(), exchange_id),
        )
        conn.commit()
    finally:
        conn.close()


def mark_deleted(exchange_id: str) -> None:
    conn = db()
    try:
        conn.execute(
            "UPDATE messages SET is_deleted=1, last_seen=%s WHERE exchange_id=%s",
            (utc_now(), exchange_id),
        )
        conn.commit()
    finally:
        conn.close()


def build_account(config: dict[str, Any]) -> Any:
    from exchangelib import (
        Account,
        Configuration,
        Credentials,
        DELEGATE,
        NTLM,
    )
    from exchangelib.version import Build, Version

    credentials = Credentials(
        username=config["username"],
        password=config["password"],
    )
    server = (config.get("server") or "").strip()
    if not server:
        raise RuntimeError(
            "mail server not configured: set MAILWATCH_EWS_SERVER or 'server' in config"
        )
    ewsa_config = Configuration(
        server=server,
        credentials=credentials,
        auth_type=NTLM,
        version=Version(build=ews_build()),
        max_connections=2,
    )
    return Account(
        primary_smtp_address=config["mailbox"],
        config=ewsa_config,
        autodiscover=False,
        access_type=DELEGATE,
    )


def initial_backfill(account: Any) -> None:
    if meta_get("backfill_done") == "1":
        update_state(backfill_done=True)
        return
    update_state(phase="backfilling")
    LOG.info("starting initial inbox backfill")
    queryset = account.inbox.all().only(*FETCH_FIELDS)
    queryset.page_size = 50
    queryset.chunk_size = 10
    count = 0
    new_count = 0
    try:
        for item in queryset:
            if STOP_EVENT.is_set():
                raise RuntimeError("backfill stopped")
            if store_item(item):
                new_count += 1
            count += 1
            if count % 10 == 0:
                LOG.info("backfill progress messages=%s new=%s", count, new_count)
        meta_set("backfill_done", "1")
        update_state(backfill_done=True, phase="running")
        log_ingest(True, "backfill", count)
        LOG.info("initial backfill complete messages=%s new=%s", count, new_count)
    except Exception as exc:
        log_ingest(False, "backfill", count, str(exc))
        raise


def prime_sync_state(account: Any) -> None:
    stored = meta_get("item_sync_state")
    if stored:
        account.inbox.item_sync_state = stored
        return
    LOG.info("priming EWS item sync state")
    account.inbox.item_sync_state = None
    for change_type, value in account.inbox.sync_items(only_fields=FETCH_FIELDS):
        process_sync_change(account, change_type, value)
    state = account.inbox.item_sync_state
    if not state:
        raise RuntimeError("EWS did not return an item sync state")
    meta_set("item_sync_state", state)


def item_id_of(value: Any) -> tuple[str | None, str | None]:
    if isinstance(value, (tuple, list)) and value:
        first = value[0]
        if hasattr(first, "id"):
            return str(getattr(first, "id", "") or "") or None, str(
                getattr(first, "changekey", "") or ""
            ) or None
        if isinstance(first, str):
            return first, None
    if hasattr(value, "id"):
        return str(getattr(value, "id", "") or "") or None, str(
            getattr(value, "changekey", "") or ""
        ) or None
    return None, None


def process_sync_change(account: Any, change_type: str, value: Any) -> int:
    if change_type == "read_flag_change":
        if isinstance(value, (tuple, list)) and len(value) >= 2:
            exchange_id, is_read = value[0], value[1]
            if hasattr(exchange_id, "id"):
                exchange_id = exchange_id.id
            update_read_state(str(exchange_id), bool(is_read))
        return 0
    if change_type == "delete":
        exchange_id, _ = item_id_of(value)
        if exchange_id:
            mark_deleted(exchange_id)
        return 0
    if change_type not in {"create", "update", "move", "read_flag_change"}:
        return 0

    exchange_id, change_key = item_id_of(value)
    if not exchange_id:
        return 0
    if getattr(value, "mime_content", None):
        full_item = value
    else:
        kwargs = {"id": exchange_id}
        if change_key:
            kwargs["changekey"] = change_key
        from exchangelib.errors import DoesNotExist

        try:
            full_item = account.inbox.all().only(*FETCH_FIELDS).get(**kwargs)
        except DoesNotExist:
            LOG.info("item disappeared during sync id=%s", bool(exchange_id))
            mark_deleted(exchange_id)
            return 0
    if store_item(full_item):
        return 1
    return 0


def sync_incremental(account: Any) -> int:
    stored = meta_get("item_sync_state")
    if stored:
        account.inbox.item_sync_state = stored
    else:
        prime_sync_state(account)
        return 0

    count = 0
    for change_type, value in account.inbox.sync_items():
        count += process_sync_change(account, change_type, value)
    state = account.inbox.item_sync_state
    if state:
        meta_set("item_sync_state", state)
    record_attempt(True)
    if count:
        log_ingest(True, "incremental_sync", count)
        LOG.info("incremental sync stored new messages=%s", count)
    return count


def reset_invalid_sync_state(account: Any) -> None:
    LOG.warning("resetting invalid EWS sync state")
    meta_set("item_sync_state", None)
    prime_sync_state(account)


def is_session_limit_error(error: Exception) -> bool:
    text = str(error).lower()
    return any(
        token in text
        for token in (
            "sessionlimit",
            "toomanyobjectsopened",
            "serverbusy",
            "http error 500",
            "mapiexceptionsessionlimit",
        )
    )


def sync_worker(account: Any) -> None:
    consecutive_errors = 0
    while not STOP_EVENT.is_set():
        SYNC_EVENT.wait(timeout=FALLBACK_SYNC_SECONDS)
        if STOP_EVENT.is_set():
            break
        SYNC_EVENT.clear()
        try:
            sync_incremental(account)
            consecutive_errors = 0
        except Exception as exc:
            consecutive_errors += 1
            record_attempt(False, exc)
            log_ingest(False, "incremental_sync", 0, str(exc))
            LOG.exception("incremental sync failed")
            text = str(exc).lower()
            if "invalidsyncstate" in text or "invalid sync state" in text:
                try:
                    reset_invalid_sync_state(account)
                except Exception:
                    LOG.exception("failed to reset sync state")
            delay = 600 if is_session_limit_error(exc) else min(
                FALLBACK_SYNC_SECONDS, 30 * min(consecutive_errors, 4)
            )
            STOP_EVENT.wait(delay)


def stream_worker(account: Any) -> None:
    errors = 0
    while not STOP_EVENT.is_set():
        try:
            with account.inbox.streaming_subscription(
                event_types=STREAM_EVENT_TYPES
            ) as subscription_id:
                errors = 0
                update_state(stream_status="connected", stream_error=None)
                LOG.info("EWS streaming subscription connected")
                for notification in account.inbox.get_streaming_events(
                    subscription_id,
                    connection_timeout=STREAM_TIMEOUT_MINUTES,
                ):
                    update_state(
                        stream_last_event=utc_now(),
                        stream_status="connected",
                    )
                    for event in getattr(notification, "events", []) or []:
                        event_type = type(event).__name__
                        exchange_id = getattr(
                            getattr(event, "item_id", None), "id", None
                        )
                        conn = db()
                        try:
                            conn.execute(
                                "INSERT INTO event_log(ts, event_type, exchange_id) "
                                "VALUES(%s, %s, %s)",
                                (utc_now(), event_type, exchange_id),
                            )
                            conn.commit()
                        finally:
                            conn.close()
                        LOG.info(
                            "EWS event type=%s item=%s",
                            event_type,
                            bool(exchange_id),
                        )
                    SYNC_EVENT.set()
            update_state(stream_status="reconnecting", stream_error=None)
            if not STOP_EVENT.is_set():
                STOP_EVENT.wait(1)
        except Exception as exc:
            errors += 1
            update_state(stream_status="error", stream_error=str(exc)[:500])
            LOG.exception("EWS streaming subscription failed")
            delay = 600 if is_session_limit_error(exc) else min(
                60, 5 * min(errors, 12)
            )
            STOP_EVENT.wait(delay)


def row_to_summary(row: dict[str, Any]) -> dict[str, Any]:
    raw_snippet = row.get("snippet")
    if raw_snippet is None:
        raw_snippet = row.get("body_text") or ""
    snippet = re.sub(r"\s+", " ", str(raw_snippet)).strip()
    return {
        "key": row["rowid"],
        "id": row["exchange_id"],
        "message_id": row["message_id"],
        "sender": row["sender"],
        "sender_name": row.get("sender_name"),
        "sender_email": row.get("sender_email"),
        "to": json_list(row.get("recipients_json")),
        "categories": json_list(row.get("categories_json")),
        "snippet": snippet[:180],
        "subject": row["subject"],
        "time": row["datetime_received"] or row["datetime_sent"],
        "size": row["size"],
        "is_read": bool(row["is_read"]),
        "has_attachments": bool(row["has_attachments"]),
        "is_new": bool(row["is_new"]),
        "is_deleted": bool(row["is_deleted"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "mime_sha256": row["mime_sha256"],
    }


def api_summary() -> dict[str, Any]:
    conn = db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE is_deleted=0"
        ).fetchone()["n"]
        unread = conn.execute(
            "SELECT COUNT(*) AS n FROM messages "
            "WHERE is_deleted=0 AND is_read=0"
        ).fetchone()["n"]
        attachments = conn.execute("SELECT COUNT(*) AS n FROM attachments").fetchone()[
            "n"
        ]
        latest = conn.execute(
            "SELECT datetime_received, subject FROM messages "
            "WHERE datetime_received IS NOT NULL "
            "ORDER BY datetime_received DESC LIMIT 1"
        ).fetchone()
        sync_state = meta_get("item_sync_state")
    finally:
        conn.close()
    with STATE_LOCK:
        state = dict(STATE)
    return {
        "mailbox": MAIL_SETTINGS.get("mailbox", ""),
        "server": f"{MAIL_SETTINGS.get('server', 'EWS')} (EWS)",
        "source_ok": state["consecutive_fail"] == 0
        and state["stream_status"] in {"connected", "reconnecting"},
        "phase": state["phase"],
        "last_ok": state["last_ok"],
        "last_attempt": state["last_attempt"],
        "last_error": state["last_error"],
        "consecutive_fail": state["consecutive_fail"],
        "stream_status": state["stream_status"],
        "stream_last_event": state["stream_last_event"],
        "stream_error": state["stream_error"],
        "backfill_done": state["backfill_done"],
        "total": total,
        "unread": unread,
        "attachments": attachments,
        "latest_time": latest["datetime_received"] if latest else None,
        "latest_subject": latest["subject"] if latest else None,
        "has_sync_state": bool(sync_state),
        "sync_interval_seconds": FALLBACK_SYNC_SECONDS,
        "storage_limit_bytes": state.get("storage_limit_bytes"),
        "storage_target_bytes": state.get("storage_target_bytes"),
        "storage_used_bytes": state.get("storage_used_bytes"),
        "storage_archive_bytes": state.get("storage_archive_bytes"),
        "storage_database_bytes": state.get("storage_database_bytes"),
        "storage_database_content_bytes": state.get(
            "storage_database_content_bytes"
        ),
        "last_cleanup": state.get("last_cleanup"),
        "last_cleanup_deleted": state.get("last_cleanup_deleted"),
        "last_cleanup_error": state.get("last_cleanup_error"),
        "server_time": utc_now(),
    }


def api_mails(
    limit: int, query: str | None, offset: int = 0
) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    where = "WHERE is_deleted=0"
    params: list[Any] = []
    if query:
        escaped = (
            query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        where += (
            " AND (subject ILIKE %s OR body_text ILIKE %s "
            "OR sender ILIKE %s OR categories_json ILIKE %s)"
        )
        params += [pattern, pattern, pattern, pattern]
    conn = db()
    try:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) AS n FROM messages {where}", params
            ).fetchone()["n"]
        )
        rows = conn.execute(
            f"""
            SELECT rowid, exchange_id, message_id, sender, sender_name,
                   sender_email, recipients_json, categories_json, subject,
                   LEFT(body_text, 400) AS snippet, datetime_received,
                   datetime_sent, size, is_read, has_attachments, is_new,
                   is_deleted, first_seen, last_seen, mime_sha256
            FROM messages
            {where}
            ORDER BY COALESCE(datetime_received, datetime_sent, first_seen) DESC,
                     rowid DESC
            LIMIT %s OFFSET %s
            """,
            (*params, limit, offset),
        ).fetchall()
    finally:
        conn.close()
    return {
        "items": [row_to_summary(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def api_mail(key: int) -> dict[str, Any] | None:
    conn = db()
    try:
        row = conn.execute("SELECT * FROM messages WHERE rowid=%s", (key,)).fetchone()
        if not row:
            return None
        attachments = conn.execute(
            "SELECT * FROM attachments WHERE message_rowid=%s ORDER BY part_index",
            (key,),
        ).fetchall()
    finally:
        conn.close()
    result = row_to_summary(row)
    result.update(
        {
            "sender_name": row["sender_name"],
            "sender_email": row["sender_email"],
            "recipients": json.loads(row["recipients_json"] or "[]"),
            "cc": json.loads(row["cc_json"] or "[]"),
            "bcc": json.loads(row["bcc_json"] or "[]"),
            "categories": json.loads(row["categories_json"] or "[]"),
            "body_text": row["body_text"] or "",
            "body_html": row["body_html"] or "",
            "datetime_sent": row["datetime_sent"],
            "datetime_received": row["datetime_received"],
            "importance": row["importance"],
            "raw_size": row["raw_size"],
            "mime_path": row["mime_path"],
            "attachment_items": [
                {
                    "id": attachment["id"],
                    "part_index": attachment["part_index"],
                    "filename": attachment["filename"],
                    "content_type": attachment["content_type"],
                    "content_id": attachment["content_id"],
                    "size": attachment["size"],
                    "sha256": attachment["sha256"],
                    "is_inline": bool(attachment["is_inline"]),
                }
                for attachment in attachments
            ],
        }
    )
    return result


def api_log(limit: int) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    conn = db()
    try:
        ingest = conn.execute(
            "SELECT * FROM ingest_log ORDER BY id DESC LIMIT %s", (limit,)
        ).fetchall()
        events = conn.execute(
            "SELECT * FROM event_log ORDER BY id DESC LIMIT %s", (limit,)
        ).fetchall()
    finally:
        conn.close()
    return {
        "ingest": [dict(row) for row in ingest],
        "events": [dict(row) for row in events],
    }


def api_tags() -> list[str]:
    """Distinct non-empty categories, used by the panel sidebar."""
    conn = db()
    try:
        rows = conn.execute(
            "SELECT categories_json FROM messages "
            "WHERE is_deleted=0 AND categories_json IS NOT NULL "
            "AND categories_json <> '[]'"
        ).fetchall()
    finally:
        conn.close()
    tags: set[str] = set()
    for row in rows:
        for value in json_list(row["categories_json"]):
            text = str(value).strip()
            if text:
                tags.add(text)
    return sorted(tags)


def api_set_read(key: int, is_read: bool) -> bool:
    """Mark one message read/unread locally and mirror it to EWS."""
    conn = db()
    try:
        row = conn.execute(
            "SELECT exchange_id, change_key FROM messages WHERE rowid=%s",
            (key,),
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "UPDATE messages SET is_read=%s, last_seen=%s WHERE rowid=%s",
            (int(is_read), utc_now(), key),
        )
        conn.commit()
    finally:
        conn.close()
    if EWS_ACCOUNT is not None and row["exchange_id"]:
        threading.Thread(
            target=_push_read_state,
            args=(row["exchange_id"], row["change_key"], bool(is_read)),
            daemon=True,
            name=f"push-read-{key}",
        ).start()
    return True


def api_mark_all_read() -> int:
    rows: list[dict[str, Any]] = []
    conn = db()
    try:
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT rowid, exchange_id, change_key "
                "FROM messages WHERE is_read=0 AND is_deleted=0"
            ).fetchall()
        ]
        if rows:
            conn.execute(
                "UPDATE messages SET is_read=1, last_seen=%s "
                "WHERE is_read=0 AND is_deleted=0",
                (utc_now(),),
            )
            conn.commit()
    finally:
        conn.close()
    if rows and EWS_ACCOUNT is not None:
        threading.Thread(
            target=_push_many_read, args=(rows,), daemon=True, name="push-read-all"
        ).start()
    return len(rows)


def _fetch_item(account: Any, row: Any) -> Any:
    from exchangelib.errors import (
        DoesNotExist,
        ErrorInvalidChangeKey,
        ErrorItemNotFound,
    )

    kwargs: dict[str, Any] = {"id": row["exchange_id"]}
    if row.get("change_key"):
        kwargs["changekey"] = row["change_key"]
    try:
        return account.inbox.get(**kwargs)
    except ErrorInvalidChangeKey:
        return account.inbox.get(id=row["exchange_id"])
    except (DoesNotExist, ErrorItemNotFound):
        return None


def _push_read_state(
    exchange_id: str, change_key: str | None, is_read: bool
) -> None:
    """Best-effort mirror of a local read flag onto the Exchange item."""
    if EWS_ACCOUNT is None:
        return
    from exchangelib.errors import (
        DoesNotExist,
        ErrorInvalidChangeKey,
        ErrorItemNotFound,
    )

    try:
        with PANEL_EWS_LOCK:
            kwargs: dict[str, Any] = {"id": exchange_id}
            if change_key:
                kwargs["changekey"] = change_key
            try:
                item = EWS_ACCOUNT.inbox.get(**kwargs)
            except ErrorInvalidChangeKey:
                item = EWS_ACCOUNT.inbox.get(id=exchange_id)
            except (DoesNotExist, ErrorItemNotFound):
                return
            if bool(item.is_read) == is_read:
                return
            item.is_read = is_read
            item.save(update_fields=["is_read"])
            LOG.info(
                "pushed read state to EWS id=%s(read=%s)", bool(exchange_id), is_read
            )
    except Exception as exc:
        LOG.warning(
            "push read state failed id=%s read=%s: %s",
            bool(exchange_id),
            is_read,
            exc,
        )


def _push_many_read(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        if STOP_EVENT.is_set():
            break
        _push_read_state(row["exchange_id"], row["change_key"], True)


def _mailbox_addresses(items: Any) -> list[str]:
    out: list[str] = []
    for item in items or []:
        addr = str(getattr(item, "email_address", "") or "")
        if addr:
            out.append(addr)
    return out


def _reply_all_recipients(account: Any, row: Any) -> list[str]:
    own = (getattr(account, "primary_smtp_address", "") or "").lower()
    candidates = [str(row.get("sender_email") or "")]
    for entry in json_list(row.get("recipients_json")) + json_list(
        row.get("cc_json")
    ):
        candidates.append(
            str(entry.get("email") or "") if isinstance(entry, dict) else str(entry)
        )
    out: list[str] = []
    seen: set[str] = set()
    for addr in candidates:
        addr = addr.strip()
        if not addr or "@" not in addr:
            continue
        if addr.lower() == own or addr.lower() in seen:
            continue
        seen.add(addr.lower())
        out.append(addr)
    return out


def _composed_from_archive(
    account: Any,
    row: Any,
    subject: str,
    body: str,
    to: list[str],
    cc: list[str],
    in_reply: bool = True,
) -> Any:
    """Build a fresh Message for an archived item EWS no longer serves."""
    from exchangelib import Body, Mailbox, Message

    kwargs: dict[str, Any] = {
        "account": account,
        "subject": subject,
        "body": Body(body),
        "to_recipients": [Mailbox(email_address=a) for a in to],
    }
    if cc:
        kwargs["cc_recipients"] = [Mailbox(email_address=a) for a in cc]
    if in_reply and row.get("message_id"):
        kwargs["in_reply_to"] = row["message_id"]
    return Message(**kwargs)


def api_send(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """reply / reply_all / forward / new, sending through EWS."""
    from exchangelib import Body, Mailbox

    action = str(payload.get("action") or "new").strip().lower()
    if action not in {"reply", "reply_all", "forward", "new"}:
        raise ApiError(400, f"unsupported action: {action}")
    body = str(payload.get("body") or "")
    subject = str(payload.get("subject") or "").strip()
    to = address_list(payload.get("to"))
    cc = address_list(payload.get("cc"))
    if action in {"forward", "new"} and not to:
        raise ApiError(400, "收件人不能为空")
    if action in {"reply", "reply_all", "new"} and not body.strip():
        raise ApiError(400, "邮件正文不能为空")

    row = None
    key: int | None = None
    if action != "new":
        try:
            key = int(payload.get("key"))
        except (TypeError, ValueError):
            raise ApiError(400, "缺少邮件 key")
        conn = db()
        try:
            row = conn.execute(
                "SELECT * FROM messages WHERE rowid=%s", (key,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise ApiError(404, "邮件不存在")

    account = EWS_ACCOUNT
    if account is None:
        raise ApiError(503, "EWS account not ready")

    try:
        with PANEL_EWS_LOCK:
            item = _fetch_item(account, row) if row is not None else None
            final_subject = subject
            resolved_to = list(to)
            message_obj = None

            if action == "new":
                final_subject = subject or "(无主题)"
                kwargs: dict[str, Any] = {
                    "account": account,
                    "subject": final_subject,
                    "body": Body(body),
                    "to_recipients": [
                        Mailbox(email_address=a) for a in resolved_to
                    ],
                }
                if cc:
                    kwargs["cc_recipients"] = [
                        Mailbox(email_address=a) for a in cc
                    ]
                from exchangelib import Message

                message_obj = Message(**kwargs)
            elif action == "reply":
                final_subject = subject or prefixed_subject("Re", row["subject"])
                if not resolved_to:
                    author = getattr(item, "author", None) if item else None
                    addr = str(
                        getattr(author, "email_address", "") or ""
                    ) or str(row.get("sender_email") or "")
                    if addr:
                        resolved_to = [addr]
                if item is not None:
                    message_obj = item.create_reply(
                        final_subject,
                        Body(body),
                        to_recipients=(
                            [Mailbox(email_address=a) for a in resolved_to]
                            if resolved_to
                            else None
                        ),
                        cc_recipients=(
                            [Mailbox(email_address=a) for a in cc] if cc else None
                        ),
                    )
                else:
                    if not resolved_to:
                        raise ApiError(400, "无法确定收件人")
                    message_obj = _composed_from_archive(
                        account, row, final_subject, body, resolved_to, cc
                    )
            elif action == "reply_all":
                final_subject = subject or prefixed_subject("Re", row["subject"])
                resolved_to = _reply_all_recipients(account, row)
                if item is not None:
                    message_obj = item.create_reply_all(final_subject, Body(body))
                else:
                    if not resolved_to:
                        raise ApiError(400, "无法确定收件人")
                    message_obj = _composed_from_archive(
                        account, row, final_subject, body, resolved_to, []
                    )
            else:  # forward
                final_subject = subject or prefixed_subject("Fw", row["subject"])
                if item is not None:
                    message_obj = item.create_forward(
                        final_subject,
                        Body(body),
                        to_recipients=[Mailbox(email_address=a) for a in to],
                        cc_recipients=(
                            [Mailbox(email_address=a) for a in cc] if cc else None
                        ),
                    )
                else:
                    message_obj = _composed_from_archive(
                        account, row, final_subject, body, to, cc, in_reply=False
                    )

            if dry_run:
                return {
                    "ok": True,
                    "dry_run": True,
                    "action": action,
                    "key": key,
                    "subject": getattr(message_obj, "subject", final_subject),
                    "to": resolved_to or to,
                    "type": type(message_obj).__name__,
                }
            message_obj.send()
    except ApiError:
        raise
    except Exception as exc:
        if not dry_run:
            log_ingest(False, "panel_send", 0, str(exc))
        raise ApiError(502, f"EWS 发送失败: {str(exc)[:200]}")

    log_ingest(True, "panel_send", 1)
    LOG.info(
        "panel sent action=%s key=%s to=%s subject=%s",
        action,
        key,
        resolved_to or to,
        final_subject,
    )
    return {
        "ok": True,
        "action": action,
        "key": key,
        "subject": final_subject,
        "to": resolved_to or to,
    }


def safe_archive_path(relative: str) -> Path:
    path = (ARCHIVE_DIR / relative).resolve()
    root = ARCHIVE_DIR.resolve()
    if os.path.commonpath((str(path), str(root))) != str(root):
        raise ValueError("path outside archive")
    return path


def content_disposition(filename: str, inline: bool) -> str:
    fallback = re.sub(r"[^\x20-\x7e]", "_", filename).replace('"', "'")
    encoded = urllib.parse.quote(filename, safe="")
    disposition = "inline" if inline else "attachment"
    return f'{disposition}; filename="{fallback}"; filename*=UTF-8\'\'{encoded}'


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "MailwatchEWS/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.debug("api " + fmt, *args)

    def authorized(self, query: dict[str, str]) -> bool:
        provided = self.headers.get("X-Panel-Token") or query.get("token")
        if not panel_auth_enabled():
            return True
        if PANEL_TOKEN and token_ok(PANEL_TOKEN, provided):
            return True
        return panel_session_ok(provided)

    def read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(400, "invalid Content-Length")
        if length <= 0:
            raise ApiError(400, "missing request body")
        if length > 1_048_576:
            raise ApiError(413, "request body too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError(400, "invalid JSON body")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON object required")
        return data

    def send_panel(self) -> None:
        try:
            data = PANEL_PATH.read_bytes()
        except FileNotFoundError:
            raise ApiError(404, "index.html not found next to ews_worker.py")
        self.send_bytes(200, data, "text/html; charset=utf-8")

    def send_json(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_bytes(
        self,
        status: int,
        data: bytes,
        content_type: str,
        disposition: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        path = parsed.path.rstrip("/") or "/"
        try:
            if path in {"/", "/mail"}:
                self.send_panel()
                return
            if not self.authorized(query):
                raise ApiError(401, "unauthorized")
            if path in {"/", "/health", "/api/health"}:
                self.send_json(200, {"status": "ok", **api_summary()})
            elif path == "/api/summary":
                self.send_json(200, api_summary())
            elif path == "/api/mails":
                try:
                    limit = int(query.get("limit", "50"))
                    offset = int(query.get("offset", "0"))
                except ValueError:
                    raise ApiError(400, "limit/offset must be integers")
                self.send_json(
                    200, api_mails(limit, query.get("q"), offset)
                )
            elif path == "/api/log":
                try:
                    limit = int(query.get("limit", "40"))
                except ValueError:
                    raise ApiError(400, "limit must be an integer")
                self.send_json(200, api_log(limit))
            elif path == "/api/tags":
                self.send_json(200, {"items": api_tags()})
            elif path.startswith("/api/mail/"):
                try:
                    key = int(path.rsplit("/", 1)[-1])
                except ValueError:
                    raise ApiError(400, "invalid message key")
                payload = api_mail(key)
                if payload is None:
                    self.send_json(404, {"error": "mail not found"})
                else:
                    self.send_json(200, payload)
            elif path.startswith("/api/att/") or path.startswith("/api/img/"):
                parts = path.split("/")
                try:
                    key = int(parts[3])
                    attachment_id = int(parts[4])
                except (IndexError, ValueError):
                    raise ApiError(400, "invalid attachment path")
                conn = db()
                try:
                    row = conn.execute(
                        "SELECT a.*, m.rowid AS message_rowid FROM attachments a "
                        "JOIN messages m ON m.rowid=a.message_rowid "
                        "WHERE m.rowid=%s AND a.id=%s",
                        (key, attachment_id),
                    ).fetchone()
                finally:
                    conn.close()
                if not row:
                    self.send_json(404, {"error": "attachment not found"})
                    return
                file_path = safe_archive_path(row["path"])
                data = file_path.read_bytes()
                content_type = (row["content_type"] or "").strip()
                if not content_type or content_type == "application/octet-stream":
                    # 邮件源常把 PDF/图片标成 octet-stream，会让浏览器改成下载而非内嵌
                    content_type = (
                        mimetypes.guess_type(row["filename"] or "")[0]
                        or content_type
                        or "application/octet-stream"
                    )
                inline = path.startswith("/api/img/") or bool(row["is_inline"])
                self.send_bytes(
                    200,
                    data,
                    content_type,
                    content_disposition(row["filename"] or "attachment", inline),
                )
            elif path.startswith("/api/mime/"):
                try:
                    key = int(path.rsplit("/", 1)[-1])
                except ValueError:
                    raise ApiError(400, "invalid message key")
                conn = db()
                try:
                    row = conn.execute(
                        "SELECT mime_path FROM messages WHERE rowid=%s", (key,)
                    ).fetchone()
                finally:
                    conn.close()
                if not row or not row["mime_path"]:
                    self.send_json(404, {"error": "mime not found"})
                    return
                file_path = safe_archive_path(row["mime_path"])
                data = gzip.decompress(file_path.read_bytes())
                self.send_bytes(
                    200,
                    data,
                    "message/rfc822",
                    content_disposition("message.eml", False),
                )
            else:
                raise ApiError(404, "not found")
        except ApiError as exc:
            self.send_json(exc.status, {"error": exc.message})
        except ValueError as exc:
            # address parsing, path traversal checks, bad ids, ...
            self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            LOG.exception("API request failed path=%s", path)
            self.send_json(500, {"error": str(exc)[:300]})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        path = parsed.path.rstrip("/") or "/"
        try:
            if path == "/api/login":
                payload = self.read_json_body()
                session = panel_login(
                    payload.get("username"),
                    payload.get("password"),
                )
                self.send_json(
                    200,
                    {
                        "ok": True,
                        "token": session,
                        "expires_in": PANEL_SESSION_TTL_SECONDS,
                    },
                )
                return
            if not self.authorized(query):
                raise ApiError(401, "unauthorized")
            if path == "/api/logout":
                provided = self.headers.get("X-Panel-Token") or query.get("token")
                panel_logout(provided)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/send":
                payload = self.read_json_body()
                dry = bool(payload.get("dry_run"))
                self.send_json(200, api_send(payload, dry_run=dry))
                return
            if path == "/api/mails/read":
                updated = api_mark_all_read()
                self.send_json(200, {"ok": True, "updated": updated})
                return
            match = re.fullmatch(r"/api/mail/(\d+)/read", path)
            if match:
                key = int(match.group(1))
                body = self.read_json_body()
                if "read" not in body:
                    raise ApiError(400, "missing read flag")
                is_read = bool(body["read"])
                if not api_set_read(key, is_read):
                    raise ApiError(404, "mail not found")
                self.send_json(
                    200, {"ok": True, "key": key, "read": is_read}
                )
                return
            raise ApiError(404, "not found")
        except ApiError as exc:
            self.send_json(exc.status, {"error": exc.message})
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            LOG.exception("POST failed path=%s", path)
            self.send_json(500, {"error": str(exc)[:300]})


def install_signal_handlers() -> None:
    def stop_handler(signum: int, frame: Any) -> None:
        LOG.info("received signal=%s, stopping", signum)
        STOP_EVENT.set()
        SYNC_EVENT.set()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)


def main() -> int:
    global EWS_ACCOUNT

    logging.basicConfig(
        level=os.environ.get("MAILWATCH_EWS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    install_signal_handlers()
    init_db()
    try:
        enforce_storage_limit()
    except Exception:
        LOG.exception("startup storage cleanup failed")
    config = load_config()
    MAIL_SETTINGS.update(config)
    LOG.info(
        "starting mailwatch-ews base=%s api=%s:%s stream_timeout=%sm "
        "sync=%ss panel=%s",
        BASE_DIR,
        API_HOST,
        API_PORT,
        STREAM_TIMEOUT_MINUTES,
        FALLBACK_SYNC_SECONDS,
        PANEL_PATH if PANEL_PATH.exists() else "missing",
    )

    server = ThreadingHTTPServer((API_HOST, API_PORT), ApiHandler)
    server.daemon_threads = True
    api_thread = threading.Thread(target=server.serve_forever, daemon=True)
    api_thread.start()

    try:
        account = build_account(config)
        EWS_ACCOUNT = account
        LOG.info("EWS account created")
        if INITIAL_BACKFILL:
            initial_backfill(account)
        else:
            update_state(backfill_done=meta_get("backfill_done") == "1")
        prime_sync_state(account)
        if INITIAL_BACKFILL:
            meta_set("backfill_done", "1")
        sync_incremental(account)
        update_state(phase="running")
        LOG.info("initial synchronization complete")
    except Exception:
        update_state(phase="failed")
        LOG.exception("initial EWS setup failed")
        server.shutdown()
        return 1

    threads = [
        threading.Thread(target=stream_worker, args=(account,), daemon=True),
        threading.Thread(target=sync_worker, args=(account,), daemon=True),
        threading.Thread(target=cleanup_worker, daemon=True),
    ]
    for thread in threads:
        thread.start()

    try:
        while not STOP_EVENT.is_set():
            time.sleep(1)
    finally:
        STOP_EVENT.set()
        SYNC_EVENT.set()
        # Total shutdown budget must stay well under supervisor's
        # stopwaitsecs (35s), otherwise supervisord resorts to SIGKILL.
        # Joins are sequential, so cap their *combined* wait, not each one.
        deadline = time.monotonic() + 20
        for thread in threads:
            thread.join(timeout=max(0.1, deadline - time.monotonic()))
        server.shutdown()
        server.server_close()
    LOG.info("mailwatch-ews stopped")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
