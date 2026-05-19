"""SQLite: создание project.db и доступ к данным."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"


def load_config() -> dict[str, Any]:
    with CONFIG_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def db_path() -> Path:
    cfg = load_config()
    return BASE_DIR / cfg.get("database", "project.db")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, expected = stored.split("$", 1)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return secrets.compare_digest(digest.hex(), expected)


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    remote_user TEXT,
    timestamp TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    protocol TEXT,
    status_code INTEGER NOT NULL,
    response_size INTEGER NOT NULL DEFAULT 0,
    referer TEXT,
    user_agent TEXT,
    source_file TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    raw_line TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(source_file, line_number)
);

CREATE INDEX IF NOT EXISTS ix_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS ix_access_logs_ip ON access_logs(ip_address);
CREATE INDEX IF NOT EXISTS ix_access_logs_status ON access_logs(status_code);

CREATE TABLE IF NOT EXISTS import_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    imported_lines INTEGER NOT NULL DEFAULT 0,
    skipped_lines INTEGER NOT NULL DEFAULT 0,
    message TEXT
);

CREATE TABLE IF NOT EXISTS file_offsets (
    source_file TEXT PRIMARY KEY,
    byte_offset INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""


def get_connection() -> sqlite3.Connection:
    path = db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_session() -> Generator[sqlite3.Connection, None, None]:
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> Path:
    """Создаёт project.db, таблицы и пользователя по умолчанию."""
    path = db_path()
    with db_session() as conn:
        conn.executescript(SCHEMA)
        cfg = load_config()
        auth = cfg.get("auth", {})
        username = auth.get("username", "admin")
        password = auth.get("password", "admin123")
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, hash_password(password), _utc_now()),
            )
    return path


def get_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    total = conn.execute("SELECT COUNT(*) AS c FROM access_logs").fetchone()["c"]
    top_ips = conn.execute(
        """
        SELECT ip_address, COUNT(*) AS hits
        FROM access_logs
        GROUP BY ip_address
        ORDER BY hits DESC
        LIMIT 10
        """
    ).fetchall()
    top_urls = conn.execute(
        """
        SELECT url, COUNT(*) AS hits
        FROM access_logs
        GROUP BY url
        ORDER BY hits DESC
        LIMIT 10
        """
    ).fetchall()
    by_status = conn.execute(
        """
        SELECT status_code, COUNT(*) AS hits
        FROM access_logs
        GROUP BY status_code
        ORDER BY hits DESC
        """
    ).fetchall()
    last_job = conn.execute(
        "SELECT * FROM import_jobs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return {
        "total_entries": total,
        "top_ips": [dict(r) for r in top_ips],
        "top_urls": [dict(r) for r in top_urls],
        "by_status": [dict(r) for r in by_status],
        "last_job": dict(last_job) if last_job else None,
    }


if __name__ == "__main__":
    created = init_db()
    print(f"База данных создана: {created}")
