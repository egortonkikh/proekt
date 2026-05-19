"""Парсинг Apache access log и импорт в SQLite."""

from __future__ import annotations

import fnmatch
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from database import BASE_DIR, _utc_now, load_config

COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)\s*'
    r'(?:"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    r'\s*$'
)

COMMON_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)\s*$'
)

REQUEST_PATTERN = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<protocol>\S+))?$'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class ParseLineError(Exception):
    pass


@dataclass
class ParsedLogLine:
    ip_address: str
    remote_user: str | None
    timestamp: datetime
    method: str
    url: str
    protocol: str | None
    status_code: int
    response_size: int
    referer: str | None
    user_agent: str | None
    raw_line: str


class ApacheLogParser:
    def __init__(self, log_format: str = "combined") -> None:
        fmt = log_format.lower()
        if fmt not in ("combined", "common"):
            raise ValueError(f"Неподдерживаемый формат: {log_format}")
        self._pattern = COMBINED_PATTERN if fmt == "combined" else COMMON_PATTERN

    def parse_line(self, line: str) -> ParsedLogLine:
        stripped = line.rstrip("\n\r")
        if not stripped or stripped.startswith("#"):
            raise ParseLineError("пустая строка")

        match = self._pattern.match(stripped)
        if not match:
            raise ParseLineError("неверный формат")

        groups = match.groupdict()
        timestamp = datetime.strptime(groups["time"], TIME_FORMAT)

        req_match = REQUEST_PATTERN.match(groups.get("request") or "")
        if not req_match:
            raise ParseLineError("неверный запрос")

        req = req_match.groupdict()
        user = groups.get("user")
        remote_user = None if user in (None, "-") else user

        status_raw = groups.get("status") or "-"
        status_code = int(status_raw) if status_raw.isdigit() else 0

        size_raw = groups.get("size") or "-"
        response_size = int(size_raw) if size_raw.isdigit() else 0

        referer = groups.get("referer")
        if referer == "-":
            referer = None
        agent = groups.get("agent")
        if agent == "-":
            agent = None

        return ParsedLogLine(
            ip_address=groups["ip"],
            remote_user=remote_user,
            timestamp=timestamp,
            method=req["method"],
            url=req["url"],
            protocol=req.get("protocol"),
            status_code=status_code,
            response_size=response_size,
            referer=referer,
            user_agent=agent,
            raw_line=stripped,
        )


def discover_log_files() -> list[Path]:
    cfg = load_config()
    logs_cfg = cfg.get("logs", {})
    directory = BASE_DIR / logs_cfg.get("directory", "logs")
    mask = logs_cfg.get("file_mask", "access*.log")
    if not directory.exists():
        directory.mkdir(parents=True, exist_ok=True)
        return []
    files = sorted(p for p in directory.iterdir() if p.is_file() and fnmatch.fnmatch(p.name, mask))
    return files


def _get_offset(conn: sqlite3.Connection, source_file: str) -> int:
    row = conn.execute(
        "SELECT byte_offset FROM file_offsets WHERE source_file = ?", (source_file,)
    ).fetchone()
    return int(row["byte_offset"]) if row else 0


def _set_offset(conn: sqlite3.Connection, source_file: str, offset: int) -> None:
    conn.execute(
        """
        INSERT INTO file_offsets (source_file, byte_offset, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(source_file) DO UPDATE SET
            byte_offset = excluded.byte_offset,
            updated_at = excluded.updated_at
        """,
        (source_file, offset, _utc_now()),
    )


def import_logs(conn: sqlite3.Connection, *, full: bool = False) -> dict[str, Any]:
    cfg = load_config()
    logs_cfg = cfg.get("logs", {})
    parser = ApacheLogParser(logs_cfg.get("format", "combined"))
    files = discover_log_files()

    if full:
        conn.execute("DELETE FROM file_offsets")
        conn.execute("DELETE FROM access_logs")

    cur = conn.execute(
        "INSERT INTO import_jobs (started_at, status) VALUES (?, ?)",
        (_utc_now(), "running"),
    )
    job_id = cur.lastrowid
    imported = 0
    skipped = 0
    messages: list[str] = []

    insert_sql = """
        INSERT OR IGNORE INTO access_logs (
            ip_address, remote_user, timestamp, method, url, protocol,
            status_code, response_size, referer, user_agent,
            source_file, line_number, raw_line, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    for path in files:
        source_key = str(path.relative_to(BASE_DIR)).replace("\\", "/")
        start_offset = 0 if full else _get_offset(conn, source_key)
        file_imported = 0

        with path.open("rb") as fh:
            if start_offset:
                prefix = fh.read(start_offset)
                line_no = prefix.count(b"\n")
                fh.seek(start_offset)
            else:
                line_no = 0

            while True:
                raw = fh.readline()
                if not raw:
                    break
                line_no += 1
                try:
                    text = raw.decode("utf-8", errors="replace")
                    parsed = parser.parse_line(text)
                except ParseLineError:
                    skipped += 1
                    continue

                cur = conn.execute(
                    insert_sql,
                    (
                        parsed.ip_address,
                        parsed.remote_user,
                        parsed.timestamp.isoformat(),
                        parsed.method,
                        parsed.url,
                        parsed.protocol,
                        parsed.status_code,
                        parsed.response_size,
                        parsed.referer,
                        parsed.user_agent,
                        source_key,
                        line_no,
                        parsed.raw_line,
                        _utc_now(),
                    ),
                )
                if cur.rowcount:
                    imported += 1
                    file_imported += 1

            new_offset = fh.tell()

        _set_offset(conn, source_key, new_offset)
        messages.append(f"{source_key}: +{file_imported} (offset {new_offset})")

    status = "done"
    message = "; ".join(messages) if messages else "Нет файлов для импорта"
    conn.execute(
        """
        UPDATE import_jobs
        SET finished_at = ?, status = ?, imported_lines = ?, skipped_lines = ?, message = ?
        WHERE id = ?
        """,
        (_utc_now(), status, imported, skipped, message, job_id),
    )

    return {
        "job_id": job_id,
        "imported": imported,
        "skipped": skipped,
        "message": message,
        "files": len(files),
    }
