"""
Persistence layer (SQLite + optional JSON-lines feed).

Design notes
------------
* One shared connection guarded by a lock. The honeypot is I/O bound (network
  waits dominate), so serialized writes are never the bottleneck, and SQLite
  in WAL mode lets the dashboard read concurrently without blocking writers.
* All timestamps are UTC, stored as 'YYYY-MM-DD HH:MM:SS' so SQLite's
  strftime() can bucket them directly for charts.
* Every event is also appended to `events.jsonl` (one JSON object per line),
  which can be shipped to a SIEM (ELK / Splunk / Wazuh) as-is.
* Attacker-controlled strings are always passed as bound parameters — never
  formatted into SQL — so a password like `'); DROP TABLE x;--` is harmless.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("honeypot.db")

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,
    src_ip         TEXT    NOT NULL,
    src_port       INTEGER,
    client_version TEXT,
    started_at     TEXT    NOT NULL,
    ended_at       TEXT,
    duration       REAL,
    login_success  INTEGER NOT NULL DEFAULT 0,
    username       TEXT,
    password       TEXT,
    term           TEXT,
    end_reason     TEXT
);

CREATE TABLE IF NOT EXISTS auth_attempts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    src_ip          TEXT    NOT NULL,
    ts              TEXT    NOT NULL,
    method          TEXT    NOT NULL,          -- password | publickey
    username        TEXT,
    password        TEXT,
    key_type        TEXT,
    key_fingerprint TEXT,
    success         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT    NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    src_ip     TEXT    NOT NULL,
    ts         TEXT    NOT NULL,
    command    TEXT    NOT NULL,
    kind       TEXT    NOT NULL DEFAULT 'shell', -- shell | exec
    known      INTEGER NOT NULL DEFAULT 1,       -- emulated by fake shell?
    risk       INTEGER NOT NULL DEFAULT 0,
    tags       TEXT    NOT NULL DEFAULT ''        -- comma separated
);

CREATE TABLE IF NOT EXISTS iocs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    src_ip     TEXT NOT NULL,
    ts         TEXT NOT NULL,
    ioc_type   TEXT NOT NULL,   -- url | ip
    value      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_ip      ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_auth_ip          ON auth_attempts(src_ip);
CREATE INDEX IF NOT EXISTS idx_auth_ts          ON auth_attempts(ts);
CREATE INDEX IF NOT EXISTS idx_auth_session     ON auth_attempts(session_id);
CREATE INDEX IF NOT EXISTS idx_cmd_session      ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_cmd_ip           ON commands(src_ip);
CREATE INDEX IF NOT EXISTS idx_ioc_value        ON iocs(value);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def new_session_id() -> str:
    return uuid.uuid4().hex[:16]


class EventStore:
    """Thread-safe writer used by the honeypot engine.

    Storage failures (disk full, locked database...) are logged and swallowed:
    losing one event is better than crashing an attacker session and tipping
    them off. Calls made after :meth:`close` are silently ignored, so session
    threads still running during shutdown cannot raise.
    """

    def __init__(self, db_path: Path, jsonl_path: Path | None = None):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._closed = False
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None, timeout=10)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()
        self._jsonl = None
        if jsonl_path is not None:
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._jsonl = open(jsonl_path, "a", encoding="utf-8", buffering=1)

    def _migrate(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"Database schema v{version} is newer than this code (v{SCHEMA_VERSION})")
        self._conn.executescript(SCHEMA)
        # future migrations go here:  if version < 2: ALTER TABLE ...
        self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------------ utils
    def _exec(self, sql: str, params: tuple[Any, ...]) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._conn.execute(sql, params)
            except sqlite3.Error:
                log.exception("database write failed: %s", sql.split("(")[0].strip())

    def _emit(self, event: str, **data: Any) -> None:
        if self._jsonl is None:
            return
        record = {"ts": utc_now(), "event": event, **data}
        with self._lock:
            if self._closed:
                return
            try:
                self._jsonl.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError:
                log.exception("jsonl write failed")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conn.close()
            if self._jsonl:
                self._jsonl.close()

    def prune(self, days: int) -> int:
        """Delete sessions (and, via ON DELETE CASCADE, their events) older than ``days``.
        Returns the number of sessions removed."""
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            if self._closed:
                return 0
            cur = self._conn.execute("DELETE FROM sessions WHERE started_at < ?", (cutoff,))
            return cur.rowcount

    # --------------------------------------------------------------- sessions
    def create_session(self, src_ip: str, src_port: int) -> str:
        sid = new_session_id()
        self._exec(
            "INSERT INTO sessions (id, src_ip, src_port, started_at) VALUES (?, ?, ?, ?)",
            (sid, src_ip, src_port, utc_now()),
        )
        self._emit("session.connect", session=sid, src_ip=src_ip, src_port=src_port)
        return sid

    def set_client_version(self, sid: str, version: str) -> None:
        self._exec("UPDATE sessions SET client_version=? WHERE id=?", (version[:200], sid))
        self._emit("session.client_version", session=sid, version=version[:200])

    def set_term(self, sid: str, term: str) -> None:
        self._exec("UPDATE sessions SET term=? WHERE id=?", (term[:64], sid))

    def mark_login(self, sid: str, username: str, password: str) -> None:
        self._exec(
            "UPDATE sessions SET login_success=1, username=?, password=? WHERE id=?",
            (username, password, sid),
        )

    def end_session(self, sid: str, duration: float, reason: str) -> None:
        self._exec(
            "UPDATE sessions SET ended_at=?, duration=?, end_reason=? WHERE id=?",
            (utc_now(), round(duration, 2), reason, sid),
        )
        self._emit("session.closed", session=sid, duration=round(duration, 2), reason=reason)

    # ------------------------------------------------------------------- auth
    def log_auth(
        self,
        sid: str,
        src_ip: str,
        method: str,
        username: str,
        success: bool,
        password: str | None = None,
        key_type: str | None = None,
        key_fingerprint: str | None = None,
    ) -> None:
        self._exec(
            """INSERT INTO auth_attempts
               (session_id, src_ip, ts, method, username, password, key_type, key_fingerprint, success)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (sid, src_ip, utc_now(), method, username, password, key_type, key_fingerprint, int(success)),
        )
        self._emit(
            "auth.success" if success else "auth.failed",
            session=sid,
            src_ip=src_ip,
            method=method,
            username=username,
            password=password,
            key_type=key_type,
            key_fingerprint=key_fingerprint,
        )

    # --------------------------------------------------------------- commands
    def log_command(
        self,
        sid: str,
        src_ip: str,
        command: str,
        kind: str,
        known: bool,
        risk: int,
        tags: tuple[str, ...],
    ) -> None:
        self._exec(
            """INSERT INTO commands (session_id, src_ip, ts, command, kind, known, risk, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (sid, src_ip, utc_now(), command, kind, int(known), risk, ",".join(tags)),
        )
        self._emit(
            "command.input",
            session=sid,
            src_ip=src_ip,
            command=command,
            kind=kind,
            known=known,
            risk=risk,
            tags=list(tags),
        )

    def log_ioc(self, sid: str, src_ip: str, ioc_type: str, value: str) -> None:
        self._exec(
            "INSERT INTO iocs (session_id, src_ip, ts, ioc_type, value) VALUES (?, ?, ?, ?, ?)",
            (sid, src_ip, utc_now(), ioc_type, value[:2048]),
        )
        self._emit("ioc", session=sid, src_ip=src_ip, ioc_type=ioc_type, value=value[:2048])
