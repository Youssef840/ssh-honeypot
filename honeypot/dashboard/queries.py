"""
Read-only analytics queries for the dashboard.

All functions take an open sqlite3 connection (row_factory=sqlite3.Row) and
return plain Python structures, so they are trivially reusable from the JSON
API, the HTML views, or a Jupyter notebook.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from ..analysis import TAG_TECHNIQUES

# Weights for the "most dangerous IP" score. Tune to taste.
W_ATTEMPT = 1  # each login attempt
W_SUCCESS = 15  # each successful login (attacker got a shell)
W_COMMAND = 2  # each command typed
W_RISK = 3  # each risk point from analysis rules
W_IOC = 10  # each URL / C2 IP dropped


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _one(conn: sqlite3.Connection, sql: str, params: tuple = ()):
    row = conn.execute(sql, params).fetchone()
    return row[0] if row and row[0] is not None else 0


def _since(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
def summary(conn) -> dict:
    day = _since(24)
    return {
        "sessions": _one(conn, "SELECT COUNT(*) FROM sessions"),
        "auth_attempts": _one(conn, "SELECT COUNT(*) FROM auth_attempts"),
        "failed_logins": _one(conn, "SELECT COUNT(*) FROM auth_attempts WHERE success=0"),
        "successful_logins": _one(conn, "SELECT COUNT(*) FROM auth_attempts WHERE success=1"),
        "unique_ips": _one(conn, "SELECT COUNT(DISTINCT src_ip) FROM sessions"),
        "commands": _one(conn, "SELECT COUNT(*) FROM commands"),
        "iocs": _one(conn, "SELECT COUNT(DISTINCT value) FROM iocs WHERE ioc_type='url'"),
        "attempts_24h": _one(conn, "SELECT COUNT(*) FROM auth_attempts WHERE ts>=?", (day,)),
        "ips_24h": _one(conn, "SELECT COUNT(DISTINCT src_ip) FROM sessions WHERE started_at>=?", (day,)),
        "avg_session": round(float(_one(conn, "SELECT AVG(duration) FROM sessions WHERE duration IS NOT NULL")), 1),
    }


def timeline(conn, hours: int = 24) -> dict:
    """Attempts per bucket. <=48h -> hourly buckets, otherwise daily."""
    hourly = hours <= 48
    fmt_sql = "%Y-%m-%d %H:00" if hourly else "%Y-%m-%d"
    rows = conn.execute(
        f"""SELECT strftime('{fmt_sql}', ts) AS bucket,
                   COUNT(*)                   AS attempts,
                   SUM(success)               AS successes
            FROM auth_attempts WHERE ts >= ? GROUP BY bucket""",
        (_since(hours),),
    ).fetchall()
    data = {r["bucket"]: (r["attempts"], r["successes"] or 0) for r in rows}

    now = datetime.now(timezone.utc)
    labels, attempts, successes = [], [], []
    if hourly:
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours - 1)
        steps = [start + timedelta(hours=i) for i in range(hours)]
        py_fmt = "%Y-%m-%d %H:00"
    else:
        days = max(1, hours // 24)
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
        steps = [start + timedelta(days=i) for i in range(days)]
        py_fmt = "%Y-%m-%d"
    for step in steps:
        key = step.strftime(py_fmt)
        a, s = data.get(key, (0, 0))
        labels.append(step.strftime("%H:00" if hourly else "%m-%d"))
        attempts.append(a)
        successes.append(s)
    return {"labels": labels, "attempts": attempts, "successes": successes}


def top_ips(conn, limit: int = 10, ip: str | None = None) -> list[dict]:
    where = "WHERE s.src_ip = ?" if ip else ""
    params = (ip, limit) if ip else (limit,)
    return _rows(
        conn,
        f"""
        WITH s AS (SELECT src_ip, COUNT(*) AS sessions, MIN(started_at) AS first_seen,
                          MAX(started_at) AS last_seen, MAX(login_success) AS got_shell
                   FROM sessions GROUP BY src_ip),
             a AS (SELECT src_ip, COUNT(*) AS attempts, SUM(success) AS successes
                   FROM auth_attempts GROUP BY src_ip),
             c AS (SELECT src_ip, COUNT(*) AS cmds, SUM(risk) AS risk_sum, MAX(risk) AS max_risk
                   FROM commands GROUP BY src_ip),
             i AS (SELECT src_ip, COUNT(DISTINCT value) AS iocs FROM iocs GROUP BY src_ip)
        SELECT s.src_ip, s.sessions, s.first_seen, s.last_seen, s.got_shell,
               COALESCE(a.attempts, 0)  AS attempts,
               COALESCE(a.successes, 0) AS successes,
               COALESCE(c.cmds, 0)      AS commands,
               COALESCE(c.risk_sum, 0)  AS risk_sum,
               COALESCE(c.max_risk, 0)  AS max_risk,
               COALESCE(i.iocs, 0)      AS iocs,
               ( COALESCE(a.attempts, 0)  * {W_ATTEMPT}
               + COALESCE(a.successes, 0) * {W_SUCCESS}
               + COALESCE(c.cmds, 0)      * {W_COMMAND}
               + COALESCE(c.risk_sum, 0)  * {W_RISK}
               + COALESCE(i.iocs, 0)      * {W_IOC} ) AS score
        FROM s
        LEFT JOIN a ON a.src_ip = s.src_ip
        LEFT JOIN c ON c.src_ip = s.src_ip
        LEFT JOIN i ON i.src_ip = s.src_ip
        {where}
        ORDER BY score DESC, s.last_seen DESC
        LIMIT ?""",
        params,
    )


CRITICAL_RISK = 10  # one command line reaching this (reverse shell, miner, dropper chain…)
PERSISTENT_ATTEMPTS = 20


def threat_level(row: dict) -> str:
    """Classify an attacker by *what they did*, not by volume.

    The numeric ``score`` orders the ranking; the level answers "how worried
    should I be?" — a noisy brute-forcer must not look as bad as an attacker
    who got in and launched a cryptominer.

    * critical — ran a high-impact command (risk >= 10 in a single line)
    * high     — got a shell and executed commands or dropped IOCs
    * medium   — logged in (no activity), or brute-forced persistently
    * low      — a handful of failed guesses or a port scan
    """
    successes = row.get("successes", 0) or 0
    if (row.get("max_risk", 0) or 0) >= CRITICAL_RISK:
        return "critical"
    if successes and ((row.get("commands", 0) or 0) or (row.get("iocs", 0) or 0)):
        return "high"
    if successes or (row.get("attempts", 0) or 0) >= PERSISTENT_ATTEMPTS:
        return "medium"
    return "low"


def top_values(conn, column: str, limit: int = 10) -> list[dict]:
    allowed = {"username", "password"}
    if column not in allowed:  # column names cannot be bound parameters
        raise ValueError(column)
    return _rows(
        conn,
        f"""
        SELECT {column} AS value, COUNT(*) AS count
        FROM auth_attempts WHERE method='password' AND {column} IS NOT NULL
        GROUP BY {column} ORDER BY count DESC LIMIT ?""",
        (limit,),
    )


def top_combos(conn, limit: int = 10) -> list[dict]:
    return _rows(
        conn,
        """
        SELECT username, password, COUNT(*) AS count, MAX(success) AS worked
        FROM auth_attempts WHERE method='password'
        GROUP BY username, password ORDER BY count DESC LIMIT ?""",
        (limit,),
    )


def top_commands(conn, limit: int = 10) -> list[dict]:
    return _rows(
        conn,
        """
        SELECT command, COUNT(*) AS count, MAX(risk) AS risk
        FROM commands GROUP BY command ORDER BY count DESC LIMIT ?""",
        (limit,),
    )


def tag_breakdown(conn) -> list[dict]:
    """Count of commands per behaviour tag, with its MITRE ATT&CK technique id."""
    counts: dict[str, int] = {}
    for (tags,) in conn.execute("SELECT tags FROM commands WHERE tags != ''"):
        for tag in tags.split(","):
            counts[tag] = counts.get(tag, 0) + 1
    return [
        {"tag": t, "count": c, "technique": TAG_TECHNIQUES.get(t, "")}
        for t, c in sorted(counts.items(), key=lambda kv: -kv[1])
    ]


def client_versions(conn, limit: int = 8) -> list[dict]:
    return _rows(
        conn,
        """
        SELECT COALESCE(client_version, '(none)') AS value, COUNT(*) AS count
        FROM sessions GROUP BY value ORDER BY count DESC LIMIT ?""",
        (limit,),
    )


def recent_iocs(conn, limit: int = 15) -> list[dict]:
    return _rows(
        conn,
        """
        SELECT ioc_type, value, COUNT(*) AS hits, MAX(ts) AS last_seen,
               COUNT(DISTINCT src_ip) AS ips
        FROM iocs GROUP BY ioc_type, value ORDER BY last_seen DESC LIMIT ?""",
        (limit,),
    )


def recent_sessions(
    conn, limit: int = 15, offset: int = 0, ip: str | None = None, only_logged_in: bool = False
) -> list[dict]:
    where, params = [], []
    if ip:
        where.append("s.src_ip = ?")
        params.append(ip)
    if only_logged_in:
        where.append("s.login_success = 1")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    return _rows(
        conn,
        f"""
        SELECT s.*,
               (SELECT COUNT(*) FROM auth_attempts a WHERE a.session_id = s.id) AS attempts,
               (SELECT COUNT(*) FROM commands c WHERE c.session_id = s.id)      AS commands,
               (SELECT COALESCE(SUM(risk),0) FROM commands c WHERE c.session_id = s.id) AS risk
        FROM sessions s {clause}
        ORDER BY s.started_at DESC LIMIT ? OFFSET ?""",
        (*params, limit, offset),
    )


def count_sessions(conn, ip: str | None = None, only_logged_in: bool = False) -> int:
    where, params = [], []
    if ip:
        where.append("src_ip = ?")
        params.append(ip)
    if only_logged_in:
        where.append("login_success = 1")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    return _one(conn, f"SELECT COUNT(*) FROM sessions {clause}", tuple(params))


def session_detail(conn, sid: str) -> dict | None:
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
    if row is None:
        return None
    return {
        "session": dict(row),
        "auth": _rows(conn, "SELECT * FROM auth_attempts WHERE session_id=? ORDER BY id", (sid,)),
        "commands": _rows(conn, "SELECT * FROM commands WHERE session_id=? ORDER BY id", (sid,)),
        "iocs": _rows(conn, "SELECT * FROM iocs WHERE session_id=? ORDER BY id", (sid,)),
    }


def ip_detail(conn, ip: str) -> dict:
    return {
        "ip": ip,
        "stats": next(iter(top_ips(conn, 1, ip=ip)), None),
        "credentials": _rows(
            conn,
            """
            SELECT username, password, method, COUNT(*) AS count, MAX(success) AS worked
            FROM auth_attempts WHERE src_ip=? GROUP BY username, password, method
            ORDER BY count DESC LIMIT 100""",
            (ip,),
        ),
        "commands": _rows(
            conn,
            """
            SELECT ts, command, risk, tags, session_id FROM commands
            WHERE src_ip=? ORDER BY id DESC LIMIT 200""",
            (ip,),
        ),
        "iocs": _rows(conn, "SELECT DISTINCT ioc_type, value FROM iocs WHERE src_ip=?", (ip,)),
        "sessions": recent_sessions(conn, limit=50, ip=ip),
    }
