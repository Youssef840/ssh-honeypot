import json
import sqlite3

from honeypot.dashboard import queries as q
from honeypot.database import SCHEMA_VERSION, EventStore


def _conn(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def test_schema_version_is_set(tmp_path):
    EventStore(tmp_path / "a.db").close()
    assert _conn(tmp_path / "a.db").execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_jsonl_feed(populated_db, tmp_path):
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    events = [json.loads(line)["event"] for line in lines]
    assert events[0] == "session.connect" and "auth.success" in events and "ioc" in events


def test_writes_after_close_are_ignored(tmp_path):
    store = EventStore(tmp_path / "a.db")
    store.close()
    store.create_session("192.0.2.1", 1)  # must not raise during shutdown races
    store.close()  # idempotent


def test_prune_cascades(populated_db):
    db_path, _ = populated_db
    conn = _conn(db_path)
    conn.execute("UPDATE sessions SET started_at = '2000-01-01 00:00:00'")
    conn.commit()
    conn.close()
    store = EventStore(db_path)
    assert store.prune(30) == 2
    store.close()
    conn = _conn(db_path)
    assert conn.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0] == 0


def test_queries(populated_db):
    db_path, sid = populated_db
    conn = _conn(db_path)
    s = q.summary(conn)
    assert (s["auth_attempts"], s["successful_logins"], s["unique_ips"]) == (3, 1, 2)
    top = q.top_ips(conn)
    assert top[0]["src_ip"] == "203.0.113.9"  # got a shell + downloaded something
    assert q.threat_level(top[0]) == "high"  # got a shell and ran a (risk 8) download
    assert q.threat_level(top[1]) == "low"  # one failed guess
    assert q.top_ips(conn, 1, ip="198.51.100.2")[0]["attempts"] == 1
    assert len(q.timeline(conn, 24)["labels"]) == 24
    assert len(q.timeline(conn, 24 * 7)["labels"]) == 7
    assert q.session_detail(conn, sid)["commands"][0]["tags"] == "download"
    assert q.tag_breakdown(conn) == [{"tag": "download", "count": 1, "technique": "T1105"}]
    # the SQL-injection-looking password was stored as inert data
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 2


def test_threat_levels_are_behaviour_based():
    assert q.threat_level({"attempts": 500}) == "medium"  # loud brute-forcer, never got in
    assert q.threat_level({"attempts": 3}) == "low"
    assert q.threat_level({"attempts": 1, "successes": 1}) == "medium"  # got in, did nothing
    assert q.threat_level({"successes": 1, "commands": 2, "max_risk": 1}) == "high"
    assert q.threat_level({"successes": 1, "commands": 1, "max_risk": 14}) == "critical"
