import base64
import sqlite3

import pytest
from flask import g

from honeypot.config import DashboardSettings
from honeypot.dashboard.app import create_app
from honeypot.database import EventStore


@pytest.fixture()
def client(populated_db):
    db_path, _ = populated_db
    return create_app(DashboardSettings(db_path=db_path, password="")).test_client()


def test_all_pages_render(client, populated_db):
    _, sid = populated_db
    for url in (
        "/",
        "/sessions",
        "/sessions?logged_in=1&page=1",
        f"/session/{sid}",
        "/ip/203.0.113.9",
        "/api/summary",
        "/api/timeline?hours=168",
        "/api/top-ips",
        "/api/top/password",
        "/api/top/combos",
        "/export/auth.csv",
        "/healthz",
    ):
        assert client.get(url).status_code == 200, url


def test_attacker_input_is_escaped(client):
    html = client.get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_security_headers(client):
    headers = client.get("/").headers
    assert "script-src 'self' https://cdnjs.cloudflare.com" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"


def test_invalid_inputs_404(client):
    assert client.get("/ip/not-an-ip").status_code == 404
    assert client.get("/session/../../etc").status_code == 404
    assert client.get("/api/top/unknown").status_code == 404


def test_basic_auth(populated_db):
    db_path, _ = populated_db
    c = create_app(DashboardSettings(db_path=db_path, username="u", password="secret")).test_client()
    assert c.get("/").status_code == 401
    assert c.get("/healthz").status_code == 200  # health probe stays open
    token = base64.b64encode(b"u:secret").decode()
    assert c.get("/", headers={"Authorization": f"Basic {token}"}).status_code == 200
    bad = base64.b64encode(b"u:wrong").decode()
    assert c.get("/", headers={"Authorization": f"Basic {bad}"}).status_code == 401


def test_dashboard_connection_is_read_only(populated_db):
    db_path, _ = populated_db
    app = create_app(DashboardSettings(db_path=db_path))

    @app.get("/_try_write")
    def _try_write():  # test-only route exercising the app's own connection
        app.view_functions["healthz"]()  # opens g.db exactly as real views do
        try:
            g.db.execute("DELETE FROM sessions")
        except sqlite3.OperationalError:
            return "blocked"
        return "written"

    assert app.test_client().get("/_try_write").get_data(as_text=True) == "blocked"


def test_csv_export_neutralises_formulas(tmp_path):
    db_path = tmp_path / "hp.db"
    store = EventStore(db_path)
    sid = store.create_session("192.0.2.5", 1)
    store.log_auth(sid, "192.0.2.5", "password", "=cmd|' /C calc'!A0", False, password="+1")
    store.close()
    body = create_app(DashboardSettings(db_path=db_path)).test_client().get("/export/auth.csv").get_data(as_text=True)
    assert "'=cmd" in body and "'+1" in body
