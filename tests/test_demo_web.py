import pytest

from honeypot.dashboard.app import create_app
from honeypot.dashboard.demo_web import create_demo_app

pytest.importorskip("flask")


@pytest.fixture(scope="module")
def demo_client(tmp_path_factory):
    app = create_demo_app(tmp_path_factory.mktemp("demo"), sessions=40)
    return app.test_client()


def test_demo_dashboard_has_data(demo_client):
    summary = demo_client.get("/api/summary").get_json()
    assert summary  # seeded sessions show up in the stats
    r = demo_client.get("/")
    assert r.status_code == 200


@pytest.mark.parametrize("path", ["/", "/sessions"])
def test_demo_banner_on_every_page(demo_client, path):
    body = demo_client.get(path).get_data(as_text=True)
    assert "Demo only" in body
    assert "عرض توضيحي فقط" in body


def test_demo_needs_no_password(demo_client):
    assert demo_client.get("/sessions").status_code == 200


def test_demo_ips_are_documentation_ranges(demo_client):
    rows = demo_client.get("/api/top-ips?limit=50").get_json()
    assert rows
    assert all(r["src_ip"].startswith(("198.51.100.", "203.0.113.", "192.0.2.")) for r in rows)


def test_normal_dashboard_has_no_banner(tmp_path):
    from honeypot.config import DashboardSettings

    app = create_app(DashboardSettings(db_path=tmp_path / "hp.db", password=""))
    body = app.test_client().get("/").get_data(as_text=True)
    assert "Demo only" not in body
