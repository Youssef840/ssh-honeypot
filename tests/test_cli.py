import pytest

from honeypot import __version__
from honeypot.cli import dashboard_main, honeypot_main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        honeypot_main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_check_config(capsys):
    assert honeypot_main(["--check-config", "--port", "2022"]) == 0
    out = capsys.readouterr().out
    assert "port" in out and "2022" in out and "auth_mode" in out


def test_invalid_config_exits_2(monkeypatch, capsys):
    monkeypatch.setenv("HP_AUTH_MODE", "maybe")
    assert honeypot_main(["--check-config"]) == 2
    assert "HP_AUTH_MODE" in capsys.readouterr().err


def test_prune(populated_db, monkeypatch, capsys):
    db_path, _ = populated_db
    monkeypatch.setenv("HP_DB_PATH", str(db_path))
    assert honeypot_main(["--prune-days", "30"]) == 0
    assert "Removed 0 session(s)" in capsys.readouterr().out  # demo data is fresh


def test_dashboard_refuses_public_bind_without_password(monkeypatch, capsys):
    monkeypatch.setenv("DASH_PASSWORD", "")
    assert dashboard_main(["--host", "0.0.0.0"]) == 2
    assert "REFUSING" in capsys.readouterr().err
