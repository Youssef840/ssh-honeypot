"""
Public demo of the dashboard with simulated data.

    python -m honeypot.dashboard.demo_web          # binds 0.0.0.0:$PORT (default 5000)

No honeypot is started and nothing listens for SSH: at startup a fresh SQLite
database is filled with synthetic sessions (see ``honeypot.demo_data``) and the
dashboard is served read-only, with a banner on every page saying it is a demo.
Because the data is fake, the dashboard runs without a password here.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import tempfile
from pathlib import Path

from flask import Flask

from ..config import DashboardSettings, HoneypotSettings
from ..demo_data import seed
from .app import create_app

DEMO_SESSIONS = 150


def create_demo_app(data_dir: Path | None = None, sessions: int = DEMO_SESSIONS) -> Flask:
    data_dir = Path(data_dir or tempfile.mkdtemp(prefix="hp-demo-"))
    db_path = data_dir / "honeypot.db"
    hp = dataclasses.replace(
        HoneypotSettings(),
        auth_mode="list",
        db_path=db_path,
        host_key_path=data_dir / "host_rsa.key",
        log_file=data_dir / "honeypot.log",
        jsonl_file=data_dir / "events.jsonl",
        jsonl_enabled=False,
    )
    seed(hp, sessions)
    dash = DashboardSettings(host="0.0.0.0", db_path=db_path, password="")
    return create_app(dash, demo=True)


def main() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    port = int(os.getenv("PORT", "5000"))
    app = create_demo_app()
    print(f"Demo dashboard (simulated data): http://0.0.0.0:{port}")
    from waitress import serve

    serve(app, host="0.0.0.0", port=port, threads=8, ident="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
