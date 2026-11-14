#!/usr/bin/env python3
"""
One-command local demo: honeypot + realistic attack data + dashboard.

    python scripts/demo.py              # then open http://127.0.0.1:5000
    python scripts/demo.py --fresh      # wipe previous demo data first

What it does
  1. starts a real honeypot on 127.0.0.1:2222 (demo data lives in ./data-demo/)
  2. seeds ~150 sessions from documentation-only IP ranges (RFC 5737), spread
     over the last 24 h and replayed through the real fake shell + analyzer
  3. runs live SSH attacks against the honeypot with Paramiko
  4. serves the dashboard and opens it in your browser

While it runs you can also attack it yourself:  ssh -p 2222 root@127.0.0.1  (password: root)
Everything stays on 127.0.0.1. Press Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import shutil
import sys
import threading
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import simulate_attack  # noqa: E402

from honeypot.config import DashboardSettings, HoneypotSettings  # noqa: E402
from honeypot.dashboard.app import create_app  # noqa: E402
from honeypot.demo_data import seed  # noqa: E402
from honeypot.server import HoneypotServer  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=2222, help="honeypot port (default 2222)")
    ap.add_argument("--dash-port", type=int, default=5000, help="dashboard port (default 5000)")
    ap.add_argument("--seed", type=int, default=150, help="number of synthetic sessions (0 = none)")
    ap.add_argument("--rounds", type=int, default=3, help="live SSH attack rounds")
    ap.add_argument("--data", default="data-demo", help="demo data directory")
    ap.add_argument("--fresh", action="store_true", help="delete previous demo data first")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    data = (ROOT / args.data).resolve()
    if args.fresh and data.exists():
        shutil.rmtree(data)
    data.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    settings = dataclasses.replace(
        HoneypotSettings(),
        bind_host="127.0.0.1",
        port=args.port,
        auth_mode="list",
        db_path=data / "honeypot.db",
        host_key_path=data / "host_rsa.key",
        log_file=data / "honeypot.log",
        jsonl_file=data / "events.jsonl",
    )

    print(f"[1/4] starting honeypot on 127.0.0.1:{args.port} ...")
    server = HoneypotServer(settings)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not server.ready.wait(10):
        print("honeypot failed to start", file=sys.stderr)
        return 1

    if args.seed:
        print(f"[2/4] seeding {args.seed} synthetic attack sessions ...")
        seed(settings, args.seed)
    print(f"[3/4] running {args.rounds} live SSH attack round(s) ...")
    for i in range(args.rounds):
        print(f"  round {i + 1}")
        simulate_attack.run_round("127.0.0.1", args.port)

    app = create_app(DashboardSettings(host="127.0.0.1", port=args.dash_port, db_path=settings.db_path, password=""))
    url = f"http://127.0.0.1:{args.dash_port}"
    print(f"[4/4] dashboard: {url}")
    print(f"      attack it yourself:  ssh -p {args.port} root@127.0.0.1   (password: root)")
    print("      Ctrl+C to stop")
    if not args.no_browser:
        threading.Timer(1.5, webbrowser.open, args=[url]).start()

    from waitress import serve

    try:
        serve(app, host="127.0.0.1", port=args.dash_port, threads=8, ident="")
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
