"""
SSH honeypot server engine (Paramiko).

Connection lifecycle
--------------------
  TCP accept ─► limiter check ─► session row created
      └─► SSH handshake (fake OpenSSH banner, persistent host key)
            └─► auth loop: every password / public-key attempt is logged
                  ├─ rejected  → attacker keeps guessing (until max attempts)
                  └─ accepted (per AuthPolicy) → session channel opened
                        ├─ "exec"  request: `ssh host 'cmd'` → one emulated command
                        └─ "shell" request: interactive fake bash (FakeShell)
      └─► session closed: duration + end reason stored

What is explicitly refused
--------------------------
* Port forwarding / direct-tcpip (the honeypot must never become a proxy);
  attempted destinations are recorded as IOCs.
* SFTP / SCP subsystems.
* Any real command execution — FakeShell is a pure emulator.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field

import paramiko

from .analysis import analyze_command
from .config import HoneypotSettings
from .database import EventStore
from .fake_shell import FakeShell

log = logging.getLogger("honeypot")


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _to_str(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def key_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def load_or_create_host_key(path) -> paramiko.RSAKey:
    """A *persistent* host key matters: a key that changes on every restart is
    an obvious honeypot tell, and returning attackers would see warnings."""
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    log.info("Generating new 3072-bit RSA host key at %s", path)
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(str(path))
    return key


class ConnectionLimiter:
    """Caps total concurrent sessions and concurrent sessions per source IP."""

    def __init__(self, max_total: int, max_per_ip: int):
        self._lock = threading.Lock()
        self._total = 0
        self._per_ip: dict[str, int] = {}
        self.max_total, self.max_per_ip = max_total, max_per_ip

    def acquire(self, ip: str) -> bool:
        with self._lock:
            if self._total >= self.max_total or self._per_ip.get(ip, 0) >= self.max_per_ip:
                return False
            self._total += 1
            self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
            return True

    def release(self, ip: str) -> None:
        with self._lock:
            self._total = max(0, self._total - 1)
            remaining = self._per_ip.get(ip, 1) - 1
            if remaining <= 0:
                self._per_ip.pop(ip, None)
            else:
                self._per_ip[ip] = remaining


class AuthPolicy:
    def __init__(self, settings: HoneypotSettings):
        self.s = settings

    def decide(self, username: str, password: str, attempt_no: int) -> bool:
        mode = self.s.auth_mode
        if mode == "any":
            return True
        if mode == "never":
            return False
        if mode == "after_n":
            return attempt_no >= self.s.accept_after
        creds = self.s.accepted_creds
        return (username, password) in creds or (username, "*") in creds


@dataclass
class SessionContext:
    sid: str
    ip: str
    port: int
    store: EventStore
    settings: HoneypotSettings
    started: float = field(default_factory=time.monotonic)
    attempts: int = 0
    key_attempts: int = 0
    logged_in: bool = False
    username: str = ""
    password: str = ""
    commands: int = 0


# --------------------------------------------------------------------------- #
# Paramiko ServerInterface                                                     #
# --------------------------------------------------------------------------- #
class HoneypotInterface(paramiko.ServerInterface):
    def __init__(self, ctx: SessionContext, policy: AuthPolicy):
        self.ctx = ctx
        self.policy = policy
        self.channel_ready = threading.Event()
        self.mode: str | None = None  # "shell" | "exec"
        self.exec_command: str = ""
        self.pty = False
        self.term = ""

    # ---- authentication ---------------------------------------------------
    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        ctx = self.ctx
        username, password = _to_str(username)[:256], _to_str(password)[:256]
        ctx.attempts += 1
        allowed = ctx.attempts <= ctx.settings.max_auth_attempts
        success = allowed and self.policy.decide(username, password, ctx.attempts)
        ctx.store.log_auth(ctx.sid, ctx.ip, "password", username, success, password=password)
        log.info(
            "[%s] %s auth password %r / %r -> %s", ctx.sid, ctx.ip, username, password, "SUCCESS" if success else "fail"
        )
        if success:
            ctx.logged_in, ctx.username, ctx.password = True, username, password
            ctx.store.mark_login(ctx.sid, username, password)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        ctx = self.ctx
        ctx.key_attempts += 1
        if ctx.key_attempts > ctx.settings.max_key_attempts:
            return paramiko.AUTH_FAILED  # stop logging: prevents DB flooding with key offers
        fp = key_fingerprint(key)
        ctx.store.log_auth(
            ctx.sid, ctx.ip, "publickey", _to_str(username)[:256], False, key_type=key.get_name(), key_fingerprint=fp
        )
        log.info("[%s] %s auth publickey %r %s %s -> fail", ctx.sid, ctx.ip, username, key.get_name(), fp)
        return paramiko.AUTH_FAILED  # force fallback to password auth

    # ---- channels ---------------------------------------------------------
    def check_channel_request(self, kind, chanid):
        if kind == "session" and self.ctx.logged_in:
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        dest = f"{destination[0]}:{destination[1]}"
        self.ctx.store.log_ioc(self.ctx.sid, self.ctx.ip, "proxy-attempt", dest)
        log.warning("[%s] %s tried to tunnel to %s (refused)", self.ctx.sid, self.ctx.ip, dest)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address, port):
        self.ctx.store.log_ioc(self.ctx.sid, self.ctx.ip, "proxy-attempt", f"remote-forward {address}:{port}")
        return False

    def check_global_request(self, kind, msg):
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.pty = True
        self.term = _to_str(term)
        self.ctx.store.set_term(self.ctx.sid, self.term)
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

    def check_channel_env_request(self, channel, name, value):
        return True

    def check_channel_shell_request(self, channel):
        self.mode = "shell"
        self.channel_ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.mode = "exec"
        self.exec_command = _to_str(command)[: self.ctx.settings.max_line_length]
        self.channel_ready.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        self.ctx.store.log_ioc(self.ctx.sid, self.ctx.ip, "subsystem", _to_str(name))
        return False  # no sftp


# --------------------------------------------------------------------------- #
# Session handling                                                             #
# --------------------------------------------------------------------------- #
def _send(chan: paramiko.Channel, text: str, crlf: bool = True) -> None:
    if crlf:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    chan.sendall(text.encode("utf-8", errors="replace"))


def _record_command(ctx: SessionContext, shell: FakeShell, line: str, kind: str) -> tuple[str, bool]:
    """Run one line through the emulator, persist it with analysis.
    Returns (output, known) where known=False means an unsupported command."""
    ctx.commands += 1
    output, known = shell.run_line(line)
    # Payloads hidden behind `echo ... | base64 -d | sh` are analysed too, so an
    # obfuscated dropper scores (and yields IOCs) like its plain-text equivalent.
    payloads = shell.take_payloads()
    analysis = analyze_command("\n".join([line, *payloads]))
    ctx.store.log_command(ctx.sid, ctx.ip, line, kind, known, analysis.risk, analysis.tags)
    for payload in payloads:
        ctx.store.log_ioc(ctx.sid, ctx.ip, "decoded-payload", payload)
    for url in analysis.urls:
        ctx.store.log_ioc(ctx.sid, ctx.ip, "url", url)
    for ip in analysis.ips:
        ctx.store.log_ioc(ctx.sid, ctx.ip, "ip", ip)
    log.info("[%s] %s %s> %r (risk=%d %s)", ctx.sid, ctx.ip, kind, line, analysis.risk, ",".join(analysis.tags))
    return output, known


def _run_exec(chan: paramiko.Channel, ctx: SessionContext, shell: FakeShell, command: str) -> str:
    output, known = _record_command(ctx, shell, command, "exec")
    _send(chan, output, crlf=False)
    chan.send_exit_status(0 if known else 127)
    _linger_for_client(chan)
    return "exec_done"


def _linger_for_client(chan: paramiko.Channel, timeout: float = 2.0) -> None:
    """Give the client a moment to read output + exit status before we tear down.

    Closing the transport immediately after ``send_exit_status`` races with the
    client's reader thread: it can see the socket drop before it has processed
    the exit-status packet (``recv_exit_status()`` then returns -1). Real sshd
    waits for the client to disconnect, so we do the same, with a short cap.
    """
    chan.shutdown_write()  # send EOF, like sshd does after the command ends
    transport = chan.get_transport()
    deadline = time.monotonic() + timeout
    while transport is not None and transport.is_active() and time.monotonic() < deadline:
        if chan.closed or chan.eof_received:
            break
        time.sleep(0.02)


def _run_shell(chan: paramiko.Channel, ctx: SessionContext, shell: FakeShell, interactive: bool) -> str:
    s = ctx.settings
    chan.settimeout(s.idle_timeout)
    if interactive:
        _send(chan, shell.motd() + shell.prompt)

    buf: list[str] = []
    esc_state = 0  # 0 = normal, 1 = after ESC, 2 = inside CSI sequence
    last_was_cr = False

    while True:
        if time.monotonic() - ctx.started > s.session_timeout:
            _send(chan, "\nConnection to host closed: session timeout\n")
            return "session_timeout"
        try:
            data = chan.recv(1024)
        except TimeoutError:
            return "idle_timeout"
        if not data:
            # EOF: bots piping commands often omit the final newline
            leftover = "".join(buf).strip()
            if leftover and ctx.commands < s.max_commands_per_session:
                output, _ = _record_command(ctx, shell, leftover, "shell")
                _send(chan, output, crlf=interactive)
            try:
                chan.send_exit_status(0)
            except Exception:
                pass
            return "client_closed"

        echo: list[str] = []
        for ch in data.decode("utf-8", errors="replace"):
            # swallow ANSI escape sequences (arrow keys, etc.)
            if esc_state == 1:
                esc_state = 2 if ch == "[" else 0
                continue
            if esc_state == 2:
                if "@" <= ch <= "~":
                    esc_state = 0
                continue
            if ch == "\x1b":
                esc_state = 1
                continue

            if ch == "\n" and last_was_cr:  # CRLF -> single Enter
                last_was_cr = False
                continue
            last_was_cr = ch == "\r"

            if ch in "\r\n":
                if interactive:
                    echo.append("\r\n")
                    chan.sendall("".join(echo).encode())
                    echo = []
                line = "".join(buf)
                buf = []
                if line.strip():
                    if ctx.commands >= s.max_commands_per_session:
                        return "max_commands"
                    output, _ = _record_command(ctx, shell, line, "shell")
                    if output:
                        _send(chan, output, crlf=interactive)
                    if shell.exit_requested:
                        try:
                            chan.send_exit_status(0)
                        except Exception:
                            pass
                        return "logout"
                if interactive:
                    _send(chan, shell.prompt)
            elif ch in "\x7f\x08":  # backspace
                if buf:
                    buf.pop()
                    echo.append("\b \b")
            elif ch == "\x03":  # Ctrl-C
                buf = []
                if interactive:
                    echo.append("^C\r\n" + shell.prompt)
            elif ch == "\x04":  # Ctrl-D
                if not buf:
                    _send(chan, "".join(echo) + "logout\n")
                    return "logout"
            elif ch == "\x15":  # Ctrl-U: kill line
                echo.append("\b \b" * len(buf))
                buf = []
            elif ch >= " " and len(buf) < s.max_line_length:
                buf.append(ch)
                echo.append(ch)
        if echo and interactive:
            chan.sendall("".join(echo).encode("utf-8", errors="replace"))


def handle_client(
    client: socket.socket,
    addr,
    settings: HoneypotSettings,
    store: EventStore,
    host_key: paramiko.PKey,
    limiter: ConnectionLimiter,
    policy: AuthPolicy,
) -> None:
    ip, port = addr[0], addr[1]
    if ip.startswith("::ffff:"):  # IPv4-mapped address on a dual-stack socket
        ip = ip[7:]
    reason = "unknown"
    transport: paramiko.Transport | None = None
    chan: paramiko.Channel | None = None
    sid = store.create_session(ip, port)
    ctx = SessionContext(sid=sid, ip=ip, port=port, store=store, settings=settings)
    log.info("[%s] connection from %s:%d", sid, ip, port)
    try:
        transport = paramiko.Transport(client)
        transport.local_version = settings.ssh_banner
        transport.add_server_key(host_key)
        transport.banner_timeout = 20
        transport.handshake_timeout = 20
        transport.auth_timeout = settings.auth_timeout

        server = HoneypotInterface(ctx, policy)
        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            reason = "handshake_failed"
            log.info("[%s] handshake failed: %s", sid, exc)
            return
        if transport.remote_version:
            store.set_client_version(sid, transport.remote_version)

        # wait for a successful login + session channel
        deadline = time.monotonic() + settings.auth_timeout
        grace_set = False
        while time.monotonic() < deadline and transport.is_active():
            chan = transport.accept(1)
            if chan is not None:
                break
            if ctx.logged_in and not grace_set:  # logged in late: allow time to open a channel
                deadline, grace_set = max(deadline, time.monotonic() + 10), True
            if not ctx.logged_in and ctx.attempts >= settings.max_auth_attempts:
                reason = "max_auth_attempts"
                return
        if chan is None:
            reason = "auth_failed" if not ctx.logged_in else "no_channel"
            return

        if not server.channel_ready.wait(10):
            reason = "no_shell_request"
            return

        shell = FakeShell(ctx.username, settings.hostname, ip)
        if server.mode == "exec":
            reason = _run_exec(chan, ctx, shell, server.exec_command)
        else:
            reason = _run_shell(chan, ctx, shell, interactive=server.pty)
    except (EOFError, OSError, paramiko.SSHException) as exc:
        reason = "connection_error"
        log.debug("[%s] connection error: %s", sid, exc)
    except Exception:  # never let one session crash the server
        reason = "internal_error"
        log.exception("[%s] unexpected error", sid)
    finally:
        for closable in (chan, transport):
            try:
                if closable is not None:
                    closable.close()
            except Exception:
                pass
        try:
            client.close()
        except OSError:
            pass
        limiter.release(addr[0])  # always release, even if the store fails below
        store.end_session(sid, time.monotonic() - ctx.started, reason)
        log.info("[%s] closed (%s) after %.1fs", sid, reason, time.monotonic() - ctx.started)


# --------------------------------------------------------------------------- #
# Listener                                                                     #
# --------------------------------------------------------------------------- #
class HoneypotServer:
    def __init__(self, settings: HoneypotSettings | None = None, store: EventStore | None = None):
        self.settings = settings or HoneypotSettings()
        self.store = store or EventStore(
            self.settings.db_path,
            self.settings.jsonl_file if self.settings.jsonl_enabled else None,
        )
        self.host_key = load_or_create_host_key(self.settings.host_key_path)
        self.limiter = ConnectionLimiter(self.settings.max_connections, self.settings.max_per_ip)
        self.policy = AuthPolicy(self.settings)
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self.bound_port: int | None = None
        self.ready = threading.Event()

    def serve_forever(self) -> None:
        s = self.settings
        family = socket.AF_INET6 if ":" in s.bind_host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        if os.name == "nt":
            # On Windows SO_REUSEADDR lets *another* process steal the port;
            # SO_EXCLUSIVEADDRUSE is the safe equivalent.
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # also accept IPv4
        sock.bind((s.bind_host, s.port))
        sock.listen(128)
        sock.settimeout(1.0)  # lets Ctrl+C / shutdown() be noticed promptly
        self._sock = sock
        self.bound_port = sock.getsockname()[1]
        self.ready.set()
        log.info("Honeypot listening on %s:%d (auth_mode=%s)", s.bind_host, self.bound_port, s.auth_mode)

        while not self._stop.is_set():
            try:
                client, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            client.settimeout(None)
            if not self.limiter.acquire(addr[0]):
                log.warning("Connection limit hit, dropping %s", addr[0])
                client.close()
                continue
            threading.Thread(
                target=handle_client,
                args=(client, addr, s, self.store, self.host_key, self.limiter, self.policy),
                daemon=True,
                name=f"hp-{addr[0]}:{addr[1]}",
            ).start()
        sock.close()

    def shutdown(self) -> None:
        self._stop.set()
