"""
Central configuration.

Every setting comes from an environment variable, optionally loaded from a
``.env`` file in the current working directory, so the same code runs
locally, in a VM, or in Docker without edits. Relative paths are resolved
against the working directory.

Defaults are deliberately *safe*: the honeypot listens on 127.0.0.1 only
until you explicitly expose it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

AUTH_MODES = ("list", "after_n", "any", "never")


def load_dotenv(path: Path | None = None) -> None:
    """Minimal ``.env`` loader (``KEY=VALUE`` lines) so python-dotenv is not needed.
    Real environment variables always win over the file."""
    path = path or Path.cwd() / ".env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


load_dotenv()


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_path(name: str, default: str) -> Path:
    p = Path(os.environ.get(name) or default).expanduser()
    return p if p.is_absolute() else Path.cwd() / p


def parse_creds(raw: str) -> frozenset[tuple[str, str]]:
    """``'root:root,admin:*'`` -> ``{('root', 'root'), ('admin', '*')}``.
    Only the first ``:`` separates user from password, so passwords may contain ``:``."""
    creds: set[tuple[str, str]] = set()
    for item in raw.split(","):
        item = item.strip()
        if ":" in item:
            user, _, pwd = item.partition(":")
            creds.add((user, pwd))
    return frozenset(creds)


@dataclass(frozen=True)
class HoneypotSettings:
    # --- network ---
    bind_host: str = field(default_factory=lambda: _env_str("HP_BIND_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("HP_PORT", 2222))

    # --- storage ---
    db_path: Path = field(default_factory=lambda: _env_path("HP_DB_PATH", "data/honeypot.db"))
    host_key_path: Path = field(default_factory=lambda: _env_path("HP_HOST_KEY", "data/host_rsa.key"))
    log_file: Path = field(default_factory=lambda: _env_path("HP_LOG_FILE", "data/honeypot.log"))
    jsonl_file: Path = field(default_factory=lambda: _env_path("HP_JSONL_FILE", "data/events.jsonl"))
    jsonl_enabled: bool = field(default_factory=lambda: _env_bool("HP_JSONL_ENABLED", True))
    retention_days: int = field(default_factory=lambda: _env_int("HP_RETENTION_DAYS", 0))  # 0 = keep forever

    # --- deception / fingerprint ---
    ssh_banner: str = field(
        default_factory=lambda: _env_str("HP_SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
    )
    hostname: str = field(default_factory=lambda: _env_str("HP_HOSTNAME", "srv-prod-01"))

    # --- authentication policy ---
    # list    : accept only credentials in HP_ACCEPTED_CREDS ('user:*' = any password)
    # after_n : accept the N-th password attempt of a session regardless of credentials
    # any     : accept everything
    # never   : reject everything (pure credential harvesting)
    auth_mode: str = field(default_factory=lambda: _env_str("HP_AUTH_MODE", "list").strip().lower())
    accepted_creds: frozenset[tuple[str, str]] = field(
        default_factory=lambda: parse_creds(
            _env_str(
                "HP_ACCEPTED_CREDS",
                "root:root,root:123456,root:password,root:admin,admin:admin,ubuntu:ubuntu,pi:raspberry",
            )
        )
    )
    accept_after: int = field(default_factory=lambda: _env_int("HP_ACCEPT_AFTER", 3))

    # --- abuse / resource limits ---
    max_connections: int = field(default_factory=lambda: _env_int("HP_MAX_CONNECTIONS", 100))
    max_per_ip: int = field(default_factory=lambda: _env_int("HP_MAX_PER_IP", 5))
    max_auth_attempts: int = field(default_factory=lambda: _env_int("HP_MAX_AUTH_ATTEMPTS", 6))
    max_key_attempts: int = field(default_factory=lambda: _env_int("HP_MAX_KEY_ATTEMPTS", 10))
    auth_timeout: int = field(default_factory=lambda: _env_int("HP_AUTH_TIMEOUT", 30))
    idle_timeout: int = field(default_factory=lambda: _env_int("HP_IDLE_TIMEOUT", 120))
    session_timeout: int = field(default_factory=lambda: _env_int("HP_SESSION_TIMEOUT", 600))
    max_line_length: int = field(default_factory=lambda: _env_int("HP_MAX_LINE_LENGTH", 4096))
    max_commands_per_session: int = field(default_factory=lambda: _env_int("HP_MAX_COMMANDS", 500))

    def __post_init__(self) -> None:
        errors = []
        if self.auth_mode not in AUTH_MODES:
            errors.append(f"HP_AUTH_MODE must be one of {', '.join(AUTH_MODES)} (got {self.auth_mode!r})")
        if not self.ssh_banner.startswith("SSH-2.0-") or any(c in self.ssh_banner for c in "\r\n"):
            errors.append("HP_SSH_BANNER must start with 'SSH-2.0-' and be a single line")
        if not 0 <= self.port <= 65535:
            errors.append(f"HP_PORT out of range: {self.port}")
        if self.auth_mode == "after_n" and not 1 <= self.accept_after <= self.max_auth_attempts:
            errors.append("HP_ACCEPT_AFTER must be between 1 and HP_MAX_AUTH_ATTEMPTS")
        for name in (
            "max_connections",
            "max_per_ip",
            "max_auth_attempts",
            "auth_timeout",
            "idle_timeout",
            "session_timeout",
            "max_line_length",
            "max_commands_per_session",
        ):
            if getattr(self, name) <= 0:
                errors.append(f"{name} must be > 0")
        if errors:
            raise ValueError("Invalid honeypot configuration:\n  - " + "\n  - ".join(errors))


@dataclass(frozen=True)
class DashboardSettings:
    host: str = field(default_factory=lambda: _env_str("DASH_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("DASH_PORT", 5000))
    db_path: Path = field(default_factory=lambda: _env_path("HP_DB_PATH", "data/honeypot.db"))
    username: str = field(default_factory=lambda: _env_str("DASH_USER", "admin"))
    password: str = field(default_factory=lambda: _env_str("DASH_PASSWORD", ""))
    refresh_seconds: int = field(default_factory=lambda: _env_int("DASH_REFRESH", 30))
