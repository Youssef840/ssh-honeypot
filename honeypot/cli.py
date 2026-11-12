"""Command-line entry points.

python -m honeypot             (or: ssh-honeypot)            start the SSH honeypot
python -m honeypot.dashboard   (or: ssh-honeypot-dashboard)  start the web dashboard
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import signal
import sys
from logging.handlers import RotatingFileHandler

from . import __version__
from .config import DashboardSettings, HoneypotSettings

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _setup_logging(log_file, verbose: bool) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    # paramiko is extremely chatty about the broken handshakes internet scanners produce
    logging.getLogger("paramiko").setLevel(logging.WARNING if verbose else logging.CRITICAL)


def honeypot_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ssh-honeypot", description="Low-interaction SSH honeypot (Paramiko).")
    parser.add_argument("--host", help="bind address (overrides HP_BIND_HOST)")
    parser.add_argument("--port", type=int, help="listen port (overrides HP_PORT)")
    parser.add_argument("--prune-days", type=int, metavar="N", help="delete sessions older than N days, then exit")
    parser.add_argument("--check-config", action="store_true", help="validate configuration and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        settings = HoneypotSettings()
        overrides = {k: v for k, v in (("bind_host", args.host), ("port", args.port)) if v is not None}
        if overrides:
            settings = dataclasses.replace(settings, **overrides)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.check_config:
        for f in dataclasses.fields(settings):
            print(f"{f.name:<26} {getattr(settings, f.name)}")
        return 0

    # imported lazily so `--help` / `--check-config` work even without paramiko installed
    from .database import EventStore
    from .server import HoneypotServer

    if args.prune_days is not None:
        store = EventStore(settings.db_path)
        removed = store.prune(args.prune_days)
        store.close()
        print(f"Removed {removed} session(s) older than {args.prune_days} day(s).")
        return 0

    _setup_logging(settings.log_file, args.verbose)
    log = logging.getLogger("honeypot")
    if settings.bind_host not in LOOPBACK:
        log.warning(
            "Listening on %s — make sure this is an ISOLATED machine (see docs/DEPLOYMENT.md).", settings.bind_host
        )
    if settings.port and settings.port < 1024 and sys.platform != "win32":
        log.warning("Port %d needs root. Prefer 2222 + an iptables redirect.", settings.port)

    server = HoneypotServer(settings)
    if settings.retention_days > 0:
        log.info("Retention: pruned %d old session(s)", server.store.prune(settings.retention_days))

    def _graceful(signum, _frame):
        log.info("Signal %s received, shutting down...", signum)
        server.shutdown()

    signal.signal(signal.SIGINT, _graceful)
    signal.signal(signal.SIGTERM, _graceful)
    try:
        server.serve_forever()
    except OSError as exc:
        log.error("Cannot listen on %s:%s — %s", settings.bind_host, settings.port, exc)
        return 1
    finally:
        server.store.close()
        log.info("Honeypot stopped.")
    return 0


def dashboard_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ssh-honeypot-dashboard", description="Web dashboard for the SSH honeypot.")
    parser.add_argument("--host", help="bind address (overrides DASH_HOST)")
    parser.add_argument("--port", type=int, help="listen port (overrides DASH_PORT)")
    parser.add_argument("--debug", action="store_true", help="Flask debug server (never in production)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    settings = DashboardSettings()
    overrides = {k: v for k, v in (("host", args.host), ("port", args.port)) if v is not None}
    if overrides:
        settings = dataclasses.replace(settings, **overrides)

    if settings.host not in LOOPBACK and not settings.password:
        print(
            "REFUSING to expose the dashboard on a non-loopback address without DASH_PASSWORD.\n"
            "Set DASH_PASSWORD, or keep DASH_HOST=127.0.0.1 and use an SSH tunnel.",
            file=sys.stderr,
        )
        return 2

    from .dashboard.app import create_app

    _setup_logging(None, args.debug)
    app = create_app(settings)
    print(f"Dashboard: http://{settings.host}:{settings.port}  (db: {settings.db_path})")
    if args.debug:
        app.run(host=settings.host, port=settings.port, debug=True)
        return 0
    try:
        from waitress import serve
    except ImportError:
        print("waitress not installed; falling back to Flask's development server.", file=sys.stderr)
        app.run(host=settings.host, port=settings.port)
        return 0
    serve(app, host=settings.host, port=settings.port, threads=8, ident="")
    return 0
