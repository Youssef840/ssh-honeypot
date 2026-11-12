"""
Flask dashboard (read-only view over the honeypot database).

Security model
--------------
* Opens SQLite with PRAGMA query_only: the dashboard can never alter evidence.
* Everything shown is attacker-controlled text (usernames, passwords, commands)
  → Jinja2 autoescaping is on, chart data goes through `tojson` into a
  non-executable <script type="application/json"> block, and a strict CSP
  forbids inline scripts. A password like `<script>alert(1)</script>` renders
  as harmless text.
* Optional HTTP Basic auth (DASH_PASSWORD); run_dashboard.py refuses to bind a
  non-loopback address without it.
* CSV export neutralises spreadsheet formula injection (=, +, -, @).
"""

from __future__ import annotations

import csv
import hmac
import io
import ipaddress
import math
import sqlite3

from flask import Flask, Response, abort, g, jsonify, render_template, request

from .. import __version__
from ..config import DashboardSettings
from ..database import EventStore
from . import queries as q

PAGE_SIZE = 25


def create_app(settings: DashboardSettings | None = None) -> Flask:
    settings = settings or DashboardSettings()
    app = Flask(__name__)
    app.config["HP_SETTINGS"] = settings
    app.config["JSON_SORT_KEYS"] = False

    if not settings.db_path.exists():  # first run: create an empty schema
        EventStore(settings.db_path).close()
    db_path = str(settings.db_path.resolve())

    # ------------------------------------------------------------- database
    def db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(db_path, timeout=5)
            # query_only rejects every INSERT/UPDATE/DELETE/DDL on this
            # connection; unlike URI mode=ro it also works on a WAL database
            # whose -shm file has not been created yet.
            conn.execute("PRAGMA query_only = ON")
            conn.row_factory = sqlite3.Row
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def _close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    # ------------------------------------------------------------- security
    @app.before_request
    def _require_auth():
        if not settings.password or request.endpoint in ("healthz", "static"):
            return None
        auth = request.authorization
        ok = (
            auth is not None
            and hmac.compare_digest((auth.username or "").encode(), settings.username.encode())
            and hmac.compare_digest((auth.password or "").encode(), settings.password.encode())
        )
        if not ok:
            return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Honeypot Dashboard"'})
        return None

    @app.after_request
    def _headers(resp: Response):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------- helpers
    @app.template_filter("level")
    def _level(row):
        return q.threat_level(row)

    @app.template_filter("dur")
    def _dur(seconds):
        if seconds is None:
            return "—"
        seconds = float(seconds)
        if seconds < 60:
            return f"{seconds:.0f}s"
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"

    @app.context_processor
    def _inject():
        return {"refresh_seconds": settings.refresh_seconds, "version": __version__}

    def _valid_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            abort(404)

    # ------------------------------------------------------------- pages
    @app.get("/")
    def index():
        conn = db()
        chart_data = {
            "timeline": q.timeline(conn, 24),
            "tags": q.tag_breakdown(conn),
            "passwords": q.top_values(conn, "password", 10),
            "usernames": q.top_values(conn, "username", 10),
            "clients": q.client_versions(conn),
        }
        return render_template(
            "index.html",
            s=q.summary(conn),
            top_ips=q.top_ips(conn, 10),
            usernames=chart_data["usernames"],
            passwords=chart_data["passwords"],
            combos=q.top_combos(conn, 10),
            commands=q.top_commands(conn, 10),
            iocs=q.recent_iocs(conn, 10),
            sessions=q.recent_sessions(conn, 10),
            chart_data=chart_data,
        )

    @app.get("/sessions")
    def sessions():
        conn = db()
        ip = request.args.get("ip") or None
        if ip:
            ip = _valid_ip(ip)
        logged_in = request.args.get("logged_in") == "1"
        page = max(1, request.args.get("page", 1, type=int))
        total = q.count_sessions(conn, ip, logged_in)
        pages = max(1, math.ceil(total / PAGE_SIZE))
        rows = q.recent_sessions(conn, PAGE_SIZE, (page - 1) * PAGE_SIZE, ip, logged_in)
        return render_template(
            "sessions.html", rows=rows, page=page, pages=pages, total=total, ip=ip or "", logged_in=logged_in
        )

    @app.get("/session/<sid>")
    def session(sid: str):
        if not sid.isalnum() or len(sid) > 64:
            abort(404)
        detail = q.session_detail(db(), sid)
        if detail is None:
            abort(404)
        return render_template("session.html", d=detail)

    @app.get("/ip/<ip>")
    def ip_view(ip: str):
        detail = q.ip_detail(db(), _valid_ip(ip))
        if detail["stats"] is None:
            abort(404)
        return render_template("ip.html", d=detail)

    # ------------------------------------------------------------- JSON API
    @app.get("/healthz")
    def healthz():
        try:
            db().execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return jsonify(status="error"), 503
        return jsonify(status="ok", version=__version__)

    @app.get("/api/summary")
    def api_summary():
        return jsonify(q.summary(db()))

    @app.get("/api/timeline")
    def api_timeline():
        hours = min(max(request.args.get("hours", 24, type=int), 1), 24 * 90)
        return jsonify(q.timeline(db(), hours))

    @app.get("/api/top-ips")
    def api_top_ips():
        limit = min(request.args.get("limit", 10, type=int), 500)
        rows = q.top_ips(db(), limit)
        for r in rows:
            r["level"] = q.threat_level(r)
        return jsonify(rows)

    @app.get("/api/top/<field>")
    def api_top(field: str):
        limit = min(request.args.get("limit", 10, type=int), 500)
        conn = db()
        if field in ("username", "password"):
            return jsonify(q.top_values(conn, field, limit))
        if field == "combos":
            return jsonify(q.top_combos(conn, limit))
        if field == "commands":
            return jsonify(q.top_commands(conn, limit))
        abort(404)

    @app.get("/export/auth.csv")
    def export_auth():
        def safe(v):
            v = "" if v is None else str(v)
            return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["ts", "src_ip", "method", "username", "password", "key_fingerprint", "success", "session_id"])
        for r in db().execute("""SELECT ts, src_ip, method, username, password, key_fingerprint, success, session_id
                                 FROM auth_attempts ORDER BY id"""):
            writer.writerow([safe(x) for x in r])
        return Response(
            out.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=auth_attempts.csv"},
        )

    @app.errorhandler(404)
    def _not_found(_e):
        return render_template("404.html"), 404

    return app
