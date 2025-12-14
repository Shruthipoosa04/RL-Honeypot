 # honeypot_web.py
import os
import json
import sqlite3
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, send_file,
    abort, jsonify, make_response
)
from logger_utils import log_interaction, ensure_data_paths

# Config
HOST = "0.0.0.0"
PORT = int(os.environ.get("HONEYPOT_PORT", 8080))
DEBUG = bool(os.environ.get("HONEYPOT_DEBUG", False))
SECRET_KEY = os.environ.get("HONEYPOT_SECRET_KEY", "change_this_secret")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(SECRET_KEY=SECRET_KEY)

# Ensure data dir and DB exist
ensure_data_paths()

# Helper to capture rich request context
def capture_event(route_name: str, extra: dict = None):
    if extra is None:
        extra = {}
    # get remote IP with X-Forwarded-For fallback
    xff = request.headers.get("X-Forwarded-For", "")
    remote_addr = request.remote_addr or "unknown"
    if xff:
        client_ip = xff.split(",")[0].strip()
    else:
        client_ip = remote_addr

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "route": route_name,
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode(errors="ignore"),
        "client_ip": client_ip,
        "remote_addr": remote_addr,
        "xff": xff,
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": dict(request.headers),
        "form": request.form.to_dict(),
        "args": request.args.to_dict(),
        "files": {k: {"filename": v.filename, "content_length": v.content_length}
                  for k, v in request.files.items()},
        # request.get_data might be binary; decode best-effort:
        "raw_body": None,
    }
    try:
        raw = request.get_data(cache=True)
        if raw:
            try:
                event["raw_body"] = raw.decode("utf-8", errors="replace")
            except Exception:
                event["raw_body"] = str(raw)
    except Exception:
        event["raw_body"] = "<could not read>"

    event.update(extra)
    log_interaction(event)
    return event

# ========== Routes ==========

@app.route("/", methods=["GET"])
def home():
    capture_event("home")
    return render_template("login.html")  # landing disguised as login

# decoy admin login
@app.route("/login", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Capture submitted credentials
        creds = {
            "submitted_username": request.form.get("username"),
            "submitted_password": request.form.get("password"),
            "submitted_token": request.form.get("token")
        }
        capture_event("login_attempt", extra={"submitted": creds})
        # Fake failure to encourage repeated attempts
        return render_template("login.html", error="Invalid credentials. Please try again.")
    else:
        capture_event("login_page")
        return render_template("login.html")

# fake panel/dashboard
@app.route("/panel")
def panel():
    capture_event("panel_page")
    fake_data = {
        "system_status": "Operational",
        "connected_devices": 12,
        "suspicious_connections": 3
    }
    return render_template("panel.html", data=fake_data)

# fake DB/browser page
@app.route("/database")
def database():
    capture_event("database_page")
    # Show fake records to entice further exploration
    fake_rows = [
        {"id": 1, "name": "device-01", "ip": "10.0.0.12"},
        {"id": 2, "name": "device-02", "ip": "10.0.0.21"},
        {"id": 3, "name": "controller", "ip": "10.0.0.5"},
    ]
    return render_template("database.html", rows=fake_rows)

 
# fake upload endpoint to capture files
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        files_info = {}
        for field, f in request.files.items():
            # read (but do not save permanently) — capture metadata and first bytes
            content = f.stream.read(4096)  # first 4KB
            f.stream.seek(0)
            files_info[field] = {
                "filename": f.filename,
                "content_snippet": content.decode("utf-8", errors="replace")[:500],
                "content_length": len(content)
            }
        capture_event("upload", extra={"files": files_info, "form": request.form.to_dict()})
        return render_template("upload.html", success=True)
    else:
        capture_event("upload_page")
        return render_template("upload.html")

# decoy config route
@app.route("/config")
def config():
    capture_event("config_page")
    return render_template("panel.html", data={"system_status": "Config Center", "connected_devices": 0})

# decoy backup download (serves a small harmless zip to look real)
@app.route("/backup.zip")
def backup():
    capture_event("backup_download")
    # Create a small in-memory bytes zip or serve a static dummy file if present
    dummy_path = os.path.join("static", "assets", "dummy-backup.zip")
    if os.path.exists(dummy_path):
        return send_file(dummy_path, as_attachment=True, download_name="backup.zip")
    # fallback: small plain text as zip (not a valid zip) — still looks like file
    payload = "This is a dummy backup file.\n"
    resp = make_response(payload)
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = 'attachment; filename="backup.zip"'
    return resp

# intentionally attractive 404-ish fake page
@app.errorhandler(404)
def page_not_found(e):
    capture_event("404", extra={"error": str(e)})
    return render_template("fake_404.html"), 404

# Simple API to fetch recent logs (useful for integration; protect if exposing publicly)
@app.route("/_logs/recent", methods=["GET"])
def recent_logs():
    # This endpoint returns last N interactions from JSONL (safe for local usage)
    n = int(request.args.get("n", 25))
    interactions = []
    try:
        with open(os.path.join("data", "interactions.jsonl"), "r", encoding="utf8") as fh:
            for line in fh:
                if line.strip():
                    interactions.append(json.loads(line))
    except FileNotFoundError:
        interactions = []
    capture_event("logs_fetch", extra={"returned": min(n, len(interactions))})
    return jsonify(interactions[-n:][::-1])

if __name__ == "__main__":
    # production should use a real WSGI server; running here for quick tests
    app.run(host=HOST, port=PORT, debug=DEBUG)