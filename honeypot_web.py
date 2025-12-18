# honeypot_web.py
import os
import json
from datetime import datetime
from flask import (
    Flask, render_template, request, send_file,
    jsonify, make_response
)

from logger_utils import (
    log_interaction,
    log_rl_decision,
    ensure_data_paths
)

# ---------------- RL IMPORTS ----------------
from rl.state_builder import build_state
from rl.q_agent import load_model, choose_action, update_q, Q
from rl.reward import calculate_reward
from rl.deception import apply_deception
# --------------------------------------------

# ---------------- CONFIG --------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("HONEYPOT_PORT", 8080))
DEBUG = bool(os.environ.get("HONEYPOT_DEBUG", False))
SECRET_KEY = os.environ.get("HONEYPOT_SECRET_KEY", "change_this_secret")
# --------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(SECRET_KEY=SECRET_KEY)

# Ensure data paths + load RL model
ensure_data_paths()
load_model()

# --------------------------------------------------
# HELPER: CAPTURE REQUEST CONTEXT
# --------------------------------------------------
def capture_event(route_name: str, extra: dict = None):
    if extra is None:
        extra = {}

    xff = request.headers.get("X-Forwarded-For", "")
    remote_addr = request.remote_addr or "unknown"
    client_ip = xff.split(",")[0].strip() if xff else remote_addr

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "route": route_name,
        "method": request.method,
        "path": request.path,
        "client_ip": client_ip,
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": dict(request.headers),
        "form": request.form.to_dict(),
        "args": request.args.to_dict(),
        "files": {
            k: {"filename": v.filename, "content_length": v.content_length}
            for k, v in request.files.items()
        },
        "raw_body": None,
    }

    try:
        raw = request.get_data(cache=True)
        if raw:
            event["raw_body"] = raw.decode("utf-8", errors="replace")
    except Exception:
        event["raw_body"] = "<unreadable>"

    event.update(extra)
    log_interaction(event)
    return event

# --------------------------------------------------
# RL HOOK (USED BY MULTIPLE ROUTES)
# --------------------------------------------------
def run_rl(log_event):
    state = build_state(log_event)
    action = choose_action(state)

    deception_response = apply_deception(action)

    reward = calculate_reward(log_event)
    next_state = state
    update_q(state, action, reward, next_state)

    # Log RL internals (CRITICAL)
    log_rl_decision(
        state=state,
        action=action,
        reward=reward,
        q_values=Q[state],
        meta={
            "route": log_event.get("route"),
            "client_ip": log_event.get("client_ip")
        }
    )

    return deception_response

# ================= ROUTES ===================

@app.route("/")
def home():
    event = capture_event("home")
    run_rl(event)
    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        event = capture_event("login_attempt", extra={
            "submitted": {
                "username": request.form.get("username"),
                "password": request.form.get("password"),
            }
        })
        run_rl(event)
        return render_template("login.html", error="Invalid credentials.")
    event = capture_event("login_page")
    run_rl(event)
    return render_template("login.html")

@app.route("/panel")
def panel():
    event = capture_event("panel_page")
    run_rl(event)
    return render_template("panel.html", data={
        "system_status": "Operational",
        "connected_devices": 12,
        "suspicious_connections": 3
    })

@app.route("/database")
def database():
    event = capture_event("database_page")
    run_rl(event)
    return render_template("database.html", rows=[
        {"id": 1, "name": "device-01", "ip": "10.0.0.12"},
        {"id": 2, "name": "device-02", "ip": "10.0.0.21"},
        {"id": 3, "name": "controller", "ip": "10.0.0.5"},
    ])

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        files_info = {}
        for field, f in request.files.items():
            content = f.stream.read(4096)
            f.stream.seek(0)
            files_info[field] = {
                "filename": f.filename,
                "size": len(content)
            }
        event = capture_event("upload", extra={"files": files_info})
        run_rl(event)
        return render_template("upload.html", success=True)

    event = capture_event("upload_page")
    run_rl(event)
    return render_template("upload.html")

@app.route("/backup.zip")
def backup():
    event = capture_event("backup_download")
    run_rl(event)

    dummy = os.path.join("static", "assets", "dummy-backup.zip")
    if os.path.exists(dummy):
        return send_file(dummy, as_attachment=True, download_name="backup.zip")

    resp = make_response("Dummy backup file\n")
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = 'attachment; filename="backup.zip"'
    return resp

@app.errorhandler(404)
def page_not_found(e):
    event = capture_event("404", extra={"error": str(e)})
    run_rl(event)
    return render_template("fake_404.html"), 404

@app.route("/_logs/recent")
def recent_logs():
    n = int(request.args.get("n", 20))
    logs = []
    try:
        with open("data/interactions.jsonl", "r", encoding="utf8") as f:
            for line in f:
                logs.append(json.loads(line))
    except FileNotFoundError:
        pass

    capture_event("logs_fetch", extra={"returned": n})
    return jsonify(logs[-n:][::-1])

# ---------------- RUN -----------------------
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
