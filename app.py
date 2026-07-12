import json
import os
import threading
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import database as db
from mds_collector import collect_switch, _build_ssh, _ssh_exec

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", uuid.uuid4().hex)
db.init_db()

collect_cache = {}
CACHE_LOCK = threading.Lock()
POLL_INTERVAL = 30


def _get_cached(host):
    with CACHE_LOCK:
        return collect_cache.get(host)


def _set_cached(host, data):
    with CACHE_LOCK:
        collect_cache[host] = data


def _load_cache_from_db():
    switches = db.get_all_switches()
    for sw in switches:
        snap = db.get_latest_snapshot(sw["id"])
        if snap:
            try:
                data = json.loads(snap["data_json"])
                _set_cached(sw["host"], data)
            except (json.JSONDecodeError, TypeError):
                pass


def _collect_and_cache(switch_dict):
    host = switch_dict["host"]
    res = collect_switch(host, switch_dict["username"], switch_dict["password"], switch_dict.get("port", 22))
    _set_cached(host, res)
    return res


@app.context_processor
def inject_user():
    return {
        "current_user": session.get("username"),
        "current_role": session.get("role"),
    }


# ---------- Auth Helpers ----------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def api_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = db.get_user_by_id(session["user_id"])
        if not user or user.get("role") != "admin":
            return render_template("index.html", error="Admin access required"), 403
        return f(*args, **kwargs)
    return decorated


# ---------- Auth Routes ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.verify_user(username, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            db.audit("user_login", f"User {username} logged in")
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    db.audit("user_logout", f"User {username} logged out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
@admin_required
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if not username or not password:
            return render_template("signup.html", error="Username and password required")
        if db.create_user(username, password, role):
            db.audit("user_created", f"Admin created user {username} with role {role}")
            return redirect(url_for("users_page"))
        return render_template("signup.html", error="Username already exists")
    return render_template("signup.html")


@app.route("/users")
@admin_required
def users_page():
    return render_template("users.html")


@app.route("/api/users")
@api_login_required
def api_users():
    if session.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    users = db.get_all_users()
    return jsonify(users)


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@api_login_required
def api_delete_user(user_id):
    if session.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    if user_id == session["user_id"]:
        return jsonify({"error": "Cannot delete yourself"}), 400
    db.delete_user(user_id)
    db.audit("user_deleted", f"Admin deleted user id {user_id}")
    return jsonify({"status": "ok"})


@app.route("/api/me")
def api_me():
    if "user_id" in session:
        return jsonify({
            "authenticated": True,
            "username": session.get("username"),
            "role": session.get("role"),
        })
    return jsonify({"authenticated": False})


# ---------- HTML Routes (protected) ----------

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/switch/<int:switch_id>")
@login_required
def switch_detail(switch_id):
    switch = db.get_switch(switch_id)
    if not switch:
        return render_template("index.html", error="Switch not found")
    return render_template("switch.html", switch=switch)


@app.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_switch():
    if request.method == "POST":
        host = request.form["host"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        port = int(request.form.get("port", 22))
        label = request.form.get("label", "").strip()
        site = request.form.get("site", "").strip()
        db.add_switch(host, username, password, port, label, site)
        sw = {"host": host, "username": username, "password": password, "port": port}
        res = _collect_and_cache(sw)
        label = label or host
        db.audit("switch_added", f"Added switch {label} ({host}) at {site}", switch_host=host,
                 details={"label": label, "port": port, "site": site, "reachable": res.get("reachable")})
        return redirect(url_for("index"))
    return render_template("add_switch.html")


@app.route("/edit/<int:switch_id>", methods=["GET", "POST"])
@login_required
def edit_switch(switch_id):
    switch = db.get_switch(switch_id)
    if not switch:
        return render_template("index.html", error="Switch not found")
    if request.method == "POST":
        host = request.form["host"].strip()
        username = request.form["username"].strip()
        password = request.form["password"] or switch["password"]
        port = int(request.form.get("port", 22))
        label = request.form.get("label", "").strip()
        site = request.form.get("site", "").strip()
        db.update_switch(switch_id, host=host, username=username, password=password,
                         port=port, label=label, site=site)
        with CACHE_LOCK:
            collect_cache.pop(switch["host"], None)
        db.audit("switch_edited", f"Edited switch {label} ({host})", switch_id=switch_id, switch_host=host,
                 details={"label": label, "port": port, "site": site})
        return redirect(url_for("index"))
    return render_template("add_switch.html", switch=switch, edit=True)


@app.route("/delete/<int:switch_id>", methods=["POST"])
@login_required
def delete_switch(switch_id):
    switch = db.get_switch(switch_id)
    if switch:
        db.audit("switch_deleted", f"Deleted switch {switch['label']} ({switch['host']})",
                 switch_id=switch_id, switch_host=switch["host"])
        with CACHE_LOCK:
            collect_cache.pop(switch["host"], None)
    db.delete_switch(switch_id)
    return redirect(url_for("index"))


# ---------- REST API (protected) ----------

@app.route("/api/switches")
@api_login_required
def api_switches():
    switches = db.get_all_switches()
    result = []
    for sw in switches:
        data = _get_cached(sw["host"])
        entry = {"id": sw["id"], "host": sw["host"], "label": sw["label"],
                 "port": sw["port"], "site": sw.get("site", "")}
        if data:
            entry["data"] = data
        else:
            entry["data"] = None
        result.append(entry)
    return jsonify(result)


@app.route("/api/switch/<int:switch_id>", methods=["PUT", "DELETE"])
@api_login_required
def api_switch_edit(switch_id):
    switch = db.get_switch(switch_id)
    if not switch:
        return jsonify({"error": "Switch not found"}), 404
    if request.method == "DELETE":
        db.audit("switch_deleted", f"Deleted switch {switch['label']} ({switch['host']})",
                 switch_id=switch_id, switch_host=switch["host"])
        with CACHE_LOCK:
            collect_cache.pop(switch["host"], None)
        db.delete_switch(switch_id)
        return jsonify({"status": "ok"})
    data = request.get_json() or {}
    host = data.get("host", switch["host"]).strip()
    username = data.get("username", switch["username"]).strip()
    password = data.get("password", "") or switch["password"]
    port = int(data.get("port", switch["port"]))
    label = data.get("label", switch["label"]).strip()
    site = data.get("site", switch.get("site", "")).strip()
    db.update_switch(switch_id, host=host, username=username, password=password,
                     port=port, label=label, site=site)
    with CACHE_LOCK:
        collect_cache.pop(switch["host"], None)
    if host != switch["host"]:
        collect_cache.pop(host, None)
    db.audit("switch_edited", f"Edited switch {label} ({host})", switch_id=switch_id, switch_host=host)
    return jsonify({"status": "ok"})


@app.route("/api/switch/<int:switch_id>")
@api_login_required
def api_switch_detail(switch_id):
    switch = db.get_switch(switch_id)
    if not switch:
        return jsonify({"error": "Switch not found"}), 404
    data = _get_cached(switch["host"])
    if not data:
        data = _collect_and_cache(switch)
    return jsonify({"switch": switch, "data": data})


@app.route("/api/metrics/<int:switch_id>")
@api_login_required
def api_metrics(switch_id):
    snapshots = db.get_snapshots(switch_id, limit=500)
    cpu_series = []
    mem_series = []
    for snap in snapshots:
        try:
            data = json.loads(snap["data_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        if not data.get("reachable"):
            continue
        r = data.get("resource", {})
        cpu_val = r.get("cpu_usage")
        mem_val = r.get("memory_usage_pct")
        ts = snap["collected_at"]
        if isinstance(cpu_val, (int, float)):
            cpu_series.append({"timestamp": ts, "value": cpu_val})
        if isinstance(mem_val, (int, float)):
            mem_series.append({"timestamp": ts, "value": mem_val})
    return jsonify({"cpu": cpu_series, "memory": mem_series})


@app.route("/api/refresh/<int:switch_id>", methods=["POST"])
@api_login_required
def api_refresh(switch_id):
    switch = db.get_switch(switch_id)
    if not switch:
        return jsonify({"error": "Switch not found"}), 404
    res = _collect_and_cache(switch)
    db.save_snapshot(switch_id, json.dumps(res, default=str))
    status = "success" if res.get("reachable") else "failed"
    db.audit(f"refresh_{status}",
             f"Refresh {status} for {switch['label']} ({switch['host']})",
             switch_id=switch_id, switch_host=switch["host"],
             details={"reachable": res.get("reachable"),
                      "error": res.get("error"),
                      "cpu": res.get("resource", {}).get("cpu_usage"),
                      "memory_pct": res.get("resource", {}).get("memory_usage_pct")})
    return jsonify({"reachable": res.get("reachable", False), "host": switch["host"]})


@app.route("/api/refresh_all", methods=["POST"])
@api_login_required
def api_refresh_all():
    switches = db.get_all_switches()
    success = 0
    failed = 0
    for sw in switches:
        res = _collect_and_cache(sw)
        if res.get("reachable"):
            success += 1
        else:
            failed += 1
    db.audit("refresh_all",
             f"Refreshed all switches: {success} online, {failed} offline",
             details={"success": success, "failed": failed, "total": len(switches)})
    return jsonify({"status": "ok", "success": success, "failed": failed})


@app.route("/api/logs")
@api_login_required
def api_logs():
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    event_type = request.args.get("event_type")
    switch_id = request.args.get("switch_id", type=int)
    logs = db.get_audit_logs(limit=limit, offset=offset, event_type=event_type, switch_id=switch_id)
    types = db.get_audit_event_types()
    stats = db.get_audit_stats()
    return jsonify({"logs": logs, "event_types": types, "stats": stats})


@app.route("/api/config")
def api_config():
    return jsonify({"poll_interval": POLL_INTERVAL})


@app.route("/api/terminal/<int:switch_id>", methods=["POST"])
@api_login_required
def api_terminal(switch_id):
    sw = db.get_switch(switch_id)
    if not sw:
        return jsonify({"error": "Switch not found"}), 404
    data = request.get_json() or {}
    cmd = data.get("command", "").strip()
    if not cmd:
        return jsonify({"error": "No command"}), 400
    try:
        ssh = _build_ssh(sw["host"], sw["username"], sw["password"], sw["port"], timeout=15)
        output = _ssh_exec(ssh, cmd + "\n", timeout=30)
        ssh.close()
        db.audit("terminal_command", f"Executed on {sw['label']}: {cmd[:80]}",
                 switch_id=switch_id, switch_host=sw["host"],
                 details={"cmd": cmd, "len": len(output) if output else 0})
        return jsonify({"output": output or "(empty)"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _background_collect():
    """Periodically collect all switches so metrics accumulate."""
    while True:
        threading.Event().wait(POLL_INTERVAL)
        try:
            switches = db.get_all_switches()
        except Exception:
            continue
        for sw in switches:
            try:
                res = _collect_and_cache(sw)
                db.save_snapshot(sw["id"], json.dumps(res, default=str))
            except Exception:
                pass


if __name__ == "__main__":
    _load_cache_from_db()
    t = threading.Thread(target=_background_collect, daemon=True)
    t.start()
    db.audit("system_startup", "Cisco Switch Manager started")
    app.run(host="0.0.0.0", port=5000, debug=True)
