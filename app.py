import json
import os
import threading
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import database as db
from mds_collector import collect_switch, collect_switch_tier1, collect_switch_tier2, _build_ssh, _ssh_exec

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", uuid.uuid4().hex)
db.init_db()

collect_cache = {}
CACHE_LOCK = threading.Lock()
POLL_INTERVAL = 30
TIER2_INTERVAL = 600  # 10 minutes between full collections
_tier2_last_run = {}  # host -> timestamp of last tier2 collection


def _get_cached(host):
    with CACHE_LOCK:
        return collect_cache.get(host)


def _set_cached(host, data):
    with CACHE_LOCK:
        collect_cache[host] = data


def _load_cache_from_db():
    import time
    switches = db.get_all_switches()
    for sw in switches:
        snap = db.get_latest_snapshot(sw["id"])
        if snap:
            try:
                data = json.loads(snap["data_json"])
                _set_cached(sw["host"], data)
                # Restore tier2 timestamp from snapshot time
                collected_at = snap.get("collected_at", "")
                if collected_at:
                    try:
                        from datetime import datetime
                        ts = datetime.strptime(collected_at, "%Y-%m-%d %H:%M:%S").timestamp()
                        _tier2_last_run[sw["host"]] = ts
                    except Exception:
                        pass
            except (json.JSONDecodeError, TypeError):
                pass


def _collect_and_cache(switch_dict):
    """Collect from switch using tiered approach: tier1 every cycle, tier2 every 10 minutes."""
    import time
    host = switch_dict["host"]
    port = switch_dict.get("port", 22)
    now = time.time()
    last_t2 = _tier2_last_run.get(host, 0)
    need_tier2 = (now - last_t2) >= TIER2_INTERVAL

    if need_tier2:
        # Full collection (includes tier2 data)
        res = collect_switch(host, switch_dict["username"], switch_dict["password"], port)
        if res.get("reachable"):
            _tier2_last_run[host] = now
    else:
        # Tier 1 only — merge with cached tier2 data
        t1 = collect_switch_tier1(host, switch_dict["username"], switch_dict["password"], port)
        cached = _get_cached(host) or {}
        res = {**cached, **t1}
        res["host"] = host
        res["reachable"] = t1.get("reachable", False)

    _set_cached(host, res)
    return res


# ---------- Alert Evaluation ----------

OPERATORS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
}


def _extract_metric_value(data, metric):
    if not data or not data.get("reachable"):
        return None
    r = data.get("resource", {})
    mapping = {
        "cpu_usage": r.get("cpu_usage"),
        "memory_usage_pct": r.get("memory_usage_pct"),
        "memory_used_kb": r.get("memory_used_kb"),
        "load_1m": r.get("load_1m"),
        "interface_count": len(data.get("interfaces", [])),
        "down_interfaces": sum(1 for i in data.get("interfaces", []) if i.get("status") != "up"),
        "port_count": len(data.get("interfaces", [])),
    }
    return mapping.get(metric)


def evaluate_alerts_for_switch(switch_id, switch_host, data):
    rules = db.get_all_alert_rules()
    for rule in rules:
        if not rule["enabled"]:
            continue
        value = _extract_metric_value(data, rule["metric"])
        if value is None:
            continue
        op_fn = OPERATORS.get(rule["operator"])
        if op_fn and op_fn(value, rule["threshold"]):
            existing = db.get_alerts(limit=50, status="active", switch_id=switch_id)
            already_fired = any(
                a["rule_id"] == rule["id"] and a["message"] == f"{rule['metric']} {rule['operator']} {rule['threshold']} (current: {value})"
                for a in existing
            )
            if not already_fired:
                msg = f"{rule['metric']} {rule['operator']} {rule['threshold']} (current: {value})"
                db.add_alert(rule["id"], switch_id, switch_host, msg, value, rule["severity"])


def evaluate_all_alerts():
    switches = db.get_all_switches()
    for sw in switches:
        data = _get_cached(sw["host"])
        if data:
            evaluate_alerts_for_switch(sw["id"], sw["host"], data)


@app.context_processor
def inject_user():
    uid = session.get("user_id")
    ht = ""
    if uid:
        u = db.get_user_by_id(uid)
        if u:
            ht = u.get("hidden_tabs", "")
    return {
        "current_user": session.get("username"),
        "current_role": session.get("role"),
        "hidden_tabs": ht,
        "active_alert_count": db.get_active_alert_count(),
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


@app.route("/api/users/<int:user_id>", methods=["DELETE", "PUT"])
@api_login_required
def api_user_manage(user_id):
    if session.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    if request.method == "DELETE":
        if user_id == session["user_id"]:
            return jsonify({"error": "Cannot delete yourself"}), 400
        db.delete_user(user_id)
        db.audit("user_deleted", f"Admin deleted user id {user_id}")
        return jsonify({"status": "ok"})
    data = request.get_json() or {}
    if "hidden_tabs" in data:
        db.update_user_tabs(user_id, data["hidden_tabs"])
        db.audit("user_updated", f"Admin updated tabs for user id {user_id}",
                 details={"hidden_tabs": data["hidden_tabs"]})
    if "password" in data and data["password"]:
        db.change_password(user_id, data["password"])
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
    uid = session.get("user_id")
    hidden = ""
    if uid:
        u = db.get_user_by_id(uid)
        if u:
            hidden = u.get("hidden_tabs", "")
    return render_template("switch.html", switch=switch, current_hidden_tabs=hidden)


@app.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html")


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html")


@app.route("/rules")
@login_required
def rules_page():
    return render_template("rules.html")


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


@app.route("/api/traffic/<int:switch_id>")
@api_login_required
def api_traffic(switch_id):
    snapshots = db.get_recent_snapshots(switch_id, limit=50)
    latest = None
    previous = None
    for snap in snapshots:
        try:
            data = json.loads(snap["data_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        if not data.get("reachable"):
            continue
        traffic = data.get("traffic", [])
        if traffic:
            if latest is None:
                latest = {"traffic": traffic, "ts": snap["collected_at"]}
            elif previous is None:
                previous = {"traffic": traffic, "ts": snap["collected_at"]}
                break
    current = latest["traffic"] if latest else []
    rates = []
    if previous and latest:
        prev_map = {t["interface"]: t for t in previous["traffic"]}
        dt = 0
        try:
            from datetime import datetime
            fmt = "%Y-%m-%d %H:%M:%S"
            t1 = datetime.strptime(previous["ts"], fmt)
            t2 = datetime.strptime(latest["ts"], fmt)
            dt = (t2 - t1).total_seconds()
        except Exception:
            pass
        for entry in current:
            name = entry.get("interface", "")
            prev = prev_map.get(name, {})
            rx_b = entry.get("rx_bytes", 0)
            tx_b = entry.get("tx_bytes", 0)
            prx_b = prev.get("rx_bytes", 0)
            ptx_b = prev.get("tx_bytes", 0)
            rx_p = entry.get("rx_packets", 0)
            tx_p = entry.get("tx_packets", 0)
            prx_p = prev.get("rx_packets", 0)
            ptx_p = prev.get("tx_packets", 0)
            rx_rate = round((rx_b - prx_b) / dt, 0) if dt > 0 else 0
            tx_rate = round((tx_b - ptx_b) / dt, 0) if dt > 0 else 0
            pps_in = round((rx_p - prx_p) / dt, 0) if dt > 0 else 0
            pps_out = round((tx_p - ptx_p) / dt, 0) if dt > 0 else 0
            rates.append({
                "interface": name, "rx_bytes": rx_b, "tx_bytes": tx_b,
                "rx_packets": rx_p, "tx_packets": tx_p,
                "rx_rate_bps": rx_rate, "tx_rate_bps": tx_rate,
                "pps_in": pps_in, "pps_out": pps_out,
            })
    else:
        for entry in current:
            rates.append({
                "interface": entry.get("interface", ""),
                "rx_bytes": entry.get("rx_bytes", 0), "tx_bytes": entry.get("tx_bytes", 0),
                "rx_packets": entry.get("rx_packets", 0), "tx_packets": entry.get("tx_packets", 0),
                "rx_rate_bps": 0, "tx_rate_bps": 0, "pps_in": 0, "pps_out": 0,
            })
    return jsonify({"traffic": rates, "collected_at": latest["ts"] if latest else None})


@app.route("/api/mac-table/<int:switch_id>")
@api_login_required
def api_mac_table(switch_id):
    snap = db.get_latest_snapshot(switch_id)
    if not snap:
        return jsonify({"mac_table": [], "collected_at": None})
    try:
        data = json.loads(snap["data_json"])
    except (json.JSONDecodeError, TypeError):
        return jsonify({"mac_table": [], "collected_at": None})
    mac_table = data.get("mac_table", [])
    return jsonify({"mac_table": mac_table, "collected_at": snap.get("collected_at")})


@app.route("/api/refresh/<int:switch_id>", methods=["POST"])
@api_login_required
def api_refresh(switch_id):
    switch = db.get_switch(switch_id)
    if not switch:
        return jsonify({"error": "Switch not found"}), 404
    res = _collect_and_cache(switch)
    db.save_snapshot(switch_id, json.dumps(res, default=str))
    evaluate_alerts_for_switch(switch_id, switch["host"], res)
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
    return jsonify({"poll_interval": POLL_INTERVAL, "tier2_interval": TIER2_INTERVAL})


@app.route("/api/settings", methods=["GET", "POST"])
@api_login_required
def api_settings():
    global POLL_INTERVAL, TIER2_INTERVAL
    if session.get("role") != "admin":
        return jsonify({"error": "Admin only"}), 403
    if request.method == "GET":
        return jsonify({
            "poll_interval": POLL_INTERVAL,
            "tier2_interval": TIER2_INTERVAL,
            "tier2_last_run": dict(_tier2_last_run),
        })
    data = request.get_json(silent=True) or {}
    if "poll_interval" in data:
        val = int(data["poll_interval"])
        if val >= 10:
            POLL_INTERVAL = val
    if "tier2_interval" in data:
        val = int(data["tier2_interval"])
        if val >= 60:
            TIER2_INTERVAL = val
    db.audit("settings_change",
             f"Settings updated: POLL_INTERVAL={POLL_INTERVAL}, TIER2_INTERVAL={TIER2_INTERVAL}")
    return jsonify({"poll_interval": POLL_INTERVAL, "tier2_interval": TIER2_INTERVAL})


@app.route("/api/alerts")
@api_login_required
def api_alerts():
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    status = request.args.get("status")
    severity = request.args.get("severity")
    switch_id = request.args.get("switch_id", type=int)
    alerts = db.get_alerts(limit=limit, offset=offset, status=status, severity=severity, switch_id=switch_id)
    return jsonify({"alerts": alerts, "count": db.get_active_alert_count()})


@app.route("/api/alerts/acknowledge_all", methods=["POST"])
@api_login_required
def api_acknowledge_all():
    db.acknowledge_all_alerts()
    return jsonify({"status": "ok"})


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@api_login_required
def api_acknowledge_alert(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok"})


@app.route("/api/alerts/<int:alert_id>", methods=["DELETE"])
@api_login_required
def api_delete_alert(alert_id):
    with db._get_conn() as conn:
        conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    return jsonify({"status": "ok"})


@app.route("/api/alerts/summary")
@api_login_required
def api_alerts_summary():
    with db._get_conn() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as c FROM alerts WHERE status = 'active' GROUP BY severity"
        ).fetchall()
        by_severity = {r["severity"]: r["c"] for r in rows}
        total = sum(by_severity.values())
    return jsonify({
        "total": total,
        "critical": by_severity.get("critical", 0),
        "warning": by_severity.get("warning", 0),
        "info": by_severity.get("info", 0),
    })


@app.route("/api/rules")
@api_login_required
def api_rules():
    rules = db.get_all_alert_rules()
    return jsonify({"rules": rules})


@app.route("/api/rules", methods=["POST"])
@api_login_required
def api_create_rule():
    if session.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    metric = data.get("metric", "").strip()
    operator = data.get("operator", ">")
    threshold = data.get("threshold", 0)
    severity = data.get("severity", "warning")
    if not name or not metric:
        return jsonify({"error": "Name and metric required"}), 400
    if metric not in ("cpu_usage", "memory_usage_pct", "memory_used_kb", "load_1m", "interface_count", "down_interfaces", "port_count"):
        return jsonify({"error": "Invalid metric"}), 400
    if operator not in OPERATORS:
        return jsonify({"error": "Invalid operator"}), 400
    db.add_alert_rule(name, metric, operator, threshold, severity)
    db.audit("rule_created", f"Created alert rule: {name}")
    return jsonify({"status": "ok"})


@app.route("/api/rules/<int:rule_id>", methods=["PUT", "DELETE"])
@api_login_required
def api_manage_rule(rule_id):
    if session.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    if request.method == "DELETE":
        db.delete_alert_rule(rule_id)
        db.audit("rule_deleted", f"Deleted alert rule id {rule_id}")
        return jsonify({"status": "ok"})
    data = request.get_json() or {}
    db.update_alert_rule(
        rule_id,
        name=data.get("name"),
        metric=data.get("metric"),
        operator=data.get("operator"),
        threshold=data.get("threshold"),
        severity=data.get("severity"),
        enabled=data.get("enabled"),
    )
    db.audit("rule_updated", f"Updated alert rule id {rule_id}")
    return jsonify({"status": "ok"})


@app.route("/api/terminal/<int:switch_id>", methods=["POST"])
@api_login_required
def api_terminal(switch_id):
    uid = session.get("user_id")
    if uid:
        u = db.get_user_by_id(uid)
        if u and "console" in (u.get("hidden_tabs", "") or "").split(","):
            return jsonify({"error": "Console access denied"}), 403
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
                evaluate_alerts_for_switch(sw["id"], sw["host"], res)
            except Exception:
                pass


if __name__ == "__main__":
    _load_cache_from_db()
    t = threading.Thread(target=_background_collect, daemon=True)
    t.start()
    db.audit("system_startup", "Cisco Switch Manager started")
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
