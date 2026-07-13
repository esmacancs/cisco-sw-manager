import sqlite3
import os
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "mds_portal.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS switches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                label TEXT,
                site TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                switch_id INTEGER NOT NULL,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_json TEXT,
                FOREIGN KEY (switch_id) REFERENCES switches(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                switch_id INTEGER,
                switch_host TEXT,
                message TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY (switch_id) REFERENCES switches(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                metric TEXT NOT NULL,
                operator TEXT NOT NULL DEFAULT '>',
                threshold REAL NOT NULL,
                severity TEXT NOT NULL DEFAULT 'warning',
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                switch_id INTEGER,
                switch_host TEXT,
                message TEXT NOT NULL,
                current_value REAL,
                severity TEXT NOT NULL DEFAULT 'warning',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged_at TIMESTAMP,
                FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
                FOREIGN KEY (switch_id) REFERENCES switches(id) ON DELETE SET NULL
            );
        """)
    _migrate_schema()
    ensure_admin_exists()


def _migrate_schema():
    with _get_conn() as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(switches)").fetchall()]
        if "site" not in cols:
            conn.execute("ALTER TABLE switches ADD COLUMN site TEXT DEFAULT ''")
        ucols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "hidden_tabs" not in ucols:
            conn.execute("ALTER TABLE users ADD COLUMN hidden_tabs TEXT DEFAULT ''")

        # Migrate alert_rules table: old schema had metric_type, switch_id; new has metric
        ar_cols = [r["name"] for r in conn.execute("PRAGMA table_info(alert_rules)").fetchall()]
        if "metric_type" in ar_cols and "metric" not in ar_cols:
            # Drop old table and recreate with new schema
            conn.execute("DROP TABLE IF EXISTS alert_rules")
            conn.execute("DROP TABLE IF EXISTS alerts")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    operator TEXT NOT NULL DEFAULT '>',
                    threshold REAL NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL,
                    switch_id INTEGER,
                    switch_host TEXT,
                    message TEXT NOT NULL,
                    current_value REAL,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged_at TIMESTAMP,
                    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
                    FOREIGN KEY (switch_id) REFERENCES switches(id) ON DELETE SET NULL
                );
            """)
            print("[migrate] Recreated alert_rules and alerts tables with new schema")
        elif not ar_cols:
            # Tables don't exist yet, will be created by executescript above
            pass


# ---------- Switches ----------

def get_all_switches():
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM switches ORDER BY label, host").fetchall()
        return [dict(r) for r in rows]


def add_switch(host, username, password, port=22, label="", site=""):
    with _get_conn() as conn:
        label = label or host
        conn.execute(
            "INSERT OR REPLACE INTO switches (host, username, password, port, label, site) VALUES (?, ?, ?, ?, ?, ?)",
            (host, username, password, port, label, site),
        )


def update_switch(switch_id, host=None, username=None, password=None, port=None, label=None, site=None):
    with _get_conn() as conn:
        sw = conn.execute("SELECT * FROM switches WHERE id = ?", (switch_id,)).fetchone()
        if not sw:
            return False
        host = host if host is not None else sw["host"]
        username = username if username is not None else sw["username"]
        password = password if password is not None else sw["password"]
        port = port if port is not None else sw["port"]
        label = label if label is not None else sw["label"]
        site = site if site is not None else sw["site"]
        conn.execute(
            "UPDATE switches SET host=?, username=?, password=?, port=?, label=?, site=? WHERE id=?",
            (host, username, password, port, label, site, switch_id),
        )
        return True


def delete_switch(switch_id):
    with _get_conn() as conn:
        conn.execute("DELETE FROM switches WHERE id = ?", (switch_id,))


def get_switch(switch_id):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM switches WHERE id = ?", (switch_id,)).fetchone()
        return dict(row) if row else None


# ---------- Snapshots ----------

def save_snapshot(switch_id, data_json):
    with _get_conn() as conn:
        conn.execute("INSERT INTO snapshots (switch_id, data_json) VALUES (?, ?)", (switch_id, data_json))


def get_latest_snapshot(switch_id):
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots WHERE switch_id = ? ORDER BY collected_at DESC LIMIT 1", (switch_id,)
        ).fetchone()
        return dict(row) if row else None


def get_snapshots(switch_id, limit=200, offset=0):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM snapshots WHERE switch_id = ? ORDER BY collected_at ASC LIMIT ? OFFSET ?",
            (switch_id, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def get_recent_snapshots(switch_id, limit=10):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM snapshots WHERE switch_id = ? ORDER BY collected_at DESC LIMIT ?",
            (switch_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- Audit Log ----------

def audit(event_type, message, switch_id=None, switch_host=None, details=None):
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log (event_type, message, switch_id, switch_host, details) VALUES (?, ?, ?, ?, ?)",
            (event_type, message, switch_id, switch_host, json.dumps(details) if details else None),
        )


def get_audit_logs(limit=200, offset=0, event_type=None, switch_id=None):
    with _get_conn() as conn:
        parts = ["SELECT * FROM audit_log"]
        params = []
        where = []
        if event_type:
            where.append("event_type = ?")
            params.append(event_type)
        if switch_id is not None:
            where.append("switch_id = ?")
            params.append(switch_id)
        if where:
            parts.append("WHERE " + " AND ".join(where))
        parts.append("ORDER BY timestamp DESC LIMIT ? OFFSET ?")
        params.extend([limit, offset])
        rows = conn.execute(" ".join(parts), params).fetchall()
        return [dict(r) for r in rows]


def get_audit_event_types():
    with _get_conn() as conn:
        rows = conn.execute("SELECT DISTINCT event_type FROM audit_log ORDER BY event_type").fetchall()
        return [r["event_type"] for r in rows]


# ---------- Users ----------

def create_user(username, password, role="user"):
    with _get_conn() as conn:
        try:
            hidden = "console" if role == "user" else ""
            conn.execute(
                "INSERT INTO users (username, password_hash, role, hidden_tabs) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, hidden),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def verify_user(username, password):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            return dict(row)
    return None


def get_user_by_id(user_id):
    with _get_conn() as conn:
        row = conn.execute("SELECT id, username, role, created_at, hidden_tabs FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_all_users():
    with _get_conn() as conn:
        rows = conn.execute("SELECT id, username, role, created_at, hidden_tabs FROM users ORDER BY username").fetchall()
        return [dict(r) for r in rows]


def change_password(user_id, new_password):
    with _get_conn() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (generate_password_hash(new_password), user_id))


def delete_user(user_id):
    with _get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def update_user_tabs(user_id, hidden_tabs):
    with _get_conn() as conn:
        conn.execute("UPDATE users SET hidden_tabs = ? WHERE id = ?", (hidden_tabs, user_id))


def ensure_admin_exists():
    with _get_conn() as conn:
        row = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
        if not row:
            create_user("admin", "admin", role="admin")
            print("[init] Created default admin user (admin / admin)")


def get_audit_stats():
    with _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) as c FROM audit_log").fetchone()["c"]
        by_type = conn.execute(
            "SELECT event_type, COUNT(*) as c FROM audit_log GROUP BY event_type ORDER BY c DESC"
        ).fetchall()
        return {"total": total, "by_type": [dict(r) for r in by_type]}


# ---------- Alert Rules ----------

def get_all_alert_rules():
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM alert_rules ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_alert_rule(rule_id):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        return dict(row) if row else None


def add_alert_rule(name, metric, operator, threshold, severity="warning"):
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO alert_rules (name, metric, operator, threshold, severity) VALUES (?, ?, ?, ?, ?)",
            (name, metric, operator, threshold, severity),
        )


def update_alert_rule(rule_id, name=None, metric=None, operator=None, threshold=None, severity=None, enabled=None):
    with _get_conn() as conn:
        rule = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        if not rule:
            return False
        name = name if name is not None else rule["name"]
        metric = metric if metric is not None else rule["metric"]
        operator = operator if operator is not None else rule["operator"]
        threshold = threshold if threshold is not None else rule["threshold"]
        severity = severity if severity is not None else rule["severity"]
        enabled = enabled if enabled is not None else rule["enabled"]
        conn.execute(
            "UPDATE alert_rules SET name=?, metric=?, operator=?, threshold=?, severity=?, enabled=? WHERE id=?",
            (name, metric, operator, threshold, severity, enabled, rule_id),
        )
        return True


def delete_alert_rule(rule_id):
    with _get_conn() as conn:
        conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))


# ---------- Alerts ----------

def add_alert(rule_id, switch_id, switch_host, message, current_value, severity):
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (rule_id, switch_id, switch_host, message, current_value, severity) VALUES (?, ?, ?, ?, ?, ?)",
            (rule_id, switch_id, switch_host, message, current_value, severity),
        )


def get_alerts(limit=200, offset=0, status=None, severity=None, switch_id=None):
    with _get_conn() as conn:
        parts = ["SELECT a.*, r.name as rule_name, r.metric FROM alerts a LEFT JOIN alert_rules r ON a.rule_id = r.id"]
        params = []
        where = []
        if status:
            where.append("a.status = ?")
            params.append(status)
        if severity:
            where.append("a.severity = ?")
            params.append(severity)
        if switch_id is not None:
            where.append("a.switch_id = ?")
            params.append(switch_id)
        if where:
            parts.append("WHERE " + " AND ".join(where))
        parts.append("ORDER BY a.created_at DESC LIMIT ? OFFSET ?")
        params.extend([limit, offset])
        rows = conn.execute(" ".join(parts), params).fetchall()
        return [dict(r) for r in rows]


def get_active_alert_count():
    with _get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE status = 'active'").fetchone()
        return row["c"]


def acknowledge_alert(alert_id):
    with _get_conn() as conn:
        conn.execute(
            "UPDATE alerts SET status = 'acknowledged', acknowledged_at = CURRENT_TIMESTAMP WHERE id = ?",
            (alert_id,),
        )


def acknowledge_all_alerts():
    with _get_conn() as conn:
        conn.execute(
            "UPDATE alerts SET status = 'acknowledged', acknowledged_at = CURRENT_TIMESTAMP WHERE status = 'active'"
        )


def delete_old_alerts(days=30):
    with _get_conn() as conn:
        conn.execute(
            "DELETE FROM alerts WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        )
