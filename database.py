import sqlite3
import os
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mds_portal.db")


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
        """)
    _migrate_schema()
    ensure_admin_exists()


def _migrate_schema():
    with _get_conn() as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(switches)").fetchall()]
        if "site" not in cols:
            conn.execute("ALTER TABLE switches ADD COLUMN site TEXT DEFAULT ''")


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
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
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
        row = conn.execute("SELECT id, username, role, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_all_users():
    with _get_conn() as conn:
        rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY username").fetchall()
        return [dict(r) for r in rows]


def change_password(user_id, new_password):
    with _get_conn() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (generate_password_hash(new_password), user_id))


def delete_user(user_id):
    with _get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


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
