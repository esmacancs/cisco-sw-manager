# Cisco Switch Manager

Multi-platform Cisco switch monitoring portal with web-based SSH terminal. Supports **MDS FC**, **Nexus NX-OS TOR**, and **Catalyst IOS/IOS-XE** core switches with platform-specific data collection and display.

## Features

- **Multi-platform auto-detection** — MDS, Nexus, IOS detected automatically via `show version`
- **Platform-specific dashboards** — VSANs for MDS, VLANs for Nexus/IOS, FCNS/FLOGI for MDS
- **Live metrics** — CPU/memory gauges with time-series charting
- **Web SSH Console** — Run commands interactively from your browser
- **Role-based access** — Admin/user roles with per-tab visibility control
- **Site grouping** — Organize switches by DataCenter, Prod, DR, etc.
- **Auto-refresh** — Configurable polling interval (Off / 10s / 30s / 60s / 120s)
- **Audit logging** — All actions logged with searchable history
- **Dark/Light theme** — Persistent theme toggle

## Quick Start

### Using Docker (recommended)

```bash
# 1. Clone the repo
git clone https://github.com/esmacancs/cisco-sw-manager.git
cd cisco-sw-manager

# 2. Set a secret key (optional — auto-generated if omitted)
export FLASK_SECRET_KEY=$(openssl rand -hex 32)

# 3. Build and start
docker compose up -d

# 4. Open http://localhost:5000
```

### Using Python directly

```bash
# 1. Clone and enter the directory
git clone https://github.com/esmacancs/cisco-sw-manager.git
cd cisco-sw-manager

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py

# 4. Open http://localhost:5000
```

## Default Credentials

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin    | Admin |

## Docker Commands

| Command                        | Description                    |
|--------------------------------|--------------------------------|
| `docker compose up -d`         | Start in background            |
| `docker compose down`          | Stop and remove container      |
| `docker compose logs -f`       | Follow logs                    |
| `docker compose build`         | Rebuild after pulling updates  |
| `docker compose pull`          | Pull latest base image         |

## Environment Variables

| Variable          | Default                        | Description                          |
|-------------------|--------------------------------|--------------------------------------|
| `FLASK_SECRET_KEY`| Auto-generated UUID            | Secret key for session encryption    |
| `FLASK_DEBUG`     | `0`                            | Set to `1` to enable debug mode      |
| `DATA_DIR`        | `/app/data` (Docker) / `.`     | Directory for SQLite database file   |

## Project Structure

```
├── app.py                 # Flask app, routes, auth, APIs
├── database.py            # SQLite database layer
├── mds_collector.py       # Multi-platform SSH collector + parsers
├── fetch_raw.py           # Standalone raw data fetcher
├── Dockerfile             # Docker build file
├── docker-compose.yml     # Docker Compose configuration
├── requirements.txt       # Python dependencies
└── templates/
    ├── login.html         # Professional split-screen login
    ├── index.html         # Dashboard with site grouping
    ├── switch.html        # Switch detail page with tabs + console
    ├── add_switch.html    # Add/Edit switch form
    ├── users.html         # User management with tab permissions
    ├── logs.html          # Audit log viewer
    ├── signup.html        # User registration
    └── users.html         # User management
```

## Upgrade

```bash
git pull
docker compose build
docker compose up -d
```

The SQLite database is stored in a Docker named volume (`cisco_data`) and persists across upgrades.
