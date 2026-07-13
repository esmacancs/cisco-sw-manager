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
- **Alert system** — Threshold-based alerting with rules, notifications, and history
- **Interface traffic monitoring** — Per-interface RX/TX rates, bytes, packets
- **MAC address table learning** — Client-to-port mapping with search and "By Port" view
- **Tiered polling** — ~50% fewer SSH commands per cycle (reduces switch load)

## Alert System

Create threshold-based rules to monitor CPU, memory, interfaces, and more:

| Metric | Description |
|--------|-------------|
| `cpu_usage` | CPU utilization percentage |
| `memory_usage_pct` | Memory usage percentage |
| `memory_used_kb` | Memory used in KB |
| `load_1m` | Load average (1 minute) |
| `interface_count` | Total interface count |
| `down_interfaces` | Number of down interfaces |
| `port_count` | Total port count |

**Severity levels:** Critical, Warning, Info

- Alerts auto-evaluate after every collection cycle and manual refresh
- Bell icon with red badge shows active alert count on all pages
- Nagios-style summary panel on dashboard (Critical / Warning / Info / Total)
- Acknowledge individual alerts or bulk "Ack All"
- Alert history page with filtering by status and severity
- Rules page: create, edit, enable/disable, delete

## Traffic Monitoring

Per-interface traffic counters collected via `show interface counters`:

- **RX/TX Rate** (bps) — calculated from snapshot deltas
- **PPS** (packets per second)
- **Total bytes and packets**
- Sortable columns, color-coded rates
- Works on MDS (FC verbose format) and Nexus (tabular multi-section format)

## MAC Address Table

Client-to-port mapping via `show mac address-table dynamic` (Nexus/IOS only):

- **Table view** — sortable columns: VLAN, MAC Address, Type, Age, Port
- **By Port view** — grouped cards showing which MACs are on each port
- **Search/filter** — filter by MAC, port, VLAN, or type
- **Stats** — total MACs, unique ports, dynamic vs static counts
- MDS switches: FLOGI tab already provides FC port-login mapping (WWN to port)

## Tiered Polling

To reduce switch load, collection is split into two tiers:

### Tier 1 — Fast-changing data (every 30s)
| Command | Platform |
|---------|----------|
| `show system resources` | MDS/Nexus |
| `show processes cpu \| i CPU` | IOS |
| `show memory statistics` | IOS |
| `show interface brief` | MDS |
| `show interface status` | Nexus/IOS |
| `show interface counters` | All |
| `show log(last 100)` | All |
| `show mac address-table dynamic` | Nexus/IOS |

### Tier 2 — Static/slow-changing data (every 10 minutes)
| Command | Platform |
|---------|----------|
| `show version` | All |
| `show inventory` | All |
| `show module` | MDS/Nexus |
| `show environment` | All |
| `show vlan brief` / `show vsan` | Nexus/IOS/MDS |
| `show port-channel summary` | All |
| `show boot` / `dir bootflash:` | All |
| `show fcns database` | MDS |
| `show flogi database` | MDS |
| `show zoneset active` | MDS |
| `show device-alias database` | MDS |
| `show port-security database` | MDS |
| `show interface description` | Nexus |

### Impact

| | Before | After |
|---|---|---|
| SSH commands per cycle (MDS) | ~19 | ~4 |
| SSH commands per cycle (Nexus) | ~15 | ~5 |
| SSH commands per cycle (IOS) | ~14 | ~6 |
| Switch load reduction | — | **~50-70%** |
| Tier1 data freshness | 30s | 30s (unchanged) |
| Tier2 data freshness | 30s | 10 minutes |

### Settings API

```bash
# View current settings
GET /api/settings

# Update (admin only)
POST /api/settings
{
  "poll_interval": 60,      # seconds (min: 10)
  "tier2_interval": 300     # seconds (min: 60)
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/switches` | GET | List all switches with latest metrics |
| `/api/switch/<id>` | GET/PUT/DELETE | Get, update, or delete a switch |
| `/api/switch/<id>` | GET | Switch detail data |
| `/api/metrics/<id>` | GET | Time-series metrics for charts |
| `/api/traffic/<id>` | GET | Interface traffic with rates |
| `/api/mac-table/<id>` | GET | MAC address table |
| `/api/refresh/<id>` | POST | Manual refresh (triggers tiered collection) |
| `/api/refresh_all` | POST | Refresh all switches |
| `/api/alerts` | GET | Alert history with filters |
| `/api/alerts/summary` | GET | Active alert counts by severity |
| `/api/alerts/<id>/acknowledge` | POST | Acknowledge an alert |
| `/api/alerts/acknowledge_all` | POST | Acknowledge all alerts |
| `/api/rules` | GET/POST | List or create alert rules |
| `/api/rules/<id>` | PUT/DELETE | Update or delete alert rule |
| `/api/settings` | GET/POST | View/update poll intervals (admin) |
| `/api/logs` | GET | Audit log with filters |
| `/api/config` | GET | Public config (poll interval) |
| `/api/terminal/<id>` | POST | Execute SSH command in terminal |

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
├── app.py                 # Flask app, routes, auth, APIs, tiered collection
├── database.py            # SQLite database layer, migrations, CRUD
├── mds_collector.py       # Multi-platform SSH collector + parsers + tiered commands
├── fetch_raw.py           # Standalone raw data fetcher
├── Dockerfile             # Docker build file
├── docker-compose.yml     # Docker Compose configuration
├── requirements.txt       # Python dependencies
└── templates/
    ├── login.html         # Professional split-screen login
    ├── index.html         # Dashboard with site grouping + alert summary
    ├── switch.html        # Switch detail page with tabs + console
    ├── alerts.html        # Alert history with filtering
    ├── rules.html         # Alert rule management
    ├── add_switch.html    # Add/Edit switch form
    ├── users.html         # User management with tab permissions
    ├── logs.html          # Audit log viewer
    └── signup.html        # User registration
```

## Upgrade

```bash
git pull
docker compose build
docker compose up -d
```

The SQLite database is stored in a Docker named volume (`cisco_data`) and persists across upgrades.
