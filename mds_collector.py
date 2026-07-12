from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import paramiko
import re

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [collector] %(levelname)s: %(message)s")


def _ssh_exec(ssh, cmd, timeout=30):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace").strip()


def _build_ssh(host, username, password, port, timeout=30):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=timeout,
    )
    return ssh


# ── Platform Detection ──────────────────────────────────────────────

def detect_platform(version_output):
    if "cisco MDS" in version_output or re.search(r"\bMDS\s+\d", version_output):
        return "mds"
    if re.search(r"(?:cisco\s+)?Nexus\s*\d", version_output):
        return "nexus"
    if re.search(r"Cisco IOS .*Software", version_output):
        return "ios"
    if "iosxe" in version_output.lower():
        return "ios"
    if "cisco IOS-XE" in version_output:
        return "ios"
    return "mds"


PLATFORM_DISPLAY = {
    "mds":   "MDS NX-OS",
    "nexus": "Nexus NX-OS",
    "ios":   "IOS/IOS-XE",
}

PLATFORM_ICON = {
    "mds":   "bi-hdd-stack-fill",
    "nexus": "bi-server",
    "ios":   "bi-router",
}

# ── Command Sets ────────────────────────────────────────────────────

def _safe_exec(ssh, cmd, timeout=30):
    """Execute command; return empty string on failure (syntax/permission error, etc)."""
    try:
        out = _ssh_exec(ssh, cmd, timeout)
        errors = ["Syntax error", "Cmd exec error", "Invalid input",
                   "% Incomplete command", "% Access denied", "% unrecognized"]
        if any(e in out for e in errors):
            return ""
        return out
    except Exception:
        return ""


BASE_COMMANDS = {
    "mds": [
        ("version",       "show version", True),
        ("resources",     "show system resources", True),
        ("interfaces",    "show interface brief", True),
        ("vsan",          "show vsan", True),
        ("modules",       "show module", True),
        ("inventory",     "show inventory", True),
        ("syslogs",       "show log last 100", True),
        ("environment",   "show environment", True),
        ("portchannel",   "show port-channel summary", True),
        ("boot",          "show boot", False),
        ("bootflash",     "dir bootflash:", False),
        ("fcns",          "show fcns database", False),
        ("flogi",         "show flogi database", False),
        ("zoneset",       "show zoneset active", False),
        ("device_aliases","show device-alias database", False),
        ("port_security", "show port-security database", False),
        ("scsi_targets",  "show scsi-targets", False),
        ("accounting",    "show accounting log", False),
    ],
    "nexus": [
        ("version",       "show version", True),
        ("resources",     "show system resources", True),
        ("interfaces",    "show interface status", True),
        ("vlan",          "show vlan brief", True),
        ("modules",       "show module", True),
        ("inventory",     "show inventory", True),
        ("syslogs",       "show logging last 100", True),
        ("environment",   "show environment", True),
        ("portchannel",   "show port-channel summary", True),
        ("boot",          "show boot", False),
        ("bootflash",     "dir bootflash:", False),
        ("int_desc",      "show interface description", False),
    ],
    "ios": [
        ("version",       "show version", True),
        ("resources",     "show processes cpu | i CPU", True),
        ("memory",        "show memory statistics", True),
        ("interfaces",    "show interfaces status", True),
        ("vlan",          "show vlan brief", True),
        ("inventory",     "show inventory", True),
        ("syslogs",       "show log last 100", True),
        ("environment",   "show env all", True),
        ("portchannel",   "show etherchannel summary", True),
        ("bootflash",     "dir flash:", False),
        ("ip_int",        "show ip interface brief", False),
    ],
}


# ── Platform-agnostic parsers (work for MDS & Nexus NX-OS) ─────────

def _parse_version_nxos(output):
    data = {}
    m = re.search(r"kickstart:\s+version\s+(\S+)", output)
    if not m:
        m = re.search(r"system:\s+version\s+(\S+)", output)
    if not m:
        m = re.search(r"version\s+(\S+)", output)
    data["version"] = m.group(1) if m else "N/A"
    m = re.search(r"cisco\s+(\S+\s+\S+)", output)
    data["model"] = m.group(1) if m else "N/A"
    m = re.search(r"Device name:\s+(\S+)", output)
    data["hostname"] = m.group(1) if m else "N/A"
    m = re.search(r"Kernel uptime is\s+(.+)", output)
    data["uptime"] = m.group(1) if m else "N/A"
    m = re.search(r"BIOS:\s+version\s+(\S+)", output)
    data["bios"] = m.group(1) if m else "N/A"
    m = re.search(r"Processor Board ID\s+(\S+)", output)
    data["serial"] = m.group(1) if m else "N/A"
    return data


def _parse_version_ios(output):
    data = {}
    m = re.search(r"Version\s+(\S+)", output)
    data["version"] = m.group(1) if m else "N/A"
    m = re.search(r"cisco\s+(\S+(?:-\S+)?)\s+", output)
    data["model"] = m.group(1) if m else "N/A"
    m = re.search(r"uptime is\s+(.+)", output)
    data["uptime"] = m.group(1) if m else "N/A"
    m = re.search(r"System .+ hostname is\s+(\S+)", output)
    data["hostname"] = m.group(1) if m else "N/A"
    m = re.search(r"Processor board ID\s+(\S+)", output)
    data["serial"] = m.group(1) if m else "N/A"
    m = re.search(r"ROM:\s+(.+)", output)
    data["bios"] = m.group(1) if m else "N/A"
    return data


def _parse_system_resources_nxos(output):
    data = {}
    m = re.search(r"CPU states\s*:\s*([\d.]+)%\s+user.*?([\d.]+)%\s+kernel", output, re.DOTALL)
    if m:
        user = float(m.group(1))
        kernel = float(m.group(2))
        data["cpu_usage"] = round(user + kernel, 2)
    else:
        data["cpu_usage"] = "N/A"
    m = re.search(r"Memory usage:\s+(\d+)K total,\s+(\d+)K used", output)
    if m:
        data["memory_total_kb"] = int(m.group(1))
        data["memory_used_kb"] = int(m.group(2))
        data["memory_usage_pct"] = round(int(m.group(2)) / int(m.group(1)) * 100, 1)
    else:
        data["memory_total_kb"] = "N/A"
        data["memory_used_kb"] = "N/A"
        data["memory_usage_pct"] = "N/A"
    m = re.search(r"Load average:\s+1 minute:\s+([\d.]+)", output)
    data["load_1m"] = m.group(1) if m else "N/A"
    return data


def _parse_cpu_ios(output):
    data = {}
    m = re.search(r"CPU utilization for five seconds:\s*([\d.]+)%", output)
    if m:
        data["cpu_usage"] = float(m.group(1))
    else:
        m = re.search(r"CPU\s+(\d+)%", output)
        data["cpu_usage"] = float(m.group(1)) if m else "N/A"
    return data


def _parse_memory_ios(output):
    data = {}
    for line in output.splitlines():
        m = re.match(r"Processor\s+(\S+)", line)
        if m:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    total = int(parts[1])
                    used = int(parts[2])
                    data["memory_total_kb"] = total
                    data["memory_used_kb"] = used
                    data["memory_usage_pct"] = round(used / total * 100, 1) if total else 0
                except (ValueError, IndexError):
                    pass
        m = re.search(r"(\S+) total\S*,\s*(\S+) used", line)
        if m and "memory_total_kb" not in data:
            try:
                total = int(m.group(1))
                used = int(m.group(2))
                data["memory_total_kb"] = total
                data["memory_used_kb"] = used
                data["memory_usage_pct"] = round(used / total * 100, 1) if total else 0
            except ValueError:
                pass
    return data


def _parse_interfaces_brief_mds(output):
    interfaces = []
    hdr = False
    for line in output.splitlines():
        if not hdr:
            if "Interface" in line and ("Vsan" in line or "VSAN" in line):
                hdr = True
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        name = parts[0]
        if not name.startswith(("fc", "port", "mgmt", "Eth", "Po", "vfc", "sup")):
            continue
        interfaces.append({
            "name": name, "vsan": parts[1] if len(parts) > 1 else "",
            "admin_mode": parts[2] if len(parts) > 2 else "",
            "admin_trunk": parts[3] if len(parts) > 3 else "",
            "status": parts[4] if len(parts) > 4 else "",
            "sfp": parts[5] if len(parts) > 5 else "",
            "oper_mode": parts[6] if len(parts) > 6 else "",
            "oper_speed": parts[7] if len(parts) > 7 else "",
            "mode": parts[8] if len(parts) > 8 else "",
        })
    return interfaces


STATUS_WORDS = {"connected", "disabled", "notconect", "not-connected", "err-disabled", "suspended", "up", "down", "sfpAbsent"}

def _parse_interfaces_nxos(output):
    """Parse Nexus 'show interface status'.
    Columns: Port, Name, Status, Vlan, Duplex, Speed, Type
    """
    interfaces = []
    hdr = False
    for line in output.splitlines():
        if "Status" in line and "Vlan" in line and "Duplex" in line:
            hdr = True; continue
        if not hdr: continue
        stripped = line.strip()
        if not stripped or stripped.startswith("--"): continue
        parts = stripped.split()
        if len(parts) < 4: continue
        name = parts[0]
        if name.startswith("---"): continue
        status_idx = None
        for i, p in enumerate(parts):
            if p.lower() in STATUS_WORDS:
                status_idx = i; break
        if status_idx is None: continue
        desc_parts = [p for p in parts[1:status_idx] if p != "--"]
        desc = " ".join(desc_parts)
        status = parts[status_idx]
        if status.lower() == "connected": status = "up"
        elif status.lower() in ("disabled", "notconect", "not-connected"): status = "down"
        rem = parts[status_idx + 1:]
        vlan = rem[0] if rem else ""
        duplex = rem[1] if len(rem) > 1 else ""
        speed = rem[2] if len(rem) > 2 else ""
        typ = " ".join(rem[3:]) if len(rem) > 3 else ""
        interfaces.append({
            "name": name, "description": desc, "status": status,
            "vlan": vlan, "duplex": duplex, "speed": speed, "type": typ,
        })
    return interfaces


def _parse_interface_desc_nxos(output):
    descs = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and not parts[0].startswith("-") and parts[0] != "Interface":
            d = parts[1].strip()
            if d and d != "--":
                descs[parts[0]] = d
    return descs


def _parse_interfaces_ios(output):
    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and not parts[0].startswith("-") and not parts[0].startswith("Port"):
            iface = {"name": parts[0], "status": parts[1], "vlan": parts[2], "duplex": parts[3], "speed": parts[4], "type": parts[5] if len(parts) > 5 else ""}
            interfaces.append(iface)
    return interfaces


def _parse_vlan_nxos(output):
    vlans = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit():
            vlans.append({"id": parts[0], "name": parts[1], "status": parts[2], "ports": parts[3] if len(parts) > 3 else ""})
    return vlans


def _parse_vlan_ios(output):
    vlans = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit():
            vlans.append({"id": parts[0], "name": parts[1], "status": parts[3] if len(parts) > 3 else parts[2], "ports": " ".join(parts[4:]) if len(parts) > 4 else ""})
    return vlans


def _parse_modules_nxos(output):
    modules = []
    lines = output.splitlines()
    in_table = False
    for line in lines:
        if "Mod  Ports" in line and "Module-Type" in line:
            in_table = True
            continue
        if in_table:
            if line.startswith("---"):
                continue
            stripped = line.strip()
            if not stripped or not stripped[0].isdigit():
                in_table = False
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            modules.append({
                "mod": parts[0],
                "type": " ".join(parts[2:-2]),
                "model": parts[-2],
                "status": parts[-1].rstrip("* "),
            })
    return modules


def _parse_modules_ios(output):
    modules = []
    current = {}
    for line in output.splitlines():
        if line.startswith("NAME:"):
            if current:
                modules.append(current)
            current = {}
            m = re.search(r'"([^"]*)"', line)
            if m:
                current["name"] = m.group(1)
        elif line.startswith("PID:"):
            parts = line.split(",")
            for p in parts:
                kv = p.split(":", 1)
                k = kv[0].strip().lower()
                v = kv[1].strip().strip('"') if len(kv) > 1 else ""
                current[k] = v
    if current:
        modules.append(current)
    return modules


def _parse_env_nxos_common(output):
    env = {"power_supplies": [], "fans": [], "temperatures": [], "power_summary": {}}
    lines = output.splitlines()
    in_ps = False
    for line in lines:
        if "PS  Model" in line:
            in_ps = True; continue
        if in_ps:
            if line.startswith("-"): continue
            stripped = line.strip()
            if not stripped or stripped.startswith("("): continue
            if not stripped[0].isdigit():
                in_ps = False; continue
            parts = stripped.split()
            if len(parts) >= 4:
                env["power_supplies"].append({"ps": parts[0], "model": parts[1], "watts": parts[2], "amp": parts[3], "status": parts[4] if len(parts) > 4 else ""})
    in_fan = False
    for line in lines:
        if "Fan             Model" in line:
            in_fan = True; continue
        if in_fan:
            if "Fan Air Filter" in line: break
            stripped = line.strip()
            if not stripped or stripped.startswith("-"): continue
            m = re.match(r"(Fan_in_PS\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+(?:\s+\S+)*)", stripped)
            if m:
                env["fans"].append({"name": m.group(1), "model": m.group(2), "hw": m.group(3), "status": m.group(4), "airflow": m.group(5), "speed_rpm": "--"})
                continue
            m = re.match(r"(ChassisFan\d)\s+(.+?)\s+(\S+)\s+(\S+)\s+(Front to Back|Back to Front)\s+(.+)", stripped)
            if m:
                env["fans"].append({"name": m.group(1), "model": m.group(2).strip(), "hw": m.group(3), "status": m.group(4), "airflow": m.group(5), "speed_rpm": m.group(6).strip()})
    in_temp = False
    for line in lines:
        if "Module   Sensor" in line:
            in_temp = True; continue
        if in_temp:
            if line.startswith("-"): continue
            if not line.strip():
                in_temp = False; continue
            parts = line.split()
            if len(parts) >= 7 and parts[0].isdigit():
                env["temperatures"].append({"module": parts[0], "sensor": parts[1] + " " + parts[2].strip("()"), "major_thresh": parts[3], "minor_thresh": parts[4], "current_temp": parts[5], "status": parts[6]})
    for line in lines:
        m = re.match(r"Total Power Capacity\s+([\d.]+)\s*W", line)
        if m: env["power_summary"]["capacity_w"] = m.group(1)
        m = re.match(r"Total Power Allocated \(budget\)\s+([\d.]+)\s*W", line)
        if m: env["power_summary"]["allocated_w"] = m.group(1)
        m = re.match(r"Total Power Available\s+([\d.]+)\s*W", line)
        if m: env["power_summary"]["available_w"] = m.group(1)
        m = re.search(r"Power Supply redundancy mode:\s+(\S+)", line)
        if m: env["power_summary"]["redundancy_mode"] = m.group(1)
    return env


def _parse_env_ios(output):
    env = {"power_supplies": [], "fans": [], "temperatures": []}
    for line in output.splitlines():
        stripped = line.strip()
        m = re.search(r"SW\s+(\d+)\s+(\S+)", stripped)
        if m and "OK" in stripped:
            env["power_supplies"].append({"ps": m.group(1), "status": m.group(2)})
        m = re.search(r"Fan\s+(\d+)\s+(\S+)", stripped)
        if m and ("OK" in stripped or "FAN" in stripped):
            env["fans"].append({"name": m.group(0).split()[0], "status": m.group(2)})
        m = re.search(r"Temperature\s+(\S+)", stripped)
        if m:
            status = m.group(1)
            value_m = re.search(r"(\d+)\s+C", stripped)
            env["temperatures"].append({"sensor": stripped.split()[0] if stripped else "", "current_temp": value_m.group(1) if value_m else "", "status": status})
    return env


def _parse_inventory_common(output):
    inventory = []
    current = {}
    for line in output.splitlines():
        if line.startswith("NAME:"):
            if current: inventory.append(current)
            current = {}
            m = re.search(r'"([^"]*)"', line)
            if m: current["name"] = m.group(1)
        elif line.startswith("PID:"):
            parts = line.split(",")
            for p in parts:
                kv = p.split(":", 1)
                k = kv[0].strip().lower()
                v = kv[1].strip().strip('"') if len(kv) > 1 else ""
                current[k] = v
    if current: inventory.append(current)
    return inventory


def _parse_syslogs_common(output):
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line: continue
        m = re.match(r"(\d{4}\s+\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+%(\S+)-(\d+)-(\S+):\s*(.+)", line)
        if m:
            entries.append({"timestamp": m.group(1), "host": m.group(2), "facility": m.group(3), "severity": m.group(4), "mnemonic": m.group(5), "message": m.group(6)})
        else:
            entries.append({"timestamp": "", "host": "", "facility": "", "severity": "", "mnemonic": "", "message": line})
    return entries


def _parse_portchannel_nxos(output):
    channels = []
    lines = output.splitlines()
    in_table = False
    for line in lines:
        # Format 1: "Interface" + "Total Ports" (older NX-OS / MDS)
        if "Interface" in line and "Total Ports" in line:
            in_table = True; continue
        if in_table:
            if line.startswith("-"): continue
            if not line.strip(): continue
            parts = line.split()
            if len(parts) >= 4 and parts[0].lower().startswith("port-channel"):
                channels.append({"interface": parts[0], "total_ports": parts[1], "oper_ports": parts[2], "first_oper_port": parts[3] if len(parts) > 3 else ""})
                continue
            if parts[0].isdigit() and parts[0] not in ("1",):
                in_table = False; continue
    if channels: return channels
    # Format 2: "Group" + "Ports" (newer NX-OS)
    for line in lines:
        if "Group" in line and "Ports" in line and "Protocol" in line:
            for l in lines[lines.index(line) + 1:]:
                if l.startswith("-"): continue
                if not l.strip(): continue
                parts = l.split()
                if len(parts) >= 5 and parts[0].isdigit():
                    members = " ".join(parts[4:])
                    channels.append({"interface": "port-channel" + parts[0], "total_ports": parts[1], "oper_ports": "", "first_oper_port": members})
            return channels
    # Fallback: any line starting with "port-channel"
    for line in lines:
        parts = line.split()
        if parts and parts[0].lower().startswith("port-channel"):
            channels.append({"interface": parts[0], "total_ports": "", "oper_ports": "", "first_oper_port": " ".join(parts[1:]) if len(parts) > 1 else ""})
    return channels


def _parse_etherchannel_ios(output):
    channels = []
    for line in output.splitlines():
        parts = line.split()
        if not parts: continue
        if (len(parts) >= 3 and parts[0].startswith("Po")) or parts[0].startswith("Port-channel"):
            channels.append({"interface": parts[0], "total_ports": "", "oper_ports": "", "first_oper_port": " ".join(parts[1:]) if len(parts) > 1 else ""})
    return channels


def _parse_boot_nxos(output):
    data = {"current": {}, "next_reload": {}}
    section = None
    for line in output.splitlines():
        if "Current Boot Variables" in line: section = "current"; continue
        if "Boot Variables on next reload" in line: section = "next_reload"; continue
        if section:
            m = re.match(r"(\w+(?:\s+\w+)?)\s*=\s*(.+)", line)
            if m:
                key = m.group(1).strip().lower().replace(" ", "_")
                data[section][key] = m.group(2).strip()
            elif "Boot POAP" in line:
                data[section]["boot_poap"] = line.split("Boot POAP")[1].strip()
            elif "No module boot variable" in line:
                data[section]["module_boot"] = "not set"
    return data


def _parse_bootflash(output):
    files = []
    usage = {}
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^\d+\s+\w+", stripped) and any(m in stripped for m in ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]):
            parts = stripped.split(None, 5)
            if len(parts) >= 6 and parts[0].isdigit():
                files.append({"size": int(parts[0]), "date": parts[1] + " " + parts[2], "time": parts[3], "year": parts[4], "name": parts[5]})
        m = re.search(r"(\d+)\s+bytes\s+(used|free|total)", line)
        if m: usage[m.group(2)] = int(m.group(1))
    return {"files": files, "usage": usage}


# ── FC-specific parsers (MDS only) ─────────────────────────────────

def _parse_vsan(output):
    vsans = []
    for line in output.splitlines():
        m = re.match(r"vsan\s+(\d+)\s+information", line)
        if m:
            vsans.append({"id": m.group(1), "name": "", "state": ""})
        else:
            m = re.match(r"\s+name:(\S+)\s+state:(\S+)", line)
            if m and vsans:
                vsans[-1]["name"] = m.group(1)
                vsans[-1]["state"] = m.group(2)
    return vsans


def _parse_fcns(output):
    entries = []
    current_vsan = None
    for line in output.splitlines():
        m = re.match(r"VSAN\s+(\d+):", line)
        if m:
            current_vsan = m.group(1); continue
        parts = line.split()
        if len(parts) >= 4 and parts[0].startswith("0x"):
            entries.append({"vsan": current_vsan, "fcid": parts[0], "type": parts[1], "pwwn": parts[2], "vendor": parts[3].strip("()") if len(parts) > 3 else "", "fc4_features": " ".join(parts[4:]) if len(parts) > 4 else ""})
    return entries


def _parse_flogi(output):
    entries = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].startswith("fc"):
            entries.append({"interface": parts[0], "vsan": parts[1], "fcid": parts[2], "port_name": parts[3], "node_name": parts[4] if len(parts) > 4 else ""})
    return entries


def _parse_zoneset(output):
    zonesets = []
    current_zs = None
    for line in output.splitlines():
        m = re.match(r"zoneset name (\S+) vsan (\d+)", line)
        if m:
            current_zs = {"name": m.group(1), "vsan": m.group(2), "zones": []}
            zonesets.append(current_zs); continue
        m = re.match(r"\s+zone name (\S+) vsan (\d+)", line)
        if m and current_zs is not None:
            current_zs["zones"].append({"name": m.group(1), "vsan": m.group(2), "members": []}); continue
        m = re.match(r"\s+\*\s*fcid (\S+) \[pwwn (\S+)\]", line)
        if m and current_zs is not None and current_zs["zones"]:
            current_zs["zones"][-1]["members"].append({"fcid": m.group(1), "pwwn": m.group(2)})
    return zonesets


def _parse_device_aliases(output):
    if "no entries" in output.lower(): return []
    aliases = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not line.startswith("device-alias") and not line.startswith("-"):
            aliases.append({"name": parts[0], "pwwn": parts[1] if len(parts) > 1 else ""})
    return aliases


def _parse_port_security(output):
    if "Syntax error" in output or "Cmd exec error" in output: return []
    entries = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            entries.append({"interface": parts[0], "vsan": parts[1], "pwwn": parts[2]})
    return entries


def _parse_scsi_targets(output):
    if "Syntax error" in output or "Cmd exec error" in output: return []
    entries = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and "vsan" in line.lower():
            entries.append({"target": parts[0], "vsan": parts[1]})
    return entries


def _parse_accounting(output):
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line: continue
        m = re.match(r"(\w+\s+\w+\s+\d+\s+[\d:]+)\s+\d+:(type=\w+):(id=\S+):(user=\S+):cmd=(.+)", line)
        if m:
            entries.append({"timestamp": m.group(1), "type": m.group(2).split("=")[1], "id": m.group(3).split("=")[1], "user": m.group(4).split("=")[1], "command": m.group(5)})
        else:
            m2 = re.match(r"(\w+\s+\w+\s+\d+\s+[\d:]+)\s+(\d+):type=(\w+):id=(\S+):user=(\S+):cmd=(.+)", line)
            if m2:
                entries.append({"timestamp": m2.group(1), "type": m2.group(3), "id": m2.group(4), "user": m2.group(5), "command": m2.group(6)})
    return entries


# ── Per-platform collect dispatcher ─────────────────────────────────

def _safe_parse(parser, raw, default):
    try:
        return parser(raw)
    except Exception as e:
        logging.warning("parser %s failed: %s", parser.__name__, e)
        return default

def _collect_mds(ssh):
    raw = {}
    for key, cmd, _ in BASE_COMMANDS["mds"]:
        raw[key] = _safe_exec(ssh, cmd)
    return {
        "platform": "mds",
        "version_info": _safe_parse(_parse_version_nxos, raw["version"], {}),
        "resource": _safe_parse(_parse_system_resources_nxos, raw["resources"], {}),
        "interfaces": _safe_parse(_parse_interfaces_brief_mds, raw["interfaces"], []),
        "vsans": _safe_parse(_parse_vsan, raw["vsan"], []),
        "modules": _safe_parse(_parse_modules_nxos, raw["modules"], []),
        "inventory": _safe_parse(_parse_inventory_common, raw["inventory"], []),
        "flogi": _safe_parse(_parse_flogi, raw["flogi"], []),
        "fcns": _safe_parse(_parse_fcns, raw["fcns"], []),
        "syslogs": _safe_parse(_parse_syslogs_common, raw["syslogs"], []),
        "zoneset": _safe_parse(_parse_zoneset, raw["zoneset"], []),
        "environment": _safe_parse(_parse_env_nxos_common, raw["environment"], {"power_supplies": [], "fans": [], "temperatures": [], "power_summary": {}}),
        "portchannels": _safe_parse(_parse_portchannel_nxos, raw["portchannel"], []),
        "device_aliases": _safe_parse(_parse_device_aliases, raw["device_aliases"], []),
        "port_security": _safe_parse(_parse_port_security, raw["port_security"], []),
        "scsi_targets": _safe_parse(_parse_scsi_targets, raw["scsi_targets"], []),
        "accounting": _safe_parse(_parse_accounting, raw["accounting"], []),
        "boot": _safe_parse(_parse_boot_nxos, raw["boot"], {"current": {}, "next_reload": {}}),
        "bootflash": _safe_parse(_parse_bootflash, raw["bootflash"], {"files": [], "usage": {}}),
    }


def _collect_nexus(ssh):
    raw = {}
    for key, cmd, _ in BASE_COMMANDS["nexus"]:
        raw[key] = _safe_exec(ssh, cmd)
    interfaces = _safe_parse(_parse_interfaces_nxos, raw["interfaces"], [])
    descs = _safe_parse(_parse_interface_desc_nxos, raw["int_desc"], {})
    if descs:
        for iface in interfaces:
            n = iface.get("name", "")
            if n in descs:
                iface["description"] = descs[n]
    return {
        "platform": "nexus",
        "version_info": _safe_parse(_parse_version_nxos, raw["version"], {}),
        "resource": _safe_parse(_parse_system_resources_nxos, raw["resources"], {}),
        "interfaces": interfaces,
        "vlans": _safe_parse(_parse_vlan_nxos, raw["vlan"], []),
        "modules": _safe_parse(_parse_modules_nxos, raw["modules"], []),
        "inventory": _safe_parse(_parse_inventory_common, raw["inventory"], []),
        "syslogs": _safe_parse(_parse_syslogs_common, raw["syslogs"], []),
        "environment": _safe_parse(_parse_env_nxos_common, raw["environment"], {"power_supplies": [], "fans": [], "temperatures": [], "power_summary": {}}),
        "portchannels": _safe_parse(_parse_portchannel_nxos, raw["portchannel"], []),
        "boot": _safe_parse(_parse_boot_nxos, raw["boot"], {"current": {}, "next_reload": {}}),
        "bootflash": _safe_parse(_parse_bootflash, raw["bootflash"], {"files": [], "usage": {}}),
    }


def _collect_ios(ssh):
    raw = {}
    for key, cmd, _ in BASE_COMMANDS["ios"]:
        raw[key] = _safe_exec(ssh, cmd)
    cpu_data = _safe_parse(_parse_cpu_ios, raw["resources"], {})
    mem_data = _safe_parse(_parse_memory_ios, raw["memory"], {})
    resource = {}
    resource["cpu_usage"] = cpu_data.get("cpu_usage", "N/A")
    resource["memory_total_kb"] = mem_data.get("memory_total_kb", "N/A")
    resource["memory_used_kb"] = mem_data.get("memory_used_kb", "N/A")
    resource["memory_usage_pct"] = mem_data.get("memory_usage_pct", "N/A")
    resource["load_1m"] = "N/A"
    return {
        "platform": "ios",
        "version_info": _safe_parse(_parse_version_ios, raw["version"], {}),
        "resource": resource,
        "interfaces": _safe_parse(_parse_interfaces_ios, raw["interfaces"], []),
        "vlans": _safe_parse(_parse_vlan_ios, raw["vlan"], []),
        "inventory": _safe_parse(_parse_inventory_common, raw["inventory"], []),
        "syslogs": _safe_parse(_parse_syslogs_common, raw["syslogs"], []),
        "environment": _safe_parse(_parse_env_ios, raw["environment"], {"power_supplies": [], "fans": [], "temperatures": []}),
        "portchannels": _safe_parse(_parse_etherchannel_ios, raw["portchannel"], []),
        "bootflash": _safe_parse(_parse_bootflash, raw["bootflash"], {"files": [], "usage": {}}),
    }


PLATFORM_COLLECTORS = {
    "mds":   _collect_mds,
    "nexus": _collect_nexus,
    "ios":   _collect_ios,
}


def collect_switch(host, username, password, port=22):
    try:
        ssh = _build_ssh(host, username, password, port)
        try:
            version_raw = _ssh_exec(ssh, "show version")
            platform = detect_platform(version_raw)
            collector = PLATFORM_COLLECTORS.get(platform, _collect_mds)
            data = collector(ssh)
            data["host"] = host
            data["reachable"] = True
        finally:
            ssh.close()
        return data
    except Exception as e:
        err_msg = str(e)
        if "timed out" in err_msg.lower():
            err_msg = f"Connection timed out — unable to reach {host}:{port}"
        elif "Authentication" in err_msg:
            err_msg = f"Authentication failed — check username/password for {host}"
        return {"host": host, "reachable": False, "error": err_msg}


def collect_all(switches, max_workers=5):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(collect_switch, **sw): ip for ip, sw in switches.items()}
        for f in as_completed(futures):
            res = f.result()
            results[res["host"]] = res
    return results
