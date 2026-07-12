import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mds_collector import _build_ssh

host, username, password = "10.14.0.248", "kiranch", "kiran.kumar1"
ssh = _build_ssh(host, username, password, 22)

commands = [
    "show zoneset active",
    "show environment",
    "show port-channel summary",
    "show device-alias database",
    "show port-security database",
    "show scsi-targets",
    "show accounting log",
]
for cmd in commands:
    print(f"\n{'='*60}\n$ {cmd}\n{'='*60}")
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
    out = stdout.read().decode()
    err = stderr.read().decode()
    print(out if out.strip() else "(no output)")
    if err.strip():
        print(f"[STDERR] {err}")

ssh.close()
