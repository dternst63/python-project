import os
import stat
import subprocess
from typing import Dict


def _safe_run(cmd: list) -> str:
    """Run a command safely and return stdout or empty string."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        return ""


def gather_info(service: str = "apache2") -> Dict:
    # Filesystem check
    try:
        fs_state = os.stat("/")
        file_permissions = oct(stat.S_IMODE(fs_state.st_mode))
    except OSError:
        file_permissions = "unknown"

    # Service status (systemd-based systems)
    service_status = _safe_run(["systemctl", "is-active", service]) or "unknown"

    # SSH exposure
    ssh_listening = _safe_run(["ss", "-tuln"])
    ssh_public = "0.0.0.0:22" in ssh_listening or "[::]:22" in ssh_listening

    # Firewall detection (ufw is Debian/Ubuntu specific)
    firewall_active = bool(_safe_run(["ufw", "status"]))

    return {
        "filesystem": {
            "path": "/",
            "permissions": file_permissions,
            "risk": file_permissions not in ("0o755", "unknown"),
        },
        "service": {
            "name": service,
            "status": service_status,
            "risk": service_status == "active",
            "note": "Service risk is policy-based and context-dependent",
        },
        "network": {
            "ssh_public": ssh_public,
            "firewall_present": firewall_active,
            "risk": ssh_public and not firewall_active,
        },
        "metadata": {
            "probe_type": "read_only",
            "assumptions": [
                "systemd-based OS",
                "Linux host",
            ],
        },
    }
