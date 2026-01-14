import os
import stat
import subprocess


def gather_info(service="apache2"):
    fs_state = os.stat("/")
    file_permissions = oct(stat.S_IMODE(fs_state.st_mode))
    config_files = {
        "ssh": {
            "path": "/etc/ssh/sshd_config",
            "exists": None,
            "readable": None,
            "settings_observed": {},
        },
        "firewall": {
            "path": None,
            "exists": None,
            "readable": None,
            "settings_observed": {},
        },
        "auth": {
            "path": None,
            "exists": None,
            "readable": None,
            "settings_observed": {},
        },
    }
    proc = subprocess.run(
        ["systemctl", "is-active", service], capture_output=True, text=True
    )

    service_status = proc.stdout.strip() or "not_installed"

    risky = bool(os.stat("/etc/sudoers").st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ssh_listening = subprocess.check_output(["ss", "-tuln"], text=True)

    ssh_public = "0.0.0.0:22" in ssh_listening or "[::]:22" in ssh_listening

    firewall_active = (
        subprocess.run(
            ["ufw", "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode
        == 0
    )

    return {
        "filesystem": {
            "path": "/",
            "permissions": file_permissions,
            "risk": file_permissions != "0o755",
        },
        "service": {
            "name": service,
            "status": service_status,
            "risk": service_status == "active",
        },
        "network": {
            "ssh_running": "sshd" in ssh_listening,
            "ssh_public": ssh_public,
            "firewall_present": firewall_active,
            "risk": ssh_public and not firewall_active,
        },
        "config_files": config_files,
    }
