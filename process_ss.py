import json
import socket
from datetime import datetime, timezone
from typing import Dict, Optional

from gather_info import gather_info


def process_ss(log_path: str = "logs/hardening_extract.log") -> Optional[Dict]:
    """
    Collects system state and appends a JSONL record to the log file.
    Returns the record for further processing if needed.
    """
    result = gather_info()

    log_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "filesystem": result.get("filesystem"),
        "service": result.get("service"),
        "network": result.get("network"),
    }

    try:
        with open(log_path, "a") as log_file:
            log_file.write(json.dumps(log_record) + "\n")
    except OSError as exc:
        # Fail safely; logging errors should not crash the probe
        return None

    return log_record


if __name__ == "__main__":
    process_ss()
