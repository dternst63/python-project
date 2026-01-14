import json
import socket
from datetime import datetime, timezone

from gather_info import gather_info


def process_ss():
    result = gather_info()

    log_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "filesystem": result["filesystem"],
        "service": result["service"],
        "network": result["network"],
    }

    with open("hardening_extract.log", "a") as log_file:
        log_file.write(json.dumps(log_record) + "\n")


if __name__ == "__main__":
    process_ss()
