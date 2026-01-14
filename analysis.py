import json
from datetime import datetime, timezone


LOG_PATH = "hardening_extract.log"


def read_last_two_records(log_path):
    """
    Reads the last two valid JSON records from a JSONL log file.
    Skips malformed lines.
    Efficient for large files.
    """
    last = None
    second_last = None

    with open(log_path, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
                second_last = last
                last = record
            except json.JSONDecodeError:
                continue

    return second_last, last


def analyze_risk_changes(previous, current):
    """
    Compares risk fields between two records and emits findings.
    """
    findings = []

    if previous is None or current is None:
        return [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "finding": "insufficient_data",
                "severity": "info",
                "details": "Not enough history to analyze changes",
            }
        ]

    categories = ["filesystem", "service", "network"]

    for category in categories:
        prev_risk = previous[category]["risk"]
        curr_risk = current[category]["risk"]

        if prev_risk != curr_risk:
            findings.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "category": category,
                    "previous_risk": prev_risk,
                    "current_risk": curr_risk,
                    "severity": ("high" if curr_risk else "info"),
                    "finding": (
                        f"{category}_risk_introduced"
                        if curr_risk
                        else f"{category}_risk_resolved"
                    ),
                }
            )

    if not findings:
        findings.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "finding": "no_change",
                "severity": "info",
                "details": "No risk state changes detected",
            }
        )

    return findings


def run_analysis():
    previous, current = read_last_two_records(LOG_PATH)
    findings = analyze_risk_changes(previous, current)

    for finding in findings:
        print(json.dumps(finding, indent=2))


if __name__ == "__main__":
    run_analysis()
