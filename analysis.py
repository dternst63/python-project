import json
import os
from datetime import datetime, timezone
from typing import Tuple, List, Dict, Optional


def read_last_two_records(log_path: str) -> Tuple[Optional[dict], Optional[dict]]:
    """
    Reads the last two valid JSON records from a JSONL log file.
    Skips malformed lines.
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


def analyze_risk_changes(
    previous: Optional[dict], current: Optional[dict]
) -> List[Dict]:
    """
    Compares risk fields between two records and emits findings.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    findings = []

    if not previous or not current:
        return [
            {
                "timestamp": timestamp,
                "finding": "insufficient_data",
                "severity": "info",
                "details": "Not enough history to analyze changes",
            }
        ]

    categories = ["filesystem", "service", "network"]

    for category in categories:
        prev_risk = previous.get(category, {}).get("risk")
        curr_risk = current.get(category, {}).get("risk")

        if prev_risk is None or curr_risk is None:
            continue

        if prev_risk != curr_risk:
            findings.append(
                {
                    "timestamp": timestamp,
                    "category": category,
                    "previous_risk": prev_risk,
                    "current_risk": curr_risk,
                    "severity": "high" if curr_risk else "info",
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
                "timestamp": timestamp,
                "finding": "no_change",
                "severity": "info",
                "details": "No risk state changes detected",
            }
        )

    return findings
