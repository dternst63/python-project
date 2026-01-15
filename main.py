import json
import argparse
from analysis import read_last_two_records, analyze_risk_changes


def main():
    parser = argparse.ArgumentParser(description="Hardening risk change analysis")
    parser.add_argument(
        "--log-path",
        default="logs/example_output.log",
        help="Path to JSONL hardening log file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    args = parser.parse_args()

    previous, current = read_last_two_records(args.log_path)
    findings = analyze_risk_changes(previous, current)

    for finding in findings:
        print(json.dumps(finding, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
