Hardening Probe
===============

A lightweight, read-only Linux system hardening probe that captures
system state snapshots and performs change-based security analysis
over time.

Designed for use on Linux virtual machines, including AWS EC2 instances.

--------------------------------------------------
Overview
--------------------------------------------------

Hardening Probe inspects key aspects of a Linux system’s security posture,
including:

- Filesystem permissions
- Service exposure
- Network accessibility (SSH, firewall presence)
- Historical risk changes between runs

The tool is intentionally non-invasive:
- It does NOT modify system state
- It does NOT enforce policy
- It collects data for auditing and analysis purposes only

--------------------------------------------------
Project Structure
--------------------------------------------------

.
├── analysis.py        # Change-based risk analysis
├── gather_info.py     # Read-only system inspection
├── process_ss.py      # Snapshot persistence (JSONL logging)
├── main.py            # Single entry point
├── logs/
│   └── example_output.log
├── requirements.txt
├── README.txt
└── .gitignore

--------------------------------------------------
How It Works
--------------------------------------------------

1. gather_info.py
   Collects current system state using OS-level inspection.
   No configuration or system changes are performed.

2. process_ss.py
   Writes a JSON record (one per run) to a JSONL log file,
   including timestamp and hostname.

3. analysis.py
   Reads the last two log entries and analyzes changes in
   risk state between runs.

4. main.py
   Orchestrates snapshot logging and risk change analysis.

--------------------------------------------------
Usage
--------------------------------------------------

Run the probe:

    python main.py

Typical use cases:
- Scheduled execution via cron or systemd
- Execution via AWS SSM Run Command
- Manual auditing during security reviews

--------------------------------------------------
Output
--------------------------------------------------

Snapshot logs are written in JSON Lines (JSONL) format:

Each line represents a single system snapshot, enabling:
- Efficient log parsing
- Historical comparison
- Integration with external tooling

Example (sanitized):

{
  "timestamp": "2026-01-14T21:33:01Z",
  "host": "example-host",
  "filesystem": { ... },
  "service": { ... },
  "network": { ... }
}

--------------------------------------------------
Design Notes
--------------------------------------------------

- Read-only inspection only
- Fail-safe subprocess execution
- UTC timestamps for fleet compatibility
- Minimal dependencies (standard library only)
- Designed to degrade gracefully on different Linux distributions

--------------------------------------------------
AWS Compatibility
--------------------------------------------------

Supported:
- AWS EC2 (Amazon Linux, Ubuntu)
- SSM Run Command
- Cron or systemd scheduling

Not intended for:
- AWS Lambda (requires OS-level access)

--------------------------------------------------
Security Disclaimer
--------------------------------------------------

This tool is provided for inspection and educational purposes.
Review all code before running on production systems.

--------------------------------------------------
License
--------------------------------------------------

MIT License

Copyright (c) 2026 Dan Ernst

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

This software is provided "as is", without warranty of any kind.