# logger.py — Event Logger & reporter.py — Audit Report Generator
#
# logger.py  : Writes file transfer events to text and JSON log files.
# reporter.py: Reads logs and generates the final audit report.
#
# These are combined in one file for simplicity.
# In the repo they are saved as separate files.

# ════════════════════════════════════════════════════════════════════
# logger.py
# ════════════════════════════════════════════════════════════════════

import json
import os
import datetime

LOG_FILE      = "file_transfer.log"
JSON_LOG_FILE = "file_transfer_events.json"


def log_event(record: dict):
    """
    Write a file transfer event to both log files.

    record keys expected:
        timestamp, event_type, src_path, dest_path,
        file_hash, classification, sensitive, alert, alert_reason
    """
    # ── Human-readable log ────────────────────────────────────────
    line = (
        f"[{record['timestamp']}] [{record['event_type']:<8}] "
        f"[{record['classification']:<9}] "
        f"{'[ALERT]' if record['alert'] else '[OK]   '} "
        f"SRC={record['src_path']} "
        f"DEST={record['dest_path']} "
        f"HASH={record['file_hash']}"
    )
    if record.get("alert_reason"):
        line += f" REASON={record['alert_reason']}"

    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

    # ── Structured JSON log ───────────────────────────────────────
    events = []
    if os.path.exists(JSON_LOG_FILE):
        try:
            with open(JSON_LOG_FILE, "r") as f:
                events = json.load(f)
        except json.JSONDecodeError:
            events = []

    events.append(record)
    with open(JSON_LOG_FILE, "w") as f:
        json.dump(events, f, indent=2)


def read_log(filter_alert: bool = False) -> list:
    """Read log lines, optionally filtered to alert-only entries."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    if filter_alert:
        lines = [l for l in lines if "[ALERT]" in l]
    return lines


def read_json_log() -> list:
    """Return all events from the JSON log."""
    if not os.path.exists(JSON_LOG_FILE):
        return []
    try:
        with open(JSON_LOG_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def get_summary() -> dict:
    """Compute summary statistics from the JSON log."""
    events = read_json_log()
    alerts = [e for e in events if e.get("alert")]
    by_type = {}
    for e in events:
        t = e.get("event_type", "UNKNOWN")
        by_type[t] = by_type.get(t, 0) + 1

    sensitive = [e for e in events if e.get("sensitive")]
    return {
        "total":         len(events),
        "alerts":        len(alerts),
        "sensitive":     len(sensitive),
        "by_event_type": by_type,
        "alert_events":  alerts,
    }
