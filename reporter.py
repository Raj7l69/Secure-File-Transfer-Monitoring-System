# reporter.py — Audit Log & Final Report Generator
#
# Reads all logged file transfer events and produces:
#   1. A console audit summary
#   2. A detailed final report saved to file_transfer_report.txt
#
# Usage:
#   python reporter.py

import datetime
import os
from logger import get_summary, read_log, read_json_log, LOG_FILE, JSON_LOG_FILE
from integrity import load_baseline, verify_integrity, print_violations

REPORT_FILE  = "file_transfer_report.txt"
MONITOR_DIR  = "./monitored_folder"

# ─── DASHBOARD ────────────────────────────────────────────────────────────────

def print_dashboard():
    """Print a terminal summary of all file transfer activity."""
    summary = get_summary()
    now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 65)
    print("  SECURE FILE TRANSFER MONITOR — AUDIT DASHBOARD")
    print(f"  Generated : {now}")
    print("=" * 65)

    if summary["total"] == 0:
        print("\n  [!] No events logged. Run monitor.py first.\n")
        print("=" * 65)
        return

    alert_rate = round((summary["alerts"] / summary["total"]) * 100, 1)

    print(f"\n  FILE ACTIVITY OVERVIEW")
    print(f"  {'─'*45}")
    print(f"  Total Events     : {summary['total']}")
    print(f"  Alerts Generated : {summary['alerts']}  ({alert_rate}%)")
    print(f"  Sensitive Files  : {summary['sensitive']}")

    print(f"\n  EVENTS BY TYPE")
    print(f"  {'─'*45}")
    for evt_type, count in sorted(
            summary["by_event_type"].items(), key=lambda x: x[1], reverse=True):
        bar = "█" * min(count, 30)
        print(f"  {evt_type:<12} {count:>4}  {bar}")

    if summary["alert_events"]:
        print(f"\n  RECENT ALERTS (last 5)")
        print(f"  {'─'*45}")
        for e in summary["alert_events"][-5:]:
            print(f"  [{e['timestamp']}] {e['event_type']:<8} "
                  f"{os.path.basename(e['src_path'])}")
            print(f"    → {e.get('alert_reason', 'Suspicious activity')}")

    print("\n" + "=" * 65)


# ─── REPORT GENERATOR ─────────────────────────────────────────────────────────

def generate_report():
    """Build and save the final audit report."""
    summary    = get_summary()
    now        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines      = []

    lines.append("=" * 70)
    lines.append("  SECURE FILE TRANSFER MONITORING SYSTEM")
    lines.append("  FINAL AUDIT REPORT")
    lines.append("=" * 70)
    lines.append(f"  Report Generated : {now}")
    lines.append(f"  Log File         : {LOG_FILE}")
    lines.append(f"  JSON Log         : {JSON_LOG_FILE}")
    lines.append("=" * 70)

    if summary["total"] == 0:
        lines.append("\n  No events to report. Run monitor.py first.")
    else:
        alert_rate = round((summary["alerts"] / summary["total"]) * 100, 1)

        # ── Overview ──────────────────────────────────────────────────────
        lines.append("\n[FILE ACTIVITY SUMMARY]")
        lines.append("-" * 55)
        lines.append(f"  Total Events     : {summary['total']}")
        lines.append(f"  Alerts Generated : {summary['alerts']}  ({alert_rate}%)")
        lines.append(f"  Sensitive Files  : {summary['sensitive']}")

        # ── Event type breakdown ──────────────────────────────────────────
        lines.append("\n[EVENTS BY TYPE]")
        lines.append("-" * 55)
        lines.append(f"  {'EVENT TYPE':<15} {'COUNT':>6}")
        lines.append(f"  {'─'*15} {'─'*6}")
        for evt_type, count in sorted(
                summary["by_event_type"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {evt_type:<15} {count:>6}")

        # ── All alert events ──────────────────────────────────────────────
        if summary["alert_events"]:
            lines.append("\n[ALERT EVENTS — FULL LIST]")
            lines.append("-" * 55)
            for e in summary["alert_events"]:
                lines.append(f"  [{e['timestamp']}]")
                lines.append(f"    Event    : {e['event_type']}")
                lines.append(f"    File     : {e['src_path']}")
                lines.append(f"    Dest     : {e['dest_path']}")
                lines.append(f"    Hash     : {e['file_hash']}")
                lines.append(f"    Reason   : {e.get('alert_reason', '—')}")
                lines.append("")

        # ── Integrity check results ───────────────────────────────────────
        lines.append("\n[INTEGRITY CHECK RESULTS]")
        lines.append("-" * 55)
        if os.path.exists(MONITOR_DIR):
            violations = verify_integrity(MONITOR_DIR)
            if not violations:
                lines.append("  [+] All files match baseline — no integrity violations.")
            else:
                lines.append(f"  [!] {len(violations)} violation(s) detected:")
                for v in violations:
                    lines.append(f"\n  [{v['type']}] {v['file']}")
                    if v["type"] == "MODIFIED":
                        lines.append(f"    Baseline : {v['baseline_hash']}")
                        lines.append(f"    Current  : {v['current_hash']}")
                    elif v["type"] == "NEW":
                        lines.append(f"    Hash     : {v['current_hash']}")
        else:
            lines.append("  [!] Monitored folder not found — skipping integrity check.")

        # ── Security recommendations ──────────────────────────────────────
        lines.append("\n[SECURITY RECOMMENDATIONS]")
        lines.append("-" * 55)
        recs = [
            "Restrict write access to sensitive directories using OS-level permissions.",
            "Implement DLP (Data Loss Prevention) policies to block transfers to USB/cloud.",
            "Schedule integrity checks automatically using cron (Linux) or Task Scheduler (Windows).",
            "Correlate file transfer alerts with user login events for insider threat detection.",
            "Encrypt sensitive files at rest to reduce impact of unauthorized access.",
            "Expand sensitive filename patterns to include project-specific naming conventions.",
        ]
        for rec in recs:
            lines.append(f"  • {rec}")

    lines.append("\n" + "=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    report_text = "\n".join(lines)
    print(report_text)

    with open(REPORT_FILE, "w") as f:
        f.write(report_text)

    print(f"\n[+] Report saved to: {REPORT_FILE}")


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print_dashboard()
    print()
    generate_report()
