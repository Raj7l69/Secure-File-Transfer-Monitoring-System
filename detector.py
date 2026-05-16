# detector.py — Sensitive File Classification & Unauthorized Movement Detector
#
# Maintains a list of sensitive file patterns and restricted directories.
# Classifies each filesystem event as normal or sensitive/suspicious.
# Detects unauthorized transfers to external or untrusted destinations.
#
# Imported by monitor.py. Can also be run standalone for a demo.
#
# Usage (standalone):
#   python detector.py

import os
import re

# ─── SENSITIVE FILE PATTERNS ──────────────────────────────────────────────────
#
# Files matching these patterns are considered sensitive.
# Any event involving them triggers an alert.

SENSITIVE_EXTENSIONS = {
    ".key", ".pem", ".p12", ".pfx",        # Cryptographic keys / certificates
    ".sql", ".db", ".sqlite", ".mdb",       # Databases
    ".kdbx", ".keychain",                   # Password managers
    ".csv", ".xlsx", ".xls",               # Spreadsheets (often contain PII)
    ".docx", ".doc", ".pdf",               # Documents
    ".bak", ".backup",                     # Backups
    ".env", ".config", ".conf",            # Configuration files
    ".log",                                # Log files
    ".zip", ".tar", ".gz", ".rar", ".7z",  # Archives (bulk transfer risk)
}

SENSITIVE_FILENAME_PATTERNS = [
    r"(?i)(password)",
    r"(?i)(credential)",
    r"(?i)(secret)",
    r"(?i)(private[_\-]?key)",
    r"(?i)(confidential)",
    r"(?i)(sensitive)",
    r"(?i)(employee)",
    r"(?i)(salary)",
    r"(?i)(financial)",
    r"(?i)(payroll)",
    r"(?i)(customer)",
    r"(?i)(personal)",
    r"(?i)(ssn|social.security)",
    r"(?i)(backup)",
    r"(?i)(dump)",
]

# ─── SUSPICIOUS DESTINATION PATTERNS ─────────────────────────────────────────
#
# File destinations matching these patterns suggest exfiltration risk.

SUSPICIOUS_DESTINATIONS = [
    r"(?i)(usb|removable|external)",         # USB / removable drives
    r"(?i)(\\\\[a-z0-9])",                   # UNC network paths (\\server\share)
    r"(?i)(dropbox|onedrive|gdrive|google.drive|icloud|box\.com)",  # Cloud sync
    r"(?i)(downloads)",                      # Downloads folder (browser activity)
    r"(?i)(temp|tmp)",                       # Temp directories
    r"(?i)(recycle|trash|\.trash)",          # Recycle bin / trash
    r"(?i)(appdata\\roaming)",               # Roaming profile (sync to cloud)
    r"(^/media/)",                           # Linux external media mounts
    r"(^/mnt/)",                             # Linux mount points
]

# ─── RESTRICTED DIRECTORIES ───────────────────────────────────────────────────
#
# Files moved OUT of these directories always trigger an alert.

RESTRICTED_DIRECTORIES = [
    "./monitored_folder/restricted",
    "./monitored_folder/confidential",
    "./monitored_folder/finance",
    "./monitored_folder/hr",
]

# ─── CLASSIFICATION FUNCTIONS ─────────────────────────────────────────────────

def is_sensitive_file(filepath: str) -> tuple:
    """
    Check if a file is considered sensitive based on its name or extension.

    Returns:
        (bool, str) — (is_sensitive, reason)
    """
    filename  = os.path.basename(filepath).lower()
    _, ext    = os.path.splitext(filename)

    # Extension check
    if ext in SENSITIVE_EXTENSIONS:
        return True, f"Sensitive file extension: {ext}"

    # Filename pattern check
    for pattern in SENSITIVE_FILENAME_PATTERNS:
        if re.search(pattern, filename):
            return True, f"Sensitive filename pattern matched: {pattern}"

    # Restricted directory check
    abs_src = os.path.abspath(filepath)
    for restricted in RESTRICTED_DIRECTORIES:
        if abs_src.startswith(os.path.abspath(restricted)):
            return True, f"File is in restricted directory: {restricted}"

    return False, ""


def is_suspicious_destination(dest_path: str) -> bool:
    """
    Check if a destination path looks like a suspicious exfiltration target.

    Returns:
        bool — True if destination is suspicious
    """
    for pattern in SUSPICIOUS_DESTINATIONS:
        if re.search(pattern, dest_path):
            return True
    return False


def classify_event(src_path: str, event_type: str, dest_path: str = None) -> dict:
    """
    Classify a file system event.

    Returns a classification dict:
    {
        "label":     "SENSITIVE" | "NORMAL",
        "sensitive": bool,
        "alert":     bool,
        "reason":    str
    }
    """
    sensitive, reason = is_sensitive_file(src_path)
    alert             = False
    alert_reason      = reason

    # Always alert on sensitive file events (except normal reads)
    if sensitive and event_type in ("MODIFIED", "MOVED", "DELETED", "CREATED"):
        alert        = True
        alert_reason = reason

    # Alert on move to suspicious destination
    if dest_path and is_suspicious_destination(dest_path):
        alert        = True
        alert_reason = (alert_reason + " | " if alert_reason else "") + \
                       f"Suspicious destination: {dest_path}"

    # Alert on bulk deletion (DELETED events) of sensitive files
    if sensitive and event_type == "DELETED":
        alert_reason = (alert_reason + " | " if alert_reason else "") + \
                       "Sensitive file deleted — possible data destruction"

    return {
        "label":    "SENSITIVE" if sensitive else "NORMAL",
        "sensitive": sensitive,
        "alert":     alert,
        "reason":    alert_reason,
    }


# ─── STANDALONE DEMO ──────────────────────────────────────────────────────────

TEST_FILES = [
    ("./monitored_folder/report.docx",           "CREATED", None),
    ("./monitored_folder/passwords.txt",          "CREATED", None),
    ("./monitored_folder/employee_salary.xlsx",   "MOVED",   "/media/usb/salary.xlsx"),
    ("./monitored_folder/database_backup.sql",    "CREATED", None),
    ("./monitored_folder/notes.txt",              "MODIFIED",None),
    ("./monitored_folder/config.env",             "MOVED",   "/tmp/config.env"),
    ("./monitored_folder/image.png",              "CREATED", None),
    ("./monitored_folder/confidential_report.pdf","DELETED", None),
    ("./monitored_folder/app.py",                 "MODIFIED",None),
    ("./monitored_folder/private_key.pem",        "MOVED",   "//server/share/key.pem"),
]

if __name__ == "__main__":
    print("=" * 70)
    print("  FILE TRANSFER DETECTOR — CLASSIFICATION DEMO")
    print("=" * 70 + "\n")
    print(f"  {'FILE':<40} {'EVENT':<10} {'LABEL':<12} {'ALERT'}")
    print(f"  {'-'*40} {'-'*10} {'-'*12} {'-'*30}")

    for src, evt, dest in TEST_FILES:
        result = classify_event(src, evt, dest)
        alert_str = f"YES — {result['reason']}" if result["alert"] else "no"
        print(
            f"  {os.path.basename(src):<40} {evt:<10} "
            f"{result['label']:<12} {alert_str}"
        )

    print("\n" + "=" * 70)
