# Secure File Transfer Monitoring System

A Python-based educational toolkit that monitors a directory for file transfer activity, detects unauthorized movement of sensitive files, verifies file integrity using SHA256 hashing, and generates detailed audit reports.

Built for educational and defensive security purposes as part of a cybersecurity project.

---

## What It Does

- **Monitors** a directory in real time for file creation, modification, deletion, and movement using the `watchdog` library
- **Classifies** every file event — identifying sensitive files by extension, filename pattern, or restricted directory
- **Detects** unauthorized transfers to suspicious destinations (USB, cloud sync folders, network shares, temp directories)
- **Verifies** file integrity using SHA256 and MD5 hashes with baseline comparison
- **Logs** all events with timestamps, source/destination paths, file hashes, and alert reasons
- **Reports** a full audit summary with alert counts, event breakdown, integrity results, and security recommendations

---

## Project Structure

```
secure-file-transfer-monitor/
│
├── monitor.py       # Real-time filesystem event monitoring (watchdog)
├── detector.py      # Sensitive file classification + unauthorized movement detection
├── integrity.py     # SHA256/MD5 hashing + baseline comparison
├── logger.py        # Event logging (text + JSON)
├── reporter.py      # Audit dashboard + final report generator
│
├── monitored_folder/           # Directory being watched (auto-created)
├── integrity_baseline.json     # Baseline hash snapshot (auto-generated)
├── file_transfer.log           # Human-readable event log (auto-generated)
├── file_transfer_events.json   # Structured JSON log (auto-generated)
└── file_transfer_report.txt    # Final audit report (auto-generated)
```

---

## Requirements

- **Python:** 3.8 or above
- **OS:** Windows / Linux / macOS
- **Dependencies:**
  ```bash
  pip install watchdog
  ```
- All other modules use only the Python standard library (`hashlib`, `json`, `os`, `re`, `datetime`)

---

## How to Use

### Step 1 — Build the Integrity Baseline

Run this first on a clean, trusted state of the monitored folder.

```bash
python integrity.py
# Choose option [1] to build baseline
```

Creates `integrity_baseline.json` with SHA256 hashes of all files.

---

### Step 2 — Run the Detector Standalone (Optional Demo)

```bash
python detector.py
```

Shows how the classifier labels different file types and destinations as SENSITIVE or NORMAL.

---

### Step 3 — Start the Monitor

```bash
python monitor.py
```

Watches `./monitored_folder` in real time. Copy, move, modify, or delete files inside it to trigger events. Press `Ctrl+C` to stop.

---

### Step 4 — Verify Integrity

```bash
python integrity.py
# Choose option [2] to verify
```

Compares current file state against the baseline. Reports MODIFIED, NEW, or DELETED files.

---

### Step 5 — Generate the Report

```bash
python reporter.py
```

Prints an audit dashboard and saves the full report to `file_transfer_report.txt`.

---

## Sensitive File Detection

### By Extension

| Category | Extensions |
|---|---|
| Cryptographic keys | `.key`, `.pem`, `.p12`, `.pfx` |
| Databases | `.sql`, `.db`, `.sqlite`, `.mdb` |
| Spreadsheets | `.csv`, `.xlsx`, `.xls` |
| Documents | `.docx`, `.doc`, `.pdf` |
| Archives | `.zip`, `.tar`, `.gz`, `.rar`, `.7z` |
| Config files | `.env`, `.config`, `.conf` |

### By Filename Pattern

Files matching patterns like `password*`, `credential*`, `secret*`, `employee*`, `salary*`, `financial*`, `confidential*` are automatically flagged as sensitive.

---

## Suspicious Destination Detection

Transfers to the following destinations trigger an alert:

| Destination | Risk |
|---|---|
| USB / removable drives | Data exfiltration |
| Network shares (`\\server\share`) | Lateral movement |
| Cloud sync folders (Dropbox, OneDrive, Google Drive) | Cloud exfiltration |
| `/media/` or `/mnt/` (Linux) | External media |
| Temp directories | Staging area |
| Recycle Bin / Trash | Destruction |

---

## Sample Output

**Alert — sensitive file moved to USB:**
```
  [ALERT] [2024-11-15T14:32:07] MOVED    employee_salary.xlsx
    → Reason : Sensitive file extension: .xlsx | Suspicious destination: /media/usb/
    → Hash   : a3f1c9d2e8b7...
```

**Integrity check — file modified:**
```
  [MODIFIED] employee_salary.xlsx
    Baseline : a3f1c9d2e8b7044f...
    Current  : 9c2d1f8e3a6b77c4...
```

**Audit report summary:**
```
  Total Events     : 14
  Alerts Generated : 5  (35.7%)
  Sensitive Files  : 7
```

---

## MITRE ATT&CK Coverage

| Technique | ID |
|---|---|
| Data from Local System | T1005 |
| Exfiltration Over Physical Medium (USB) | T1052 |
| Data Staged | T1074 |
| Indicator Removal (file deletion) | T1070 |

---

## Ethical Disclaimer

This toolkit is built **strictly for educational and defensive purposes**.

- Only monitors the local `./monitored_folder` directory by default
- Does not access, read, or transmit file contents
- Only use on systems you own or have **explicit permission** to monitor

---

## Future Enhancements

- Email/Slack alerts for sensitive file events
- User and process name tracking using `psutil`
- USB device detection and automatic blocking
- Scheduled integrity checks via cron / Task Scheduler
- SIEM integration via syslog
- Web dashboard for real-time event visualization
