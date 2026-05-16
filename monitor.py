# monitor.py — Filesystem Event Monitor
#
# Uses the watchdog library to monitor a target directory for file
# system events: creation, modification, deletion, and movement.
# Each event is passed to the detector for classification and logging.
#
# Usage:
#   pip install watchdog
#   python monitor.py
#
# Press Ctrl+C to stop monitoring.

import time
import datetime
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from detector import classify_event, is_suspicious_destination
from integrity import compute_hash
from logger import log_event

# ─── CONFIGURATION ────────────────────────────────────────────────────────────

# Directory to monitor — change this to your target path
WATCH_DIRECTORY = "./monitored_folder"

# Create the folder if it doesn't exist (for demo purposes)
os.makedirs(WATCH_DIRECTORY, exist_ok=True)

# ─── EVENT HANDLER ────────────────────────────────────────────────────────────

class FileTransferHandler(FileSystemEventHandler):
    """
    Handles filesystem events detected by watchdog.
    Called automatically when files are created, modified, moved, or deleted.
    """

    def on_created(self, event):
        """Fired when a new file appears — indicates a copy or download."""
        if event.is_directory:
            return
        self._handle("CREATED", event.src_path)

    def on_modified(self, event):
        """Fired when a file's content changes — may indicate tampering."""
        if event.is_directory:
            return
        self._handle("MODIFIED", event.src_path)

    def on_deleted(self, event):
        """Fired when a file is deleted."""
        if event.is_directory:
            return
        self._handle("DELETED", event.src_path)

    def on_moved(self, event):
        """Fired when a file is moved or renamed."""
        if event.is_directory:
            return
        self._handle("MOVED", event.src_path, dest=event.dest_path)

    def _handle(self, event_type: str, src_path: str, dest: str = None):
        """
        Core event handler:
          1. Compute file hash (if file exists)
          2. Classify the event (sensitive / normal)
          3. Check destination for suspicious patterns
          4. Log the event with all metadata
        """
        ts        = datetime.datetime.now().isoformat()
        file_hash = None

        # Compute hash for existing files
        if event_type != "DELETED" and os.path.isfile(src_path):
            file_hash = compute_hash(src_path)

        # Classify the event
        classification = classify_event(src_path, event_type, dest)

        # Check destination for suspicious patterns
        suspicious_dest = False
        if dest:
            suspicious_dest = is_suspicious_destination(dest)

        # Build event record
        record = {
            "timestamp":      ts,
            "event_type":     event_type,
            "src_path":       src_path,
            "dest_path":      dest or "—",
            "file_hash":      file_hash or "—",
            "classification": classification["label"],
            "sensitive":      classification["sensitive"],
            "alert":          classification["alert"] or suspicious_dest,
            "alert_reason":   classification.get("reason", ""),
            "suspicious_dest": suspicious_dest,
        }

        # Print to console
        status = "[ALERT]" if record["alert"] else "[OK]   "
        print(
            f"  {status} [{ts}] {event_type:<8} "
            f"{os.path.basename(src_path)}"
        )
        if record["alert"]:
            print(f"    → Reason : {record['alert_reason'] or 'Suspicious destination'}")
            if file_hash:
                print(f"    → Hash   : {file_hash}")

        # Log the event
        log_event(record)


# ─── MONITOR RUNNER ───────────────────────────────────────────────────────────

def start_monitor():
    """Start the filesystem observer and run until Ctrl+C."""
    handler  = FileTransferHandler()
    observer = Observer()
    observer.schedule(handler, path=WATCH_DIRECTORY, recursive=True)
    observer.start()

    print("=" * 65)
    print("  SECURE FILE TRANSFER MONITOR — ACTIVE")
    print(f"  Watching : {os.path.abspath(WATCH_DIRECTORY)}")
    print("  Press Ctrl+C to stop.")
    print("=" * 65 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Monitor stopped.")

    observer.join()


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    start_monitor()
