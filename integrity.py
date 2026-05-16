# integrity.py — File Integrity Verification Module
#
# Computes SHA256 and MD5 hashes for files.
# Maintains a baseline hash database for pre/post transfer comparison.
# Detects tampering, corruption, or unauthorized modification.
#
# Can be run standalone to build a baseline or verify files.
#
# Usage:
#   python integrity.py

import hashlib
import json
import os
import datetime

BASELINE_FILE = "integrity_baseline.json"

# ─── HASHING FUNCTIONS ────────────────────────────────────────────────────────

def compute_hash(filepath: str, algorithm: str = "sha256") -> str:
    """
    Compute the hash of a file using the specified algorithm.
    Reads the file in chunks to handle large files efficiently.

    Args:
        filepath  : full path to the file
        algorithm : 'sha256' (default) or 'md5'

    Returns:
        Hex digest string, or None if file cannot be read.
    """
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def compute_both(filepath: str) -> dict:
    """
    Compute both SHA256 and MD5 hashes for a file.
    Returns a dict with both values.
    """
    return {
        "sha256": compute_hash(filepath, "sha256"),
        "md5":    compute_hash(filepath, "md5"),
    }


# ─── BASELINE MANAGEMENT ──────────────────────────────────────────────────────

def build_baseline(directory: str) -> dict:
    """
    Walk a directory and compute SHA256 hashes for all files.
    Save the baseline to BASELINE_FILE for later comparison.

    Returns the baseline dict.
    """
    baseline = {
        "created_at": datetime.datetime.now().isoformat(),
        "directory":  os.path.abspath(directory),
        "files":      {},
    }

    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, directory)
            h     = compute_hash(fpath)
            size  = os.path.getsize(fpath) if os.path.exists(fpath) else 0
            baseline["files"][rel] = {
                "sha256":       h,
                "size_bytes":   size,
                "recorded_at":  datetime.datetime.now().isoformat(),
            }
            print(f"  [+] {rel:<40} {h}")

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print(f"\n[+] Baseline saved: {BASELINE_FILE}")
    print(f"[+] Files indexed : {len(baseline['files'])}")
    return baseline


def load_baseline() -> dict:
    """Load the saved baseline from disk."""
    if not os.path.exists(BASELINE_FILE):
        print(f"[!] Baseline file not found: {BASELINE_FILE}")
        return {}
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def verify_integrity(directory: str) -> list:
    """
    Compare the current state of a directory against the saved baseline.
    Returns a list of violation dicts for any mismatch found.

    Violation types:
        MODIFIED  — file exists but hash changed
        DELETED   — file in baseline but missing now
        NEW       — file present now but not in baseline
    """
    baseline   = load_baseline()
    violations = []

    if not baseline:
        print("[!] No baseline to compare against. Run build_baseline() first.")
        return violations

    baseline_files = baseline.get("files", {})

    # Check all current files against baseline
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, directory)
            current_hash = compute_hash(fpath)

            if rel not in baseline_files:
                violations.append({
                    "type":          "NEW",
                    "file":          rel,
                    "baseline_hash": None,
                    "current_hash":  current_hash,
                    "timestamp":     datetime.datetime.now().isoformat(),
                })
            elif baseline_files[rel]["sha256"] != current_hash:
                violations.append({
                    "type":          "MODIFIED",
                    "file":          rel,
                    "baseline_hash": baseline_files[rel]["sha256"],
                    "current_hash":  current_hash,
                    "timestamp":     datetime.datetime.now().isoformat(),
                })

    # Check for deleted files
    for rel, info in baseline_files.items():
        fpath = os.path.join(directory, rel)
        if not os.path.exists(fpath):
            violations.append({
                "type":          "DELETED",
                "file":          rel,
                "baseline_hash": info["sha256"],
                "current_hash":  None,
                "timestamp":     datetime.datetime.now().isoformat(),
            })

    return violations


def print_violations(violations: list):
    """Print integrity violations to the console in a readable format."""
    if not violations:
        print("[+] Integrity check passed — no violations found.")
        return

    print(f"\n[!] {len(violations)} integrity violation(s) detected:\n")
    for v in violations:
        print(f"  [{v['type']}] {v['file']}")
        if v["type"] == "MODIFIED":
            print(f"    Baseline : {v['baseline_hash']}")
            print(f"    Current  : {v['current_hash']}")
        elif v["type"] == "NEW":
            print(f"    Hash     : {v['current_hash']}")
        print()


# ─── STANDALONE DEMO ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    TARGET_DIR = "./monitored_folder"
    os.makedirs(TARGET_DIR, exist_ok=True)

    print("=" * 60)
    print("  FILE INTEGRITY CHECKER")
    print("=" * 60)

    choice = input(
        "\n  Choose action:\n"
        "  [1] Build baseline\n"
        "  [2] Verify integrity\n"
        "  Enter 1 or 2: "
    ).strip()

    if choice == "1":
        print(f"\n[*] Building baseline for: {TARGET_DIR}\n")
        build_baseline(TARGET_DIR)

    elif choice == "2":
        print(f"\n[*] Verifying integrity of: {TARGET_DIR}\n")
        violations = verify_integrity(TARGET_DIR)
        print_violations(violations)

    else:
        print("[!] Invalid choice.")
