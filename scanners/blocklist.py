"""
Blocklist Manager
=================
Automatically blocks IPs that exceed the risk threshold.
Writes to blocklist.txt — one IP per line with metadata.
"""

import os
import threading
from datetime import datetime

BLOCKLIST_FILE = "blocklist.txt"
BLOCK_THRESHOLD = 0.45  # risk_score >= this → auto-block

_lock = threading.Lock()


def _load_blocked_ips() -> set:
    if not os.path.exists(BLOCKLIST_FILE):
        return set()
    with open(BLOCKLIST_FILE, "r") as f:
        blocked = set()
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                blocked.add(line.split("|")[0].strip())
        return blocked


def is_blocked(ip: str) -> bool:
    return ip in _load_blocked_ips()


def block_ip(ip: str, reason: str, risk_score: float):
    """Add IP to blocklist.txt if not already there."""
    with _lock:
        blocked = _load_blocked_ips()
        if ip in blocked:
            return False  # already blocked

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = f"{ip} | {reason} | risk={risk_score:.2f} | blocked_at={timestamp}\n"

        # Write header if file is new
        write_header = not os.path.exists(BLOCKLIST_FILE)
        with open(BLOCKLIST_FILE, "a") as f:
            if write_header:
                f.write("# DDoS Auto-Blocklist\n")
                f.write("# Format: IP | reason | risk_score | timestamp\n")
                f.write(f"# Created: {timestamp}\n\n")
            f.write(entry)

        print(f"[BLOCKED] {ip} — {reason} (risk={risk_score:.2f})")
        return True


def unblock_ip(ip: str) -> bool:
    """Remove an IP from the blocklist."""
    with _lock:
        if not os.path.exists(BLOCKLIST_FILE):
            return False

        with open(BLOCKLIST_FILE, "r") as f:
            lines = f.readlines()

        new_lines = [l for l in lines if not l.startswith(ip)]
        if len(new_lines) == len(lines):
            return False  # IP wasn't in list

        with open(BLOCKLIST_FILE, "w") as f:
            f.writelines(new_lines)

        print(f"[UNBLOCKED] {ip}")
        return True


def get_all_blocked() -> list:
    """Return list of blocked IP metadata dicts."""
    if not os.path.exists(BLOCKLIST_FILE):
        return []
    results = []
    with open(BLOCKLIST_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            results.append({
                "ip":           parts[0] if len(parts) > 0 else "",
                "reason":       parts[1] if len(parts) > 1 else "",
                "risk_score":   parts[2] if len(parts) > 2 else "",
                "blocked_at":   parts[3] if len(parts) > 3 else "",
            })
    return results