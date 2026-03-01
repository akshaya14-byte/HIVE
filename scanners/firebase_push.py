"""
firebase_push.py
================
Shared helper used by both node_traffic_scanner.py and node_url_scanner.py
to push detection events and blocklist updates to Firebase Realtime Database.

SETUP:
  pip install requests

  Set your Firebase Database URL below.
  Make sure your DB rules allow writes (for dev):
    { "rules": { ".read": true, ".write": true } }
"""

import time
import requests

# ── Set your Firebase Realtime Database URL here ──────────────────────────────
FIREBASE_URL = "https://hive-f839e-default-rtdb.asia-southeast1.firebasedatabase.app"
# ─────────────────────────────────────────────────────────────────────────────


def push_detection(data: dict, detection_type: str):
    """Push a detection event to Firebase detections node."""
    payload = {
        **data,
        "type":      detection_type,   # 'traffic' or 'url'
        "timestamp": int(time.time() * 1000),  # ms for JS Date
    }
    try:
        requests.post(
            f"{FIREBASE_URL}/detections.json",
            json=payload,
            timeout=3,
        )
    except Exception as e:
        print(f"[Firebase] push_detection failed: {e}")


def push_blocklist(ip: str, reason: str, risk_score: float):
    """Add an IP to the Firebase blocklist node."""
    # Use IP as key (replace dots with dashes — Firebase key restriction)
    key = ip.replace(".", "-")
    payload = {
        "ip":         ip,
        "reason":     reason,
        "risk_score": round(risk_score, 4),
        "blocked_at": int(time.time() * 1000),
    }
    try:
        requests.put(
            f"{FIREBASE_URL}/blocklist/{key}.json",
            json=payload,
            timeout=3,
        )
    except Exception as e:
        print(f"[Firebase] push_blocklist failed: {e}")


def remove_blocklist(ip: str):
    """Remove an IP from the Firebase blocklist node."""
    key = ip.replace(".", "-")
    try:
        requests.delete(
            f"{FIREBASE_URL}/blocklist/{key}.json",
            timeout=3,
        )
    except Exception as e:
        print(f"[Firebase] remove_blocklist failed: {e}")
