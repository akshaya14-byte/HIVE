from datetime import datetime
import pickle
import numpy as np
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from blocklist import block_ip, unblock_ip, get_all_blocked, is_blocked, BLOCK_THRESHOLD
from firebase_push import push_detection, push_blocklist, remove_blocklist

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

with open("ddos_model.pkl", "rb") as f:
    saved = pickle.load(f)
clf          = saved["clf"]
scaler       = saved["scaler"]
le           = saved["le"]           # LabelEncoder — knows all real class names
feature_cols = saved["feature_cols"]

# ──────────────────────────────────────────────
# Feature Engineering (MUST match model.py / CICIDS2017 columns)
# ──────────────────────────────────────────────
# The API accepts field names that map directly to the dataset columns.
# Users send real flow stats — same fields the dataset was built from.

def extract_features(data: dict) -> list:
    """Map incoming request fields to the exact CICIDS2017 feature columns."""
    row = []
    for col in feature_cols:
        row.append(float(data.get(col, 0) or 0))
    return row

def rule_score(data: dict) -> float:
    """Lightweight rule engine on top of ML."""
    score = 0
    pps   = float(data.get("Flow Packets/s", 0))
    bps   = float(data.get("Flow Bytes/s",   0))
    syn   = float(data.get("SYN Flag Count", 0))
    fin   = float(data.get("FIN Flag Count", 0))
    pkt   = float(data.get("Min Packet Length", 0))

    if pps > 10000:                        score += 40
    if pps > 50000:                        score += 30
    if bps > 10_000_000:                   score += 20
    if syn > 0 and pkt <= 64:              score += 25
    if fin == 0 and syn > 0:               score += 10

    return max(0, min(100, score))

# ──────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────

@app.post("/scan_traffic")
def scan_traffic(data: dict):
    src_ip = data.get("src_ip", "unknown")

    # Check if already blocked
    if is_blocked(src_ip):
        return {
            "src_ip":     src_ip,
            "prediction": "BLOCKED",
            "is_attack":  True,
            "risk_score": 1.0,
            "ml_score":   None,
            "rule_score": None,
            "blocked":    True,
            "node":       "Campus Block A - Traffic Scanner",
        }

    features   = extract_features(data)
    x          = scaler.transform([features])
    prediction = le.inverse_transform(clf.predict(x))[0]
    ml_conf    = float(clf.predict_proba(x)[0].max())
    rule_prob  = rule_score(data) / 100.0
    ml_attack_prob = 0 if prediction == "BENIGN" else ml_conf
    combined   = 0.50 * ml_attack_prob + 0.50 * rule_prob
    # If rule engine is very confident, override ML (handles imbalanced training data)
    if rule_prob >= 0.70:
        is_attack = True
    elif prediction != "BENIGN":
        is_attack = True
    else:
        is_attack = combined >= 0.45

    # Auto-block if risk score crosses threshold
    newly_blocked = False
    if is_attack and combined >= BLOCK_THRESHOLD:
        newly_blocked = block_ip(src_ip, prediction, combined)

    result = {
        "src_ip":       src_ip,
        "prediction":   prediction,
        "is_attack":    is_attack,
        "risk_score":   round(combined, 4),
        "ml_score":     round(ml_conf, 4),
        "rule_score":   round(rule_prob, 4),
        "auto_blocked": newly_blocked,
        "node":         "Campus Block A - Traffic Scanner",
    }
    # Add alert to timeline if attack detected
    if is_attack:
        alerts.append({
        "type": prediction,
        "ip": src_ip,
        "time": datetime.now().isoformat()
    })

    # Push to Firebase dashboard
    push_detection(result, detection_type="traffic")
    if newly_blocked:
        push_blocklist(src_ip, prediction, combined)

    return result


@app.get("/blocklist")
def view_blocklist():
    """View all currently blocked IPs."""
    blocked = get_all_blocked()
    return {
        "total_blocked": len(blocked),
        "blocked_ips":   blocked,
    }


@app.delete("/blocklist/{ip}")
def remove_from_blocklist(ip: str):
    """Manually unblock an IP."""
    success = unblock_ip(ip)
    if success:
        return {"message": f"{ip} has been unblocked."}
    return {"message": f"{ip} was not in the blocklist."}


@app.get("/live_capture_test")
def live_capture_test():
    
    return flows
alerts = []

@app.get("/alerts")
def get_alerts():
    return alerts[-20:]
