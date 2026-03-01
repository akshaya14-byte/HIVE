"""
live_capture.py
===============
Live packet capture agent for SENTINEL.
Captures real network traffic, builds flows, and sends them
to the traffic scanner API every few seconds.

REQUIREMENTS:
  pip install scapy requests
  Install Npcap from https://npcap.com/#download (Windows)

USAGE:
  python live_capture.py                  # auto-detect interface
  python live_capture.py --iface "Wi-Fi"  # specify interface
  python live_capture.py --interval 10    # scan every 10 seconds
"""

import argparse
import time
import requests
import statistics
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest

# ── Config ────────────────────────────────────────────────────────────────────
SCANNER_URL  = "http://localhost:8000/scan_traffic"
INTERVAL     = 5      # seconds per capture window
MIN_PACKETS  = 3      # ignore flows with fewer packets (noise)
# ─────────────────────────────────────────────────────────────────────────────

flows = defaultdict(lambda: {
    "packets": 0, "bytes": 0,
    "fwd_packets": 0, "bwd_packets": 0,
    "syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0,
    "pkt_sizes": [],
    "timestamps": [],
    "dst_port": 0,
    "is_tcp": 0, "is_udp": 0, "is_icmp": 0,
    "init_win_fwd": 0, "init_win_bwd": 0,
    "start_time": None,
})

def process_packet(pkt):
    
    if not pkt.haslayer(IP):
        return

    src  = pkt[IP].src
    size = len(pkt)
    now  = time.time()
    f    = flows[src]

    if f["start_time"] is None:
        f["start_time"] = now

    f["packets"]    += 1
    f["bytes"]      += size
    f["pkt_sizes"].append(size)
    f["timestamps"].append(now)

    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        f["is_tcp"]    = 1
        f["dst_port"]  = pkt[TCP].dport
        f["syn"]      += 1 if flags & 0x02 else 0
        f["ack"]      += 1 if flags & 0x10 else 0
        f["fin"]      += 1 if flags & 0x01 else 0
        f["rst"]      += 1 if flags & 0x04 else 0
        f["psh"]      += 1 if flags & 0x08 else 0
        if f["init_win_fwd"] == 0 and pkt[TCP].window:
            f["init_win_fwd"] = pkt[TCP].window

    if pkt.haslayer(HTTPRequest):
        host = pkt[HTTPRequest].Host.decode()
        path = pkt[HTTPRequest].Path.decode()
        full_url = f"http://{host}{path}"
        print("Captured URL:", full_url)
        try:
            requests.post(
                "http://localhost:8001/scan_url",
                json={"url": full_url},
                timeout=2
            )
        except:
            pass
    elif pkt.haslayer(UDP):
        f["is_udp"]   = 1
        f["dst_port"] = pkt[UDP].dport

    elif pkt.haslayer(ICMP):
        f["is_icmp"]  = 1

def build_payload(src_ip, f, duration):
    sizes = f["pkt_sizes"] or [0]
    times = f["timestamps"]

    # Inter-arrival times
    iats = [times[i+1] - times[i] for i in range(len(times)-1)] if len(times) > 1 else [0]
    iat_mean = statistics.mean(iats) * 1000  # ms
    iat_std  = statistics.stdev(iats) * 1000 if len(iats) > 1 else 0
    iat_max  = max(iats) * 1000

    dur_s    = max((times[-1] - times[0]) if len(times) > 1 else duration, 0.001)

    return {
        "src_ip":                    src_ip,
        "Destination Port":          f["dst_port"],
        "Flow Duration":             round(dur_s * 1000, 2),   # ms
        "Total Fwd Packets":         f["packets"],
        "Total Backward Packets":    0,
        "Flow Bytes/s":              round(f["bytes"] / dur_s, 2),
        "Flow Packets/s":            round(f["packets"] / dur_s, 2),
        "Flow IAT Mean":             round(iat_mean, 4),
        "Flow IAT Std":              round(iat_std, 4),
        "Flow IAT Max":              round(iat_max, 4),
        "Fwd Packets/s":             round(f["packets"] / dur_s, 2),
        "Bwd Packets/s":             0,
        "Min Packet Length":         min(sizes),
        "Max Packet Length":         max(sizes),
        "Packet Length Mean":        round(statistics.mean(sizes), 2),
        "Packet Length Std":         round(statistics.stdev(sizes), 2) if len(sizes) > 1 else 0,
        "FIN Flag Count":            f["fin"],
        "SYN Flag Count":            f["syn"],
        "RST Flag Count":            f["rst"],
        "PSH Flag Count":            f["psh"],
        "ACK Flag Count":            f["ack"],
        "Average Packet Size":       round(statistics.mean(sizes), 2),
        "Init_Win_bytes_forward":    f["init_win_fwd"],
        "Init_Win_bytes_backward":   f["init_win_bwd"],
        "act_data_pkt_fwd":          f["packets"],
        "Active Mean":               0,
        "Idle Mean":                 0,
    }

def send_to_scanner(payload):
    try:
        res = requests.post(SCANNER_URL, json=payload, timeout=3)
        data = res.json()
        status = "🚨 ATTACK" if data.get("is_attack") else "✅ BENIGN"
        blocked = " [BLOCKED]" if data.get("auto_blocked") else ""
        print(f"  {status}{blocked} | {payload['src_ip']:<16} | "
              f"{data.get('prediction','?'):<12} | risk={data.get('risk_score',0):.2f}")
    except Exception as e:
        print(f"  ⚠ Scanner unreachable: {e}")

def run_capture(iface=None, interval=INTERVAL):
    print(f"\n{'='*55}")
    print(f"  SENTINEL Live Capture Agent")
    print(f"  Scanning every {interval}s → {SCANNER_URL}")
    print(f"  Interface: {iface or 'auto-detect'}")
    print(f"{'='*55}\n")

    while True:
        print(f"[{time.strftime('%H:%M:%S')}] Capturing {interval}s window...")
        flows.clear()

        sniff(prn=lambda p: print("Packet seen") or process_packet(p))

        if not flows:
            print("  No packets captured. Check interface name or Npcap.\n")
            continue

        print(f"  {len(flows)} unique source IPs found. Sending to scanner...")
        for src_ip, f in list(flows.items()):
            if f["packets"] < MIN_PACKETS:
                continue
            payload = build_payload(src_ip, f, interval)
            send_to_scanner(payload)

        print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL Live Capture Agent")
    parser.add_argument("--iface",    type=str, default=None, help="Network interface name e.g. 'Wi-Fi' or 'Ethernet'")
    parser.add_argument("--interval", type=int, default=INTERVAL, help="Seconds per capture window")
    args = parser.parse_args()

    run_capture(iface=args.iface, interval=args.interval)
