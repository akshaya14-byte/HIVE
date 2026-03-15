# 🛡 HIVE — Real-Time Network Security Monitoring Platform

> **AI-powered DDoS detection + Phishing URL scanner + Live packet capture + Global threat map**  
> Built for AMD Slingshot Hackathon 2025

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=flat-square&logo=fastapi)
![Firebase](https://img.shields.io/badge/Firebase-Realtime%20DB-FFCA28?style=flat-square&logo=firebase)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)
![scikit-learn](https://img.shields.io/badge/scikit--learn-Random%20Forest-F7931E?style=flat-square&logo=scikit-learn)

---

## 📌 What is HIVE?

HIVE is a full-stack, real-time network security monitoring platform that automatically:

- 🔍 **Detects DDoS attacks** using a Random Forest ML model trained on the CICIDS2017 dataset (500K+ real network flows)
- 🎣 **Scans URLs for phishing** using ML + 15 heuristic rules
- 📡 **Captures live network packets** every 5 seconds using Scapy — zero manual input
- ⊘ **Auto-blocks malicious IPs** when risk score exceeds threshold
- 🌍 **Maps attacks globally** on a live world map with geo-located IP dots
- 📊 **Displays everything in real time** on a Firebase-powered React dashboard

---

## 🎯 Problem It Solves

| Problem | HIVE's Solution |
|---|---|
| DDoS attacks take down networks in seconds | ML detects and blocks in < 10 seconds |
| Phishing URLs bypass traditional blocklists | Real-time scanner with 15 heuristic checks |
| No visibility into network traffic | Live packet capture + real-time dashboard |
| Manual response is too slow | Fully automated pipeline — no human needed |

---

## 🏗 Architecture

```
Real Network Traffic
       │
       ▼
📡 live_capture.py          ← Scapy captures packets every 5s
       │                       Extracts 27 CICIDS2017 features
       ▼
🧠 Traffic Scanner           ← FastAPI on port 8000
   (Random Forest ML)          Hybrid: ML score + rule engine
       │
       ├── Risk > 0.45 ──→ ⊘ Auto-block IP
       │
       ▼
🔥 Firebase Realtime DB      ← Syncs detections instantly
       │
       ▼
📊 React Dashboard           ← Live stats, threat map, feed
   (port 3000 / 5173)          Firebase Auth protected
```

**3 Docker containers:**
- `traffic-scanner` — FastAPI DDoS detector (`:8000`)
- `url-scanner` — FastAPI phishing scanner (`:8001`)
- `dashboard` — React frontend (`:3000`)

---

## ✨ Features

| Feature | Description |
|---|---|
| 📡 Live Packet Capture | Scapy agent sniffs real network traffic every 5s |
| 🧠 DDoS ML Detector | Random Forest on CICIDS2017 — detects SYN/UDP/HTTP floods, PortScan |
| 🎣 Phishing URL Scanner | ML + 15 heuristic rules — typosquatting, homograph attacks |
| ⊘ Auto IP Blocking | Risk > 0.45 → instant block, synced to Firebase |
| 🌍 Global Threat Map | World map with glowing red/green dots per attacking IP |
| 📊 Real-Time Dashboard | Live stats, attack charts, live feed — Firebase powered |
| 🔐 Firebase Auth | Email/password login protects the dashboard |
| 🐳 Docker Deployment | One command startup: `docker-compose up -d` |

---

## 🚀 Quick Start

### Option A — With Docker (Recommended)

#### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Python 3.11+](https://www.python.org/)
- [Npcap](https://npcap.com/#download) (Windows — for live packet capture)

#### Steps

**1. Clone the repo**
```bash
git clone https://github.com/akshaya14-byte/HIVE.git
cd HIVE
```

**2. Set up Firebase**
- Go to [console.firebase.google.com](https://console.firebase.google.com)
- Create a new project
- Enable **Realtime Database** and **Authentication (Email/Password)**
- Copy your Firebase config into `Dashboard/src/firebase.js`

**3. Start all containers**
```bash
docker-compose up -d
```

**4. Start live packet capture**
```bash
# Find your interface first
python -c "from scapy.all import IFACES; IFACES.show()"

# Then run
cd scanners
python live_capture.py --iface "\Device\NPF_{YOUR-INTERFACE-ID}"
```

**5. Open dashboard**
```
http://localhost:3000
```

---

### Option B — Without Docker

Open **4 separate PowerShell windows:**

**Window 1 — Traffic Scanner**
```powershell
cd HIVE/scanners
pip install fastapi uvicorn scikit-learn pandas numpy scipy requests
uvicorn node_traffic_scanner:app --host 0.0.0.0 --port 8000
```

**Window 2 — URL Scanner**
```powershell
cd HIVE/scanners
uvicorn node_url_scanner:app --host 0.0.0.0 --port 8001
```

**Window 3 — Dashboard**
```powershell
cd HIVE/Dashboard
npm install
npm run dev
```
Open: `http://localhost:5173`

**Window 4 — Live Capture**
```powershell
cd HIVE/scanners
pip install scapy
python live_capture.py --iface "\Device\NPF_{YOUR-INTERFACE-ID}"
```

---

## 📁 Project Structure

```
HIVE/
├── docker-compose.yml
├── scanners/
│   ├── node_traffic_scanner.py    # DDoS detector FastAPI
│   ├── node_url_scanner.py        # Phishing scanner FastAPI
│   ├── live_capture.py            # Scapy packet capture agent
│   ├── blocklist.py               # IP blocking logic
│   ├── firebase_push.py           # Firebase sync
│   ├── requirements.txt
│   └── Dockerfile
├── Dashboard/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── firebase.js            # ← Add your Firebase config here
│   │   └── components/
│   │       ├── StatsCards.jsx
│   │       ├── LiveFeed.jsx
│   │       ├── AttackChart.jsx
│   │       ├── GeoMap.jsx         # Global threat map
│   │       ├── TrafficScanner.jsx
│   │       ├── URLScanner.jsx
│   │       ├── BlocklistManager.jsx
│   │       └── Login.jsx
│   ├── package.json
│   └── Dockerfile
├── ddosmodel.py                   # Model training script
├── model.py                       # URL model training script
└── README.md
```

---

## 🧠 ML Models

### DDoS Detector
- **Dataset:** CICIDS2017 (Canadian Institute for Cybersecurity)
- **Algorithm:** Random Forest Classifier
- **Features:** 27 network flow features (packet rates, byte rates, flag counts, IAT stats)
- **Attack types:** DDoS-SYN, DDoS-UDP, DDoS-HTTP, PortScan, Infiltration, BENIGN
- **Scoring:** Hybrid ML score + rule-based heuristics → risk score 0.0–1.0

### Phishing URL Scanner
- **Dataset:** 100,000+ labeled URLs
- **Algorithm:** ML classifier + 15 heuristic rules
- **Features:** URL length, special chars, domain age, keywords, HTTPS check, homograph detection
- **Output:** PHISHING / LEGITIMATE + confidence score

---

## 🖥 Dashboard Tabs

| Tab | What it shows |
|---|---|
| **Overview** | Live stats, detection feed, attack charts |
| **Threat Map** | World map with geo-located attack IPs |
| **Traffic Scan** | Manual DDoS simulation for demos |
| **URL Scan** | Paste any URL for phishing verdict |
| **Blocklist** | All auto-blocked IPs with one-click unblock |

---

## 🛠 Tech Stack

| Layer | Technologies |
|---|---|
| ML / Data | Python 3.11, scikit-learn, pandas, numpy, CICIDS2017 |
| Backend | FastAPI, Uvicorn, Scapy, Npcap |
| Frontend | React 18, Vite, Recharts, Leaflet.js |
| Database | Firebase Realtime Database |
| Auth | Firebase Authentication |
| Infrastructure | Docker, Docker Compose |
| Geo | ipapi.co |

---

## 🔧 Firebase Setup

1. Create project at [console.firebase.google.com](https://console.firebase.google.com)
2. Enable **Realtime Database** → Start in test mode
3. Enable **Authentication** → Email/Password
4. Go to Project Settings → Your apps → Add web app
5. Copy config and paste into `Dashboard/src/firebase.js`:

```js
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  databaseURL: "https://YOUR_PROJECT-default-rtdb.firebaseio.com",
  projectId: "YOUR_PROJECT",
  storageBucket: "YOUR_PROJECT.appspot.com",
  messagingSenderId: "YOUR_SENDER_ID",
  appId: "YOUR_APP_ID"
}
```

6. Go to Authentication → Users → Add user (your email + password for login)

---

## 🔮 Roadmap

- [ ] Alert system — browser sound + popup on attack
- [ ] PDF/CSV export of detection reports  
- [ ] Email/SMS notifications for critical attacks
- [ ] Cloud deployment (Vercel + Render)
- [ ] GPU-accelerated inference with AMD ROCm
- [ ] Mobile app (React Native)
- [ ] Auto-retrain pipeline with new detections

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 🙌 Acknowledgements

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) — University of New Brunswick
- [scikit-learn](https://scikit-learn.org/) — ML framework
- [Firebase](https://firebase.google.com/) — Realtime database & auth
- [Scapy](https://scapy.net/) — Packet capture
- [Leaflet.js](https://leafletjs.com/) — Interactive maps
- [FastAPI](https://fastapi.tiangolo.com/) — Backend API

---

*Built for AMD Slingshot Hackathon 2025 — "Human Imagination, Built with AI"*
