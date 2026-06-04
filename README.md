# NetWatch-IDS 🛡️

> A Python-based Network Intrusion Detection System with real-time alerting, a live SOC-style dashboard, and MITRE ATT&CK-mapped detection rules.

![CI](https://github.com/YOUR_USERNAME/NetWatch-IDS/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red.svg)

---

## Overview

NetWatch-IDS is a lightweight, extensible intrusion detection system built in Python. It captures network packets using **Scapy**, evaluates them against a configurable **JSON rule engine**, and surfaces alerts in a real-time **Flask web dashboard**.

It supports both **live interface capture** (requires root/NET_ADMIN) and **PCAP replay mode** for safe offline testing and demonstration.

```
┌─────────────────────────────────────────────────────────┐
│                    NetWatch-IDS                          │
│                                                         │
│  Network  ──►  PacketCapture  ──►  RuleEngine           │
│  / PCAP          (Scapy)         (JSON rules)           │
│                     │                  │                │
│                PacketStore        AlertStore            │
│                     │                  │                │
│              Flask REST API  ◄──────────┘               │
│                     │                                   │
│              Web Dashboard (Chart.js)                   │
└─────────────────────────────────────────────────────────┘
```

---

## Features

- **14 built-in detection rules** — port scans, SYN floods, brute force, ARP spoofing, DNS tunneling, and more
- **MITRE ATT&CK tagging** — every rule maps to a technique ID (T1046, T1498, T1110, etc.)
- **Threshold-based detection** — rate-limiting logic to catch volume-based attacks
- **Hot-reload rules** — edit `rules/default_rules.json` and changes apply live, no restart needed
- **PCAP replay mode** — run full demos without root access or a live network
- **Real-time dashboard** — alert feed, timeline chart, live packet stream, top source IPs
- **Dockerized** — one command to run: `docker compose up`
- **REST API** — all data exposed via JSON endpoints for integration

---

## Detection Rules

| Rule ID | Name | Severity | MITRE Technique | Tactic |
|---------|------|----------|-----------------|--------|
| NW-001 | Port Scan Detected | HIGH | T1046 | Discovery |
| NW-002 | SYN Flood (DoS) | CRITICAL | T1498 | Impact |
| NW-003 | Telnet Traffic | HIGH | T1021.004 | Lateral Movement |
| NW-004 | FTP Cleartext Login | MEDIUM | T1078 | Initial Access |
| NW-005 | ARP Spoofing | HIGH | T1557.002 | Collection |
| NW-006 | ICMP Flood | MEDIUM | T1595.001 | Reconnaissance |
| NW-007 | SSH Brute Force | HIGH | T1110 | Credential Access |
| NW-008 | RDP Exposure | MEDIUM | T1021.001 | Lateral Movement |
| NW-009 | DNS Tunneling Suspect | HIGH | T1071.004 | Command & Control |
| NW-010 | SMB/NetBIOS Scan | HIGH | T1021.002 | Lateral Movement |
| NW-011 | HTTP Cleartext Creds | MEDIUM | T1557.001 | Collection |
| NW-012 | Null TCP Scan | MEDIUM | T1046 | Discovery |
| NW-013 | XMAS Tree Scan | MEDIUM | T1046 | Discovery |
| NW-014 | Suspicious High Port | LOW | T1571 | C2 |

---

## Quick Start

### Option 1: Docker (recommended)

```bash
git clone https://github.com/YOUR_USERNAME/NetWatch-IDS.git
cd NetWatch-IDS
docker compose up
```

Open **http://localhost:5000** — the dashboard auto-starts PCAP replay.

### Option 2: Local Python

```bash
git clone https://github.com/YOUR_USERNAME/NetWatch-IDS.git
cd NetWatch-IDS

pip install -r requirements.txt

# Generate the demo PCAP
python pcap_samples/generate_sample_pcap.py

# Run the dashboard (auto-replays PCAP)
python dashboard/app.py
```

Open **http://localhost:5000**

### Option 3: Live capture (requires root)

```bash
sudo python dashboard/app.py
# Then click START → Live capture in the dashboard
# Or via API:
curl -X POST http://localhost:5000/api/control/start \
  -H "Content-Type: application/json" \
  -d '{"mode":"live","interface":"eth0"}'
```

---

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Packet counts, alert counts by severity, running status |
| `/api/alerts` | GET | Recent alerts (`?n=50&severity=HIGH`) |
| `/api/alerts/counts` | GET | Alert counts per minute for charting |
| `/api/packets` | GET | Live packet stream (`?n=20`) |
| `/api/top-sources` | GET | Top 10 source IPs by alert count |
| `/api/control/start` | POST | Start capture (`{"mode":"live"}` or `{"mode":"replay"}`) |
| `/api/control/stop` | POST | Stop capture |

---

## Adding Custom Rules

Edit `rules/default_rules.json` — changes are picked up live (hot-reload):

```json
{
  "id": "NW-015",
  "name": "MongoDB Exposure",
  "description": "Connection to MongoDB port — should not be publicly accessible.",
  "severity": "HIGH",
  "mitre_technique": "T1190",
  "mitre_tactic": "Initial Access",
  "enabled": true,
  "conditions": {
    "proto": ["TCP"],
    "dst_ports": [27017]
  }
}
```

### Rule condition fields

| Field | Type | Description |
|-------|------|-------------|
| `proto` | list | `["TCP"]`, `["UDP"]`, `["ICMP"]`, `["ARP"]` |
| `dst_ports` | list | Destination port numbers |
| `src_ports` | list | Source port numbers |
| `flags` | list | TCP flags that must be present: `"S"`, `"A"`, `"F"`, `"P"`, `"R"`, `"U"` |
| `flags_not` | list | TCP flags that must NOT be present |
| `payload_contains` | list | Strings to find in packet payload (case-insensitive) |
| `threshold.count` | int | Number of matching packets to trigger |
| `threshold.seconds` | int | Time window for threshold |

---

## Project Structure

```
NetWatch-IDS/
├── netwatch/
│   ├── __init__.py
│   ├── capture.py      # Scapy packet capture + PCAP replay
│   ├── engine.py       # JSON rule engine + threshold detection
│   ├── ids.py          # Orchestrator — wires capture + engine
│   └── models.py       # Packet, Alert, PacketStore, AlertStore
├── dashboard/
│   ├── app.py          # Flask app + REST API
│   └── templates/
│       └── index.html  # SOC-style web dashboard
├── rules/
│   └── default_rules.json   # 14 MITRE-mapped detection rules
├── tests/
│   └── test_netwatch.py     # pytest test suite
├── pcap_samples/
│   └── generate_sample_pcap.py  # Demo PCAP generator
├── .github/
│   └── workflows/ci.yml     # GitHub Actions CI
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Running Tests

```bash
pytest tests/ -v
```

Or with Docker:

```bash
docker compose run test
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Packet capture | Scapy 2.5 |
| Web framework | Flask 3.0 |
| Dashboard charts | Chart.js 4.4 |
| Containerization | Docker + Compose |
| CI | GitHub Actions |
| Python | 3.11+ |

---

## Security Notes

- Live capture requires `CAP_NET_RAW` / root. The Docker Compose file handles this.
- For safe testing on any machine, use PCAP replay mode — no elevated privileges needed.
- This is an educational/portfolio project. For production IDS, consider Suricata or Zeek.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built as part of a cybersecurity portfolio targeting SOC and network security internship positions.*  
*MITRE ATT&CK® is a trademark of The MITRE Corporation.*
