
# SIEM-PME

A lightweight, open-source SIEM/SOAR system designed specifically for small and medium-sized businesses (SMBs). Built from scratch in Python — no vendor lock-in, no enterprise pricing.

## What it does

SIEM-PME monitors your infrastructure in real time, detects threats automatically, and responds to attacks with analyst confirmation — all through a simple Discord interface.

Log sources → Collector → Normalizer → Rules Engine → Scorer → Elasticsearch → Grafana + Discord



## Features

### Detection
- Real-time log collection — Linux (journald) and Windows (Event Log)
- Event normalization to a common JSON format
- Correlation rules — brute force SSH, auth failure burst, reconnaissance probes
- Behavioral risk scoring with time-based decay (LOW → ELEVATED → HIGH → CRITICAL)
- ML-based anomaly detection with Isolation Forest
- Impossible Travel Detection — flags logins from geographically impossible locations

### Response (SOAR)
- Semi-automatic IP blocking via Discord bot
- Analyst confirms with `!block <ip>` — firewall updated instantly
- `!unblock <ip>` to reverse — full analyst control at all times

### Noise Reduction
- Dynamic whitelist API — add trusted IPs and users without restarting
- False positive tracking — system suggests whitelist candidates after 3 confirmed FPs
- Profile-based thresholds — medical practice vs e-commerce have different risk tolerances

### Visibility
- Grafana dashboard — events over time, risk distribution, top targeted users
- Weekly PDF report — auto-generated every Monday and sent to Discord
- Discord alerts for HIGH and CRITICAL events in real time

### Security
- TLS encryption on all communications (HTTPS)
- Role-based authentication — least privilege per component
- `siem_agent` — write only
- `siem_grafana` — read only
- Secrets managed via `.env` — never committed to Git

## Architecture


┌─────────────────────────────────────────────────────┐
│                   Log Sources                        │
│  Linux (journald)    Windows 11 (Event Log)          │
└──────────────────────────┬──────────────────────────┘
│
┌──────▼──────┐
│  Collector  │
└──────┬──────┘
│
┌──────▼──────┐
│  Normalizer │  ← tags, enrichment
└──────┬──────┘
│
┌──────▼──────┐
│Rules Engine │  ← correlation + whitelist
└──────┬──────┘
│
┌──────▼──────┐
│Risk Scorer  │  ← behavioral scoring + decay
└──────┬──────┘
│
┌───────────┼───────────┐
│           │           │
┌──────▼─────┐ ┌───▼───┐ ┌────▼────┐
│Elasticsearch│ │Discord│ │Isolation│
│  + Grafana  │ │  Bot  │ │ Forest  │
└─────────────┘ └───────┘ └─────────┘



## Business Profiles

Each profile adjusts detection thresholds to match the business context:

| Rule | E-commerce | Medical |
|---|---|---|
| Brute force SSH | 10 attempts / 60s | 3 attempts / 60s |
| Auth failure burst | 5 attempts / 60s | 2 attempts / 60s |
| Invalid user probe | 5 attempts / 120s | 2 attempts / 120s |

## Tech Stack

- Python 3.13
- Elasticsearch 8.13 + Grafana
- Docker Compose
- discord.py
- scikit-learn (Isolation Forest)
- ReportLab (PDF reports)
- Flask (Tuning API)
- ip-api.com (Geolocation)

## Installation

### Requirements

- Docker and Docker Compose
- Python 3.10+
- Kali Linux or any Debian-based system

### Quick Start

```bash
# Clone the repository
git clone https://github.com/gbac4/siem-pme.git
cd siem-pme

# Install dependencies
pip install -r requirements.txt --break-system-packages

# Configure environment
cp .env.example .env
nano .env  # fill in your credentials

# Start Elasticsearch and Grafana
sudo docker compose up -d

# Run the SIEM pipeline
sudo python3 main.py
```

### Access

- Grafana dashboard : `http://localhost:3000` (admin / your_password)
- Elasticsearch : `https://localhost:9200`
- Tuning API : `http://localhost:5001`

### Windows Agent

```powershell
# On any Windows machine
cd siem-pme\agent
python windows_collector.py
```

## Project Structure


siem-pme/
├── agent/
│   ├── collector.py              # Linux log collection
│   └── windows_collector.py     # Windows Event Log agent
├── parser/
│   └── normalizer.py            # Event normalization and tagging
├── engine/
│   ├── rules.py                 # Correlation rules + whitelist
│   ├── scorer.py                # Behavioral risk scoring
│   ├── alerting.py              # Discord webhook alerts
│   ├── discord_bot.py           # SOAR bot — block/unblock IPs
│   ├── tuning.py                # False positive API + whitelist
│   ├── travel_detector.py       # Impossible Travel Detection
│   ├── anomaly_detector.py      # ML anomaly detection
│   ├── report_generator.py      # PDF report generation
│   └── scheduler.py             # Weekly report automation
├── profiles/
│   ├── ecommerce.yaml           # E-commerce business profile
│   └── medical.yaml             # Medical practice profile
├── data/                        # Runtime data (whitelists, history)
├── reports/                     # Generated PDF reports
├── main.py                      # Pipeline entry point
├── docker-compose.yml           # Elasticsearch + Grafana
├── requirements.txt             # Python dependencies
└── .env.example                 # Environment template



## Roadmap

### Sprint 1 — Done
- [x] Linux log collector
- [x] Event normalizer
- [x] Correlation rules engine
- [x] Behavioral risk scorer
- [x] Elasticsearch + Grafana integration

### Sprint 2 — Done
- [x] Discord alerts
- [x] Windows Event Log agent
- [x] TLS + authentication + least privilege
- [x] Dynamic whitelist API
- [x] False positive tracking

### Sprint 3 — Done
- [x] Discord bot SOAR — semi-automatic IP blocking
- [x] Impossible Travel Detection
- [x] Weekly PDF report automation
- [x] ML anomaly detection (Isolation Forest)

### Sprint 4 — Planned
- [ ] Active Directory integration
- [ ] Threat intelligence feeds (MISP, VirusTotal)
- [ ] Mobile push notifications
- [ ] Multi-tenant support

## Discord Bot Commands

| Command | Description |
|---|---|
| `!block <ip>` | Block an IP address via UFW |
| `!unblock <ip>` | Unblock an IP address |
| `!blocked` | List all currently blocked IPs |
| `!ignore` | Dismiss the latest block request |
| `!help` | Show all available commands |

## Author

Built by a cybersecurity graduate as a portfolio project demonstrating end-to-end SIEM/SOAR development.

Feedback and contributions welcome.

## License

MIT License
