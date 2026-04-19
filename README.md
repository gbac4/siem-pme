# SIEM-PME

A lightweight, open-source SIEM (Security Information and Event Management) 
system designed specifically for small and medium-sized businesses (SMBs).

Detection rules and alert thresholds automatically adapt based on your 
business profile (e-commerce, medical, finance, industry).

## How it works

Log sources → Collector → Normalizer → Rules Engine → Scorer → Elasticsearch → Grafana

Each event captured in real time goes through the full pipeline automatically.

## Features

- Real-time log collection via Linux journald
- Event normalization to a common JSON format
- Business profile system — configure once, adapt to any SMB context
- Correlation rules — brute force SSH, invalid user probes, auth failures
- Risk scoring per IP and user — LOW / MEDIUM / HIGH / CRITICAL
- Event decay — old events lose weight over time
- Whitelist system — trusted IPs and users never trigger false alerts
- Events stored in Elasticsearch
- Security dashboard in Grafana (events over time, risk levels, top users)

## Business profiles

Each profile adjusts detection thresholds to match the business context:

| Profile | Brute force threshold | Auth failure threshold |
|---|---|---|
| E-commerce | 10 attempts | 5 attempts |
| Medical | 3 attempts | 2 attempts |

## Tech stack

- Python 3.13
- Elasticsearch 8.13
- Grafana
- Docker Compose
- YAML profiles

## Installation

### Requirements

- Docker and Docker Compose
- Python 3.10+
- Kali Linux or any Debian-based system

### Quick start

```bash
# Clone the repository
git clone https://github.com/gbac4/siem-pme.git
cd siem-pme

# Install Python dependencies
pip install requests --break-system-packages

# Start Elasticsearch and Grafana
sudo docker compose up -d

# Run the SIEM pipeline
sudo python3 main.py
```

### Access the dashboard

- Grafana : http://localhost:3000 (admin / siem2026)
- Elasticsearch : http://localhost:9200

## Project structure

siem-pme/
├── agent/
│   └── collector.py       # Real-time log collection
├── parser/
│   └── normalizer.py      # Event normalization and tagging
├── engine/
│   ├── rules.py           # Correlation rules and alerting
│   └── scorer.py          # Risk scoring with decay
├── profiles/
│   ├── ecommerce.yaml     # E-commerce business profile
│   └── medical.yaml       # Medical practice profile
├── main.py                # Pipeline entry point
└── docker-compose.yml     # Elasticsearch + Grafana

## Roadmap

### Sprint 1 — Done
- [x] Log collector via journald
- [x] Event normalizer with tags
- [x] Correlation rules engine
- [x] Risk scorer with decay
- [x] Elasticsearch integration
- [x] Grafana dashboard

### Sprint 2 — In progress
- [ ] Email and Slack alerting
- [ ] TLS and authentication
- [ ] Adaptive false positive tuning
- [ ] Windows Event Log support

### Sprint 3 — Planned
- [ ] ML-based anomaly detection (Isolation Forest)
- [ ] Additional business profiles
- [ ] Automated weekly PDF reports

## Author

Built by a cybersecurity graduate as a portfolio project.
Feedback and contributions are welcome.

## License

MIT License
