---

## Security Design

| Component | Security Measure |
|---|---|
| Data in transit | TLS encryption (HTTPS) |
| Authentication | Role-based — least privilege per component |
| Agent credentials | Write-only access to Elasticsearch |
| Dashboard credentials | Read-only access |
| Secrets | Environment variables — never in code or Git |

---

## Business Profiles

The system ships with configurable profiles that adjust detection sensitivity:

| Profile | Use case | Brute force threshold |
|---|---|---|
| E-commerce | High traffic, global users | 10 attempts / 60s |
| Medical | Sensitive data, strict compliance | 3 attempts / 60s |
| Finance | High value targets | 3 attempts / 60s |
| Industry | OT/IT convergence | 5 attempts / 60s |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Log collection | Python 3.13, journald, Win32 API |
| Storage | Elasticsearch 8.13 |
| Visualization | Grafana |
| Alerting | Discord Webhooks + discord.py bot |
| ML | scikit-learn Isolation Forest |
| PDF reports | ReportLab |
| API | Flask |
| Infrastructure | Docker Compose |
| TLS | Self-signed certificates (production: CA-signed) |

---

## Deployment

### Minimum requirements

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 4 GB | 8 GB |
| CPU | 2 cores | 4 cores |
| Storage | 20 GB | 50 GB |
| OS | Any Linux | Kali / Ubuntu |

### Time to deploy

- Server setup : 15 minutes
- First agent connected : 5 minutes per machine
- Dashboard configured : 10 minutes

---

## Current Deployment

Running live on a home lab environment monitoring 5 machines simultaneously:

- 1 Kali Linux server (SIEM central)
- 4 endpoints (Windows 11 + Linux)

All events centralized, correlated, and visualized in real time.

---

## Roadmap

| Sprint | Status | Features |
|---|---|---|
| Sprint 1 | ✅ Done | Core pipeline, Elasticsearch, Grafana |
| Sprint 2 | ✅ Done | Windows agent, TLS, whitelist, Discord alerts |
| Sprint 3 | ✅ Done | SOAR bot, ML, Impossible Travel, PDF reports |
| Sprint 4 | 🔄 Planned | Active Directory, threat intel feeds, mobile alerts |

---

## Links

- **GitHub** : github.com/gbac4/siem-pme
- **Medium** : Articles documenting the full build process
- **LinkedIn** : Live progress updates throughout development

---

*Built by a cybersecurity graduate — open to feedback, collaboration, and opportunities.*
