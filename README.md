# CodeAlpha Cybersecurity Internship — Task Portfolio

> **Intern:** Aalekh Kumar  
> **Program:** CodeAlpha Cybersecurity Internship 2026  
> **Duration:** 4 Tasks | Hands-on Security Engineering  
> **GitHub:** [Aalekh2477-CodeAlpha_Tasks](https://github.com/Aalekh2477/Aalekh2477-CodeAlpha_Tasks)

---

## 🎯 Overview

This repository contains **4 progressive cybersecurity tasks** completed during the CodeAlpha internship. Each task builds practical, portfolio-ready skills — from application security auditing to network defense and intrusion detection.

| Task | Title | Focus Area | Difficulty | Key Technologies |
|------|-------|------------|------------|------------------|
| **01** | **Security Code Audit** | Application Security (AppSec) | ⭐⭐⭐ Intermediate | Python, Flask, SQLite, Bandit, Semgrep, OWASP Top 10 |
| **02** | **Phishing Awareness Module** | Security Awareness & Human Factor | ⭐⭐ Beginner | HTML5, CSS3, Vanilla JS (no frameworks) |
| **03** | **Network Packet Analyzer** | Network Security & Traffic Analysis | ⭐⭐⭐ Intermediate | Python, Scapy, BPF, PCAP |
| **04** | **Network Intrusion Detection System (NIDS)** | Blue Team / Detection Engineering | ⭐⭐⭐⭐ Advanced | Suricata, Snort, Docker, Grafana, ELK, SIEM |

---

## 📁 Repository Structure

```
Aalekh2477-CodeAlpha_Tasks/
├── README.md                          ← You are here (Master README)
├── 01_security_code_audit/            ← Task 1: Vulnerable app + secure rewrite + audit report
│   ├── app.py                         ← Intentionally vulnerable Flask app (27 flaws)
│   ├── app_secure.py                  ← Fully remediated secure version
│   ├── SECURITY_AUDIT_REPORT.md       ← 27 findings with CWE, severity, fixes
│   ├── AUDIT_TOOLKIT.md               ← SAST commands + CI/CD workflow
│   └── README.md                      ← Task 1 documentation
├── 02_phishing_awareness_module/      ← Task 2: Interactive training platform
│   ├── index.html                     ← Single-file app (6 sections, 50-question quiz)
│   └── README.md                      ← Task 2 documentation
├── 03_network_packet_analyzer/        ← Task 3: Live capture + protocol decode
│   ├── packet_analyzer.py             ← Main analyzer (Scapy-based)
│   ├── simple_capture.py              ← Beginner-friendly capture script
│   ├── demo_analysis.py               ← PCAP analysis example
│   ├── sample_packets.pcap            ← Sample capture for testing
│   ├── requirements.txt               ← pip install -r requirements.txt
│   └── README.md                      ← Task 3 documentation
└── 04_network_ids/                    ← Task 4: Production-grade NIDS stack
    ├── docker-compose.yml             ← One-command full stack deployment
    ├── suricata/                      ← Suricata config + custom rules (50+)
    ├── snort/                         ← Snort config + rules
    ├── alerting/                      ← Alert manager + auto-responders
    ├── visualization/                 ← Grafana dashboards + ELK configs
    ├── scripts/                       ← Install, update, test, manage scripts
    ├── config/                        ← Networks, thresholds, whitelists
    ├── docs/                          ← Architecture, rule writing, playbooks
    └── README.md                      ← Task 4 documentation
```

> **Note:** Folder names are prefixed with `01_`, `02_`, etc. for correct sorting and task ordering.

---

## 🚀 Quick Start — Run Any Task

### Prerequisites
- **Python 3.8+** (Tasks 1, 3)
- **Docker & Docker Compose** (Task 4)
- **Git** (for cloning)
- **Linux/macOS/WSL2** recommended (Windows works with notes per task)

---

### Task 1: Security Code Audit
```bash
cd 01_security_code_audit

# Run vulnerable app (TRAINING ONLY — isolated lab!)
python app.py
# → http://localhost:5000

# Run secure version
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app_secure.py

# Run security scans
pip install bandit semgrep safety pip-audit
bandit -r app.py
semgrep --config=auto app.py
safety check
pip-audit
```

### Task 2: Phishing Awareness Module
```bash
cd 02_phishing_awareness_module

# Open directly in browser — no server needed!
# Double-click index.html OR:
python -m http.server 8080
# → http://localhost:8080
```

### Task 3: Network Packet Analyzer
```bash
cd 03_network_packet_analyzer
pip install -r requirements.txt

# List interfaces
python packet_analyzer.py --list-interfaces

# Live capture (Linux/macOS: sudo | Windows: Admin + Npcap)
sudo python packet_analyzer.py -f "tcp port 80"

# Capture to PCAP
sudo python packet_analyzer.py -c 100 -o capture.pcap

# Analyze PCAP offline
python packet_analyzer.py -r capture.pcap -v
```

### Task 4: Network IDS (NIDS)
```bash
cd 04_network_ids

# One-command full stack deployment
docker-compose up -d

# Verify services
docker-compose ps

# Access dashboards
# Grafana:  http://localhost:3000  (admin / admin)
# Kibana:   http://localhost:5601
# Suricata logs: docker-compose logs -f suricata
```

---

## 🎓 Learning Outcomes

By completing these 4 tasks, I demonstrated proficiency in:

### Technical Skills
- ✅ **OWASP Top 10** — Identification, exploitation, and remediation of 27 vulnerability types
- ✅ **Static Application Security Testing (SAST)** — Bandit, Semgrep, Safety, pip-audit integration
- ✅ **Secure Coding Patterns** — Parameterized queries, output encoding, CSP, input validation, secure defaults
- ✅ **Network Protocol Analysis** — Ethernet, IP, TCP/UDP, DNS, HTTP, TLS packet-level inspection
- ✅ **BPF Filtering** — Capture filters for targeted traffic analysis
- ✅ **Intrusion Detection** — Suricata/Snort rule writing, threshold tuning, false positive reduction
- ✅ **SIEM & Visualization** — Grafana dashboards, ELK stack, log aggregation, alert correlation
- ✅ **Automated Response** — IP blocking, host quarantine, webhook/email/Slack notifications
- ✅ **Containerized Deployment** — Docker Compose multi-service orchestration
- ✅ **Documentation** — Architecture diagrams, runbooks, rule-writing guides, troubleshooting

### Professional Practices
- ✅ **Defense in Depth** — Layered controls: code → network → detection → response
- ✅ **Threat Modeling** — STRIDE-aligned audit methodology
- ✅ **Incident Response Playbooks** — Structured response for SQLi, C2, scanning
- ✅ **CI/CD Security** — Pipeline-integrated SAST with fail-on-critical
- ✅ **Operational Readiness** — Whitelists, monitoring mode, rollback procedures

---

## 📚 Documentation Index

| Document | Description |
|----------|-------------|
| **Task 1** | [`01_security_code_audit/README.md`](01_security_code_audit/README.md) — Vulnerability catalog, run guides, remediation patterns |
| **Task 2** | [`02_phishing_awareness_module/README.md`](02_phishing_awareness_module/README.md) — Module sections, quiz bank, deployment |
| **Task 3** | [`03_network_packet_analyzer/README.md`](03_network_packet_analyzer/README.md) — BPF cheatsheet, protocol support, troubleshooting |
| **Task 4** | [`04_network_ids/README.md`](04_network_ids/README.md) — Full architecture, rule management, dashboards, playbooks |
| **Task 4 Docs** | [`04_network_ids/docs/`](04_network_ids/docs/) — ARCHITECTURE.md, RULE_WRITING.md, RESPONSE_PLAYBOOKS.md, TROUBLESHOOTING.md |

---

## 🛡️ Security & Ethics Notice

> **⚠️ IMPORTANT — READ BEFORE RUNNING**
>
> - **Task 1 (`app.py`)** contains **intentional vulnerabilities** for educational purposes. **NEVER** deploy in production, expose to internet, or use with real data. Run only in isolated lab environments (VM, container, localhost).
> - **Task 3** requires **root/Administrator** privileges for packet capture. Use responsibly — only on networks you own or have explicit permission to monitor.
> - **Task 4 NIDS** — Deploy in **monitor mode first** (no auto-blocking). Test rules thoroughly. Whitelist management access. Have a rollback plan.
> - All code is for **learning and portfolio demonstration**. Follow responsible disclosure if you discover real vulnerabilities.

---

## 🏷️ Tags & Portfolio Links

`#CodeAlpha` `#CyberSecurity` `#Internship` `#AppSec` `#NetSec` `#BlueTeam` `#DetectionEngineering` `#SIEM` `#Python` `#Docker` `#OWASP`

- **LinkedIn Posts:** [Task 1](#) · [Task 2](#) · [Task 3](#) · [Task 4](#) *(add your post URLs)*
- **Video Demos:** [Task 1](#) · [Task 2](#) · [Task 3](#) · [Task 4](#) *(add your video URLs)*

---

## 🙏 Acknowledgments

- **CodeAlpha** — For the structured internship program and practical task design
- **OWASP** — Top 10, Cheat Sheets, and community resources
- **Suricata & Snort Communities** — Rule sets, documentation, and support
- **Open Source Tools** — Scapy, Bandit, Semgrep, Grafana, Elastic, and countless others

---

## 📬 Contact

**Aalekh Kumar**  
🔗 GitHub: [@Aalekh2477](https://github.com/Aalekh2477)  
💼 LinkedIn: [Your LinkedIn URL]  
📧 Email: [Your Email]

---

> **Built with curiosity, secured by practice.**  
> *CodeAlpha Cybersecurity Internship 2026 — Complete*