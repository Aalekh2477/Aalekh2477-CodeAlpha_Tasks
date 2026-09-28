# Task 04 — Network Intrusion Detection System (NIDS)

> **CodeAlpha Cybersecurity Internship** | Blue Team / Detection Engineering  
> **Difficulty:** ⭐⭐⭐⭐ Advanced | **Estimated Time:** 12–20 hours

---

## 🎯 Objective

Deploy a **complete, production-grade NIDS stack** using **Suricata** (primary) and **Snort** (alternative) with custom rules, multi-channel alerting, automated response, and full observability (Grafana + ELK). Containerized with Docker Compose for one-command deployment.

---

## 📂 Folder Structure

```
04_network_ids/
├── docker-compose.yml              # Full stack: Suricata, Snort, Alert Manager, Grafana, Prometheus, Loki, ELK
├── suricata/
│   ├── suricata.yaml              # Main configuration
│   ├── rules/
│   │   ├── local.rules            # 50+ custom rules (SQLi, XSS, RCE, C2, scan, brute, exfil)
│   │   ├── emerging-threats/      # ET Open rules (auto-updated)
│   │   └── threatfox/             # ThreatFox IOCs (auto-updated)
│   └── logs/                      # eve.json, fast.log, stats.log
├── snort/
│   ├── snort.conf                 # Snort configuration
│   ├── rules/
│   │   ├── local.rules            # Custom Snort rules
│   │   └── community/             # Community rules
│   └── logs/
├── alerting/
│   ├── alert_manager.py           # Alert processing, deduplication, routing
│   ├── config.yaml                # Thresholds, notification channels, auto-response triggers
│   ├── responders/
│   │   ├── block_ip.py            # Auto-block via iptables/nftables
│   │   ├── quarantine_host.py     # Host isolation (VLAN move, firewall)
│   │   ├── notify_slack.py        # Slack webhook notifications
│   │   ├── notify_email.py        # SMTP email alerts
│   │   └── webhook.py             # Generic webhook (SOAR, ticketing)
│   └── Dockerfile
├── visualization/
│   ├── grafana/
│   │   ├── dashboards/
│   │   │   └── nids-overview.json # Pre-built: Overview, Alerts, Threat Map, Protocol, Host, Rule Effectiveness
│   │   └── datasources.yaml       # Prometheus + Loki config
│   └── elk/
│       ├── filebeat.yml           # Log shipping (Suricata EVE JSON → Elasticsearch)
│       ├── logstash.conf          # Parsing, enrichment, GeoIP
│       └── kibana.ndjson          # Saved searches, visualizations, dashboards
├── scripts/
│   ├── install_suricata.sh        # Linux bare-metal install
│   ├── install_snort.sh           # Linux bare-metal install
│   ├── update_rules.sh            # Rule update automation (ET, ThreatFox, Community)
│   ├── test_rules.sh              # Syntax validation before deploy
│   └── manage_service.sh          # Start/stop/restart/status
├── config/
│   ├── networks.yaml              # Home/external networks, interfaces, HOME_NET
│   ├── thresholds.yaml            # Alert thresholds (scan: 10/60s, brute: 5/300s, SQLi: 3/60s)
│   └── whitelist.yaml             # Management IPs, internal CIDRs, rule exemptions
├── docs/
│   ├── ARCHITECTURE.md            # System design, data flow, component interactions
│   ├── RULE_WRITING.md            # Suricata/Snort rule syntax, keywords, testing, best practices
│   ├── RESPONSE_PLAYBOOKS.md      # SQLi, C2, Port Scan, Brute Force, Data Exfil playbooks
│   └── TROUBLESHOOTING.md         # Common issues, performance tuning, log locations
└── README.md                       # This file
```

---

## 🚀 Quick Start

### Prerequisites
- **Docker** ≥ 20.10 + **Docker Compose** ≥ 2.0
- **Linux** (native) or **Windows/WSL2** or **macOS** (Docker Desktop)
- Minimum **4 GB RAM**, **2 CPU cores**, **10 GB disk**

### 1️⃣ One-Command Deployment
```bash
cd 04_network_ids

# Start full stack (detached)
docker-compose up -d

# Verify all services healthy
docker-compose ps
# Expected: suricata, snort, alert-manager, grafana, prometheus, loki, elasticsearch, logstash, kibana, filebeat → "Up" / "healthy"
```

### 2️⃣ Access Dashboards
| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | admin / admin |
| **Kibana** | http://localhost:5601 | (no auth by default) |
| **Prometheus** | http://localhost:9090 | — |
| **Alert Manager** | http://localhost:9093 | — |

### 3️⃣ View Live Logs
```bash
# Suricata EVE JSON (structured alerts)
docker-compose logs -f suricata

# Alert Manager
docker-compose logs -f alert-manager

# All services
docker-compose logs -f
```

### 4️⃣ Stop & Cleanup
```bash
# Stop (preserves data volumes)
docker-compose down

# Stop + remove volumes (full reset)
docker-compose down -v
```

---

## ⚙️ Configuration Guide

### Network Interfaces (`config/networks.yaml`)
```yaml
networks:
  - name: "LAN"
    interface: "eth0"              # Capture interface
    cidr: "192.168.1.0/24"         # Local network
    home_net: "192.168.1.0/24"     # Suricata HOME_NET
    external_net: "!$HOME_NET"     # Everything else
```
> **Edit this first!** Match your actual network interface and CIDR.

### Alert Thresholds (`config/thresholds.yaml`)
```yaml
thresholds:
  port_scan:
    count: 10          # Unique destination ports
    window: 60         # Within 60 seconds
  brute_force:
    count: 5           # Failed attempts
    window: 300        # Within 5 minutes
  sql_injection:
    count: 3           # SQLi rule matches
    window: 60         # Within 1 minute
  c2_beaconing:
    count: 10          # Beacons to same destination
    window: 60         # Within 1 minute
  data_exfil:
    count: 100         # MB transferred
    window: 3600       # Within 1 hour
```

### Whitelists (`config/whitelist.yaml`)
```yaml
whitelist:
  ips:
    - "192.168.1.100"      # Management workstation
    - "10.0.0.0/8"         # Entire internal network
  domains:
    - "internal.company.com"
  rules:
    - "2000001"            # Disable specific rule ID (false positive)
```

### Notification Channels (`alerting/config.yaml`)
```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    channel: "#security-alerts"
    severity_threshold: "medium"

  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "alerts@company.com"
    password: "${EMAIL_PASSWORD}"  # Use env var!
    recipients:
      - "security@company.com"
      - "oncall@company.com"

  webhook:
    enabled: true
    url: "https://soar.company.com/api/alerts"
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
```

### Automated Responses (`alerting/config.yaml`)
```yaml
responses:
  auto_block:
    enabled: true
    triggers:
      - rule_id: 1000001    # SQL Injection
        action: block_ip
        duration: 3600      # 1 hour
      - rule_id: 1000003    # C2 Beaconing
        action: quarantine_host
        duration: 86400     # 24 hours

  rate_limit:
    enabled: true
    threshold: 100          # Alerts per minute
    window: 60
    action: rate_limit_ip
```

---

## 📝 Custom Rules (50+ Included)

### Suricata — `suricata/rules/local.rules`
```suricata
# SQL Injection
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"WEB-APP SQL Injection Attempt";
    flow:to_server,established;
    content:"union select"; nocase;
    content:"from"; nocase; distance:0;
    classtype:web-application-attack;
    sid:1000001; rev:1;
)

# Command Injection
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"WEB-APP Command Injection";
    flow:to_server,established;
    pcre:"/[;&|`$\(\)]/";
    classtype:web-application-attack;
    sid:1000002; rev:1;
)

# C2 Beaconing (periodic callbacks)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE C2 Beaconing";
    flow:to_server,established;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity;
    sid:1000003; rev:1;
)

# Data Exfiltration (large POST)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"DATA-EXFIL Large HTTP POST";
    flow:to_server,established;
    http.method; content:"POST";
    http.request_body_len; >:1000000;  # 1MB+
    classtype:data-exfiltration;
    sid:1000004; rev:1;
)
```

### Snort — `snort/rules/local.rules`
```snort
# Port Scan Detection
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SCAN Port Scan Detected";
    flags:S;
    threshold:type both, track by_src, count 20, seconds 60;
    classtype:attempted-recon;
    sid:1000001; rev:1;
)

# Brute Force SSH
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"BRUTE-FORCE SSH Login Attempts";
    flow:to_server,established;
    content:"SSH"; nocase;
    threshold:type both, track by_src, count 10, seconds 300;
    classtype:attempted-admin;
    sid:1000002; rev:1;
)
```

---

## 🔔 Alerting & Response

### Manual Response Commands
```bash
# Block IP manually (1 hour)
python3 alerting/responders/block_ip.py --ip 192.168.1.50 --duration 3600 --reason "SQL Injection"

# Quarantine host (24 hours)
python3 alerting/responders/quarantine_host.py --ip 192.168.1.50 --duration 86400

# View currently blocked IPs
python3 alerting/responders/block_ip.py --list

# Unblock IP
python3 alerting/responders/block_ip.py --unblock 192.168.1.50
```

### Alert Flow
```
Suricata/Snort → eve.json / unified2
       ↓
Filebeat → Logstash (parse, enrich, GeoIP)
       ↓
Elasticsearch (index: suricata-*)
       ↓
Alert Manager (reads eve.json via tail)
       ↓
├── Deduplication & Threshold Check
├── Severity Routing (Slack/Email/Webhook)
└── Auto-Response (block_ip, quarantine_host)
```

---

## 📊 Grafana Dashboards (Pre-Built)

Access: **http://localhost:3000** (admin/admin)

| Dashboard | Purpose |
|-----------|---------|
| **Network Overview** | Traffic volume, protocol breakdown, top talkers, connection states |
| **Alert Timeline** | Real-time alert feed with severity color-coding, searchable |
| **Threat Map** | GeoIP visualization of attackers (source country map) |
| **Protocol Analysis** | Deep-dive: HTTP methods, DNS query types, TLS versions, JA3 fingerprints |
| **Host Behavior** | Per-host anomaly detection: connections, bytes, alert count, entropy |
| **Rule Effectiveness** | Triggered rules, false positive rate, top firing rules, tuning candidates |

---

## 🔄 Rule Management

### Update Rules Automatically
```bash
# Update all rule sets
./scripts/update_rules.sh

# Update specific set
./scripts/update_rules.sh --set emerging-threats
./scripts/update_rules.sh --set threatfox
./scripts/update_rules.sh --set community
```

### Test Rules Before Deploy
```bash
# Validate Suricata config + rules
suricata -T -c /etc/suricata/suricata.yaml -v

# Validate Snort config + rules
snort -T -c /etc/snort/snort.conf

# Test specific rule file
./scripts/test_rules.sh suricata/rules/local.rules
```

### Add Custom Rule (Hot Reload)
```bash
# Append rule
echo 'alert http any any -> any any (msg:"Custom Rule"; content:"evil.com"; sid:9999999;)' >> suricata/rules/local.rules

# Reload Suricata rules (no restart!)
kill -USR2 $(pidof suricata)
```

---

## 📋 Monitoring & Maintenance

### Log Locations (Inside Containers)
| Component | Path |
|-----------|------|
| Suricata EVE JSON | `/var/log/suricata/eve.json` |
| Suricata Fast Log | `/var/log/suricata/fast.log` |
| Snort Unified2 | `/var/log/snort/alert` |
| Alert Manager | `/var/log/nids/alert_manager.log` |
| Responders | `/var/log/nids/responders.log` |

### Key Metrics to Monitor
```bash
# Alert rate per minute
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")' | wc -l

# Top attacking IPs
jq -r '.src_ip' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -20

# Rule trigger frequency
jq -r '.alert.signature_id' /var/log/suricata/eve.json | sort | uniq -c | sort -rn

# Unique destinations per source (beaconing detection)
jq -r '.src_ip + " " + .dest_ip' /var/log/suricata/eve.json | sort -u | cut -d' ' -f1 | uniq -c | sort -rn
```

### Health Checks
```bash
# Service status
docker-compose ps

# Rule count loaded
docker-compose exec suricata suricata -c /etc/suricata/suricata.yaml --dump-config | grep -c "rule"

# Interface capture verification
docker-compose exec suricata suricata -c /etc/suricata/suricata.yaml --list-interfaces

# Disk usage
docker system df
```

---

## 📚 Documentation Deep-Dive

| Doc | Description |
|-----|-------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component diagram, data flow, network topology, scaling considerations |
| [`docs/RULE_WRITING.md`](docs/RULE_WRITING.md) | Suricata/Snort syntax, keywords (content, pcre, threshold, flow), testing, performance |
| [`docs/RESPONSE_PLAYBOOKS.md`](docs/RESPONSE_PLAYBOOKS.md) | Step-by-step: SQLi, C2, Port Scan, Brute Force, Data Exfil, Malware Delivery |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | No alerts, high FP, performance, rule loading, missing logs, Windows/WSL issues |

---

## 🚨 Incident Response Playbooks (Summary)

### Playbook 1: SQL Injection Alert
1. Verify in Grafana Alert Timeline
2. Check source IP reputation (AbuseIPDB, VirusTotal)
3. Review HTTP request payload (Kibana Discover → `http.request_body`)
4. Block IP if confirmed: `block_ip.py --ip <IP> --duration 3600`
5. Notify application team for WAF rule update
6. Document in incident tracker

### Playbook 2: C2 Communication
1. Isolate host from network (quarantine VLAN or `quarantine_host.py`)
2. Capture memory dump (Volatility/LiME)
3. Block C2 domain/IP at perimeter firewall
4. Run malware scan (EDR/AV)
5. Reimage if confirmed compromised
6. Threat intel sharing (MISP, OpenCTI)

### Playbook 3: Port Scan
1. Identify scanner IP
2. Check for follow-up exploit attempts (same IP → vuln rules)
3. Rate-limit or block at perimeter
4. Monitor for lateral movement (internal → internal alerts)
5. Update honeypot/deception rules

---

## 🛠️ Troubleshooting Quick Reference

| Issue | Likely Cause | Fix |
|-------|--------------|-----|
| **No alerts** | Wrong interface, promiscuous mode off, BPF filter too restrictive | Check `config/networks.yaml`, verify interface in container |
| **High false positives** | Thresholds too low, missing whitelists, noisy rules | Tune `thresholds.yaml`, add to `whitelist.yaml`, disable rule IDs |
| **Performance issues** | Single-threaded, no AF_PACKET, too many rules | Enable `af-packet` in suricata.yaml, tune thread affinity, reduce rule set |
| **Rules not loading** | Syntax error, missing dependencies | Run `suricata -T -c suricata.yaml` |
| **Missing logs** | Filebeat not shipping, permission denied | Check filebeat.yml paths, `docker-compose logs filebeat` |
| **Grafana no data** | Prometheus not scraping, Loki not receiving | Verify targets in Prometheus UI, check Loki labels |

---

## 📚 Learning Resources

| Topic | Resource |
|-------|----------|
| Suricata User Guide | https://suricata.readthedocs.io/ |
| Snort Manual | https://www.snort.org/documents |
| Emerging Threats Rules | https://rules.emergingthreats.net/ |
| ThreatFox IOCs | https://threatfox.abuse.ch/ |
| Grafana Dashboards | https://grafana.com/grafana/dashboards/ |
| Elastic SIEM Guide | https://www.elastic.co/guide/en/security/current/index.html |
| MITRE ATT&CK | https://attack.mitre.org/ |
| Detection Engineering | https://detectionengineering.net/ |

---

## ⚠️ Security & Operational Notes

> **⚠️ CRITICAL — READ BEFORE PRODUCTION USE**
>
> 1. **Start in MONITOR MODE** — Disable `auto_block` in `alerting/config.yaml` initially
> 2. **Whitelist management access** — Add your IP/CIDR to `config/whitelist.yaml` before enabling auto-response
> 3. **Test rules thoroughly** — Use `suricata -T` and `./scripts/test_rules.sh` before deploy
> 4. **Monitor resources** — Suricata + ELK + Grafana = significant CPU/RAM. Allocate 4GB+ RAM.
> 5. **Regular rule updates** — Schedule `./scripts/update_rules.sh` via cron (daily)
> 6. **Have rollback plan** — `docker-compose down` + `iptables -F` to emergency-clear blocks
> 7. **Log retention** — Configure logrotate for `/var/log/suricata/` and Elasticsearch ILM policies
> 8. **Encryption** — Use TLS for all inter-service communication in production

---

## ✅ Submission Deliverables

- [ ] `docker-compose.yml` + all configs pushed to GitHub
- [ ] Custom rules (`suricata/rules/local.rules`, `snort/rules/local.rules`) — 50+ rules
- [ ] Alerting config with Slack/Email/Webhook examples
- [ ] Auto-response scripts (block_ip, quarantine_host, notify_*)
- [ ] Grafana dashboard JSON (`visualization/grafana/dashboards/nids-overview.json`)
- [ ] ELK configs (Filebeat, Logstash, Kibana saved objects)
- [ ] Documentation: ARCHITECTURE, RULE_WRITING, RESPONSE_PLAYBOOKS, TROUBLESHOOTING
- [ ] LinkedIn post with: Grafana screenshot, rule example, architecture diagram
- [ ] Video demo (3 min): `docker-compose up` → Grafana tour → alert trigger → auto-response
- [ ] CodeAlpha submission form completed

---

## 🔗 Navigation

← **Task 03** [`../03_network_packet_analyzer/README.md`](../03_network_packet_analyzer/README.md) | **Master README** [`../README.md`](../README.md)

---

## 🏁 Final Note

This NIDS represents the **capstone** of the CodeAlpha cybersecurity internship — combining application security, network analysis, detection engineering, and security operations into one deployable stack. Each component is modular and production-ready with proper documentation for handoff.

**Built with:** Suricata, Snort, Docker, Grafana, Prometheus, Loki, Elasticsearch, Logstash, Kibana, Python, YAML, Bash

**#CodeAlpha #CyberSecurity #NIDS #Suricata #Snort #SIEM #BlueTeam #DetectionEngineering #Docker #Grafana #ELK**