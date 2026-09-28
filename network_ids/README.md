# Network Intrusion Detection System (NIDS)

A complete NIDS implementation using **Suricata** (primary) and **Snort** (alternative) with custom rules, alerting, automated response, and visualization.

## 🎯 Features

- **Dual Engine**: Suricata (modern, multi-threaded) + Snort (legacy compatibility)
- **Custom Rules**: 50+ rules for common attacks (SQLi, XSS, RCE, C2, scanning, etc.)
- **Real-time Alerts**: Email, Slack, Syslog, Webhook notifications
- **Automated Response**: IP blocking, session termination, quarantine
- **Visualization**: Grafana dashboards + ELK stack integration
- **Containerized**: Docker Compose for easy deployment
- **Cross-platform**: Linux primary, Windows via WSL/Docker

## 📁 Project Structure

```
network_ids/
├── docker-compose.yml           # Full stack deployment
├── suricata/
│   ├── suricata.yaml           # Main configuration
│   ├── rules/
│   │   ├── local.rules         # Custom rules
│   │   ├── emerging-threats/   # ET rules (auto-updated)
│   │   └── threatfox/          # ThreatFox IOCs
│   └── logs/
├── snort/
│   ├── snort.conf              # Snort configuration
│   ├── rules/
│   │   ├── local.rules         # Custom rules
│   │   └── community/          # Community rules
│   └── logs/
├── alerting/
│   ├── alert_manager.py        # Alert processing & notification
│   ├── responders/
│   │   ├── block_ip.py         # Auto-block IPs (iptables/nftables)
│   │   ├── quarantine_host.py  # Quarantine compromised hosts
│   │   ├── notify_slack.py     # Slack notifications
│   │   ├── notify_email.py     # Email alerts
│   │   └── webhook.py          # Generic webhook
│   └── config.yaml             # Alert thresholds & routing
├── visualization/
│   ├── grafana/
│   │   ├── dashboards/         # Pre-built dashboards
│   │   └── datasources.yaml    # Prometheus/Loki config
│   └── elk/
│       ├── filebeat.yml        # Log shipping
│       ├── logstash.conf       # Log parsing
│       └── kibana.ndjson       # Saved objects
├── scripts/
│   ├── install_suricata.sh     # Linux installation
│   ├── install_snort.sh        # Linux installation
│   ├── update_rules.sh         # Rule update automation
│   ├── test_rules.sh           # Rule testing
│   └── manage_service.sh       # Service management
├── config/
│   ├── networks.yaml           # Network definitions
│   ├── thresholds.yaml         # Alert thresholds
│   └── whitelist.yaml          # IP/domain whitelists
└── docs/
    ├── ARCHITECTURE.md
    ├── RULE_WRITING.md
    ├── RESPONSE_PLAYBOOKS.md
    └── TROUBLESHOOTING.md
```

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone and start full stack
cd network_ids
docker-compose up -d

# Verify services
docker-compose ps
docker-compose logs -f suricata
```

### Option 2: Native Linux Installation

```bash
# Run installation scripts (Ubuntu/Debian)
sudo ./scripts/install_suricata.sh
sudo ./scripts/install_snort.sh

# Start services
sudo systemctl enable --now suricata
sudo systemctl enable --now snort
```

### Option 3: Windows (via WSL2/Docker)

```powershell
# Enable WSL2 and install Ubuntu
wsl --install

# Then run Linux installation inside WSL
# OR use Docker Desktop:
docker-compose up -d
```

## ⚙️ Configuration

### Network Interfaces

Edit `config/networks.yaml`:
```yaml
networks:
  - name: "LAN"
    interface: "eth0"
    cidr: "192.168.1.0/24"
    home_net: "192.168.1.0/24"
    external_net: "!$HOME_NET"
```

### Alert Thresholds

Edit `config/thresholds.yaml`:
```yaml
thresholds:
  port_scan:
    count: 10
    window: 60
  brute_force:
    count: 5
    window: 300
  sql_injection:
    count: 3
    window: 60
```

### Whitelists

Edit `config/whitelist.yaml`:
```yaml
whitelist:
  ips:
    - "192.168.1.100"  # Management station
    - "10.0.0.0/8"     # Internal network
  domains:
    - "internal.company.com"
  rules:
    - "2000001"  # Disable specific rule
```

## 📝 Custom Rules

### Suricata Rules (`suricata/rules/local.rules`)

```bash
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

# C2 Beaconing
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE C2 Beaconing";
    flow:to_server,established;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity;
    sid:1000003; rev:1;
)
```

### Snort Rules (`snort/rules/local.rules`)

```bash
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

## 🔔 Alerting & Response

### Notification Channels

Configure in `alerting/config.yaml`:
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
    password: "${EMAIL_PASSWORD}"
    recipients:
      - "security@company.com"
      - "oncall@company.com"

  webhook:
    enabled: true
    url: "https://soc.company.com/api/alerts"
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
```

### Automated Responses

```yaml
# alerting/config.yaml
responses:
  auto_block:
    enabled: true
    triggers:
      - rule_id: 1000001  # SQL Injection
        action: block_ip
        duration: 3600
      - rule_id: 1000003  # C2 Beaconing
        action: quarantine_host
        duration: 86400

  rate_limit:
    enabled: true
    threshold: 100
    window: 60
    action: rate_limit_ip
```

### Manual Response Commands

```bash
# Block IP manually
python3 alerting/responders/block_ip.py --ip 192.168.1.50 --duration 3600 --reason "SQL Injection"

# Quarantine host
python3 alerting/responders/quarantine_host.py --ip 192.168.1.50 --duration 86400

# View blocked IPs
python3 alerting/responders/block_ip.py --list

# Unblock IP
python3 alerting/responders/block_ip.py --unblock 192.168.1.50
```

## 📊 Visualization

### Grafana Dashboards

Access: `http://localhost:3000` (admin/admin)

Pre-built dashboards:
- **Network Overview**: Traffic volume, protocols, top talkers
- **Alert Timeline**: Real-time alert feed with severity
- **Threat Map**: GeoIP visualization of attacks
- **Protocol Analysis**: Deep-dive into HTTP, DNS, TLS
- **Host Behavior**: Anomaly detection per host
- **Rule Effectiveness**: Triggered rules, false positives

### ELK Stack

Access Kibana: `http://localhost:5601`

Indexes:
- `suricata-*`: All Suricata logs (EVE JSON)
- `snort-*`: Snort unified2 logs
- `alerts-*`: Processed alerts

## 🔧 Rule Management

### Update Rules Automatically

```bash
# Update all rule sets
./scripts/update_rules.sh

# Update specific rule set
./scripts/update_rules.sh --set emerging-threats
./scripts/update_rules.sh --set threatfox
./scripts/update_rules.sh --set community
```

### Test Rules Before Deployment

```bash
# Test Suricata rules
suricata -T -c /etc/suricata/suricata.yaml -v

# Test Snort rules
snort -T -c /etc/snort/snort.conf

# Validate specific rule file
./scripts/test_rules.sh suricata/rules/local.rules
```

## 📋 Monitoring & Maintenance

### Log Locations

| Component | Log Path |
|-----------|----------|
| Suricata | `/var/log/suricata/eve.json` |
| Snort | `/var/log/snort/alert` |
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
```

### Health Checks

```bash
# Service status
systemctl status suricata snort alert-manager

# Rule count
suricata -c /etc/suricata/suricata.yaml --dump-config | grep -c "rule"

# Interface capture
suricata -c /etc/suricata/suricata.yaml --list-interfaces
```

## 🔄 Rule Sources

### Auto-Updated Sources

| Source | Frequency | Description |
|--------|-----------|-------------|
| Emerging Threats | Daily | Community rules |
| ThreatFox | Hourly | Malware IOCs |
| Abuse.ch | Daily | Malware URLs/IPs |
| Snort Community | Weekly | Official Snort rules |
| ET Pro | Daily | Proofpoint rules (paid) |

### Manual Rule Addition

```bash
# Add custom rule
echo 'alert http any any -> any any (msg:"Custom Rule"; content:"evil.com"; sid:9999999;)' >> suricata/rules/local.rules

# Reload rules (no restart needed for Suricata)
kill -USR2 $(pidof suricata)
```

## 🚨 Incident Response Playbooks

### Playbook 1: SQL Injection Alert
1. Verify alert in dashboard
2. Check source IP reputation
3. Review HTTP request payload
4. Block IP if confirmed malicious
5. Notify application team
6. Update WAF rules

### Playbook 2: C2 Communication
1. Isolate host from network
2. Capture memory dump
3. Block C2 domain/IP at firewall
4. Run malware scan
5. Reimage if confirmed

### Playbook 3: Port Scan
1. Identify scanner IP
2. Check for follow-up exploits
3. Rate-limit or block at perimeter
4. Monitor for lateral movement

## 🛠️ Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| No alerts | Check interface, promiscuous mode, BPF filter |
| High false positives | Tune thresholds, add whitelists, adjust rules |
| Performance issues | Enable AF_PACKET, tune thread count, use XDP |
| Rules not loading | Check syntax: `suricata -T -c config.yaml` |
| Missing logs | Check file permissions, log rotation config |

### Performance Tuning

```yaml
# suricata.yaml
threading:
  set-cpu-affinity: true
  cpu-affinity:
    - management-cpu-set:
        cpu: [0]
    - receive-cpu-set:
        cpu: [1,2,3,4]
    - worker-cpu-set:
        cpu: [5,6,7,8,9,10,11,12,13,14,15]

default-packet-size: 1518
max-pending-packets: 10000
```

## 📚 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Rule Writing Guide](docs/RULE_WRITING.md)
- [Response Playbooks](docs/RESPONSE_PLAYBOOKS.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)

## ⚠️ Security Notes

> **⚠️ WARNING:** The vulnerable `app.py` from the security audit task contains intentional security flaws. NEVER deploy it in production. Use only in isolated lab environments for security training.

> **NIDS Deployment Warning:** 
> - Run NIDS in **monitor mode** first (no blocking)
> - Test rules thoroughly before enabling auto-response
> - Ensure management access is whitelisted
> - Monitor resource usage (CPU/Memory/Network)
> - Regular rule updates are critical
> - Have rollback plan for auto-blocking

## 📄 License

MIT License - Feel free to use for educational and commercial purposes.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add rules/improvements
4. Test thoroughly
5. Submit PR

---

**Stay Vigilant, Stay Secure** 🛡️