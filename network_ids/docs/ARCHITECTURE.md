# NIDS Architecture Documentation
# ============================================================

## Overview

This Network Intrusion Detection System (NIDS) provides comprehensive network monitoring, threat detection, and automated response capabilities using industry-standard tools.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NETWORK TRAFFIC                                     │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PACKET CAPTURE LAYER                                  │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │   Suricata       │    │   Snort 3        │    │   Zeek (opt)     │       │
│  │   (Primary)      │    │   (Secondary)    │    │   (Protocol      │       │
│  │   Multi-threaded │    │   (Legacy compat)│    │   Analysis)      │       │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘       │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      RULE PROCESSING & DETECTION                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    RULE ENGINE                                          │   │
│  │  • Signature-based Detection (30,000+ rules)                           │   │
│  │  • Protocol Analysis (HTTP, DNS, TLS, SSH, SMTP, DNS, etc.)          │   │
│  │  • Anomaly Detection (thresholds, baselines)                          │   │
│  │  • File Extraction & Analysis                                          │   │
│  │  • TLS/SSL Inspection                                                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      ALERT PROCESSING PIPELINE                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Deduplication│  │ Enrichment  │  │ Correlation │  │ Routing     │        │
│  │ (5 min)     │  │ GeoIP/TI/   │  │ (Multi-vector│  │ (Severity   │        │
│  └─────────────┘  │  Whois/DNS  │  │  attacks)   │  │  based)     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
         ┌─────────────────┐ ┌───────────┐ ┌──────────────┐
         │ Notifications   │ │ Responses │ │ Visualization│
         │ • Slack         │ │ • Block IP│ │ • Grafana    │
         │ • Email         │ │ • Quarantine│ │ • Kibana     │
         │ • Webhook       │ │ • Rate Limit│ │ • Custom     │
         │ • PagerDuty     │ │ • Rate Limit│ │   Dashboards │
         └─────────────────┘ └───────────┘ └──────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        STORAGE & LONG-TERM RETENTION                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│  │ Elasticsearch│ │ Prometheus   │ │ PostgreSQL   │ │ S3/MinIO     │       │
│  │ (Logs/Alerts)│ │ (Metrics)    │ │ (Config/State)│ │ (PCAP Archive)│       │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Suricata (Primary IDS)
- **Role**: Primary intrusion detection engine
- **Mode**: IDS (monitor) or IPS (inline with NFQUEUE)
- **Threads**: Multi-threaded (auto-scaled to CPU cores)
- **Protocols**: HTTP, DNS, TLS, SSH, SMTP, FTP, SMB, Modbus, DNP3, MQTT, etc.
- **Output**: EVE JSON, Unified2, Fast, HTTP, DNS, TLS, SSH logs
- **Rules**: 30,000+ (Emerging Threats, custom, ThreatFox, Abuse.ch)

### 2. Snort 3 (Secondary IDS)
- **Role**: Secondary detection engine, legacy rule compatibility
- **Mode**: IDS mode
- **Rules**: Community rules + custom local rules
- **Integration**: Unified2 output for compatibility

### 3. Alert Manager
- **Language**: Python 3.11+
- **Functions**:
  - Real-time alert ingestion (EVE JSON, Snort fast/unified2)
  - Deduplication (5-minute window)
  - Enrichment (GeoIP, Threat Intel, WHOIS)
  - Correlation (multi-vector attacks)
  - Routing (severity-based)
  - Notifications (Slack, Email, Webhook, PagerDuty)
  - Automated Response (Block, Quarantine, Rate Limit)

### 4. Automated Responders
| Responder | Action | Integration |
|-----------|--------|-------------|
| Block IP | iptables/nftables | Linux kernel |
| Quarantine Host | VLAN isolation / NAC API | Cisco ISE, Forescout, Aruba |
| Rate Limit | iptables/nftables | Linux kernel |
| Notifications | Slack, Email, Webhook, PagerDuty | REST APIs |

### 5. Visualization Stack
| Component | Purpose | Port |
|-----------|---------|------|
| Grafana | Dashboards & Visualization | 3000 |
| Prometheus | Metrics Collection | 9090 |
| Elasticsearch | Log Storage & Search | 9200 |
| Logstash | Log Processing | 5044/9600 |
| Filebeat | Log Shipping | 5066 |
| Kibana | Log Exploration | 5601 |
| Alert Manager | Alert Processing | 9090 |

## Data Flow

### 1. Packet Capture
```
Network Traffic → NIC (Promiscuous) → AF_PACKET/XDP → Suricata/Snort
```

### 2. Rule Matching
```
Packet → Protocol Parsers → Rule Engine → Match → Alert Generated
```

### 3. Alert Processing
```
Alert → Dedupe → Enrichment (GeoIP/TI) → Correlation → Route → Notify/Respond
```

### 4. Storage
```
EVE JSON → Filebeat → Logstash → Elasticsearch
Metrics → Prometheus → Grafana
Alerts → Alert Manager → PostgreSQL/Elasticsearch
```

### 5. Response
```
Alert → Auto-Response Engine → Block/Quarantine/Rate-Limit → Firewall/NAC
```

## Network Deployment Models

### 1. SPAN/TAP Port (Monitor Mode)
```
Core Switch ──SPAN──► NIDS Sensor
                    (Passive monitoring)
```
**Pros**: No network impact, easy deployment
**Cons**: No blocking capability

### 2. Inline (IPS Mode)
```
Internet ── Firewall ── NIDS (Inline) ── Core Switch
                     (NFQUEUE/AF_PACKET)
```
**Pros**: Can block traffic
**Cons**: Single point of failure, latency

### 3. Hybrid (Recommended)
```
Internet ── Firewall ── NIDS (SPAN) ── Core Switch
                        │
                        ▼
                  Alert Manager
                        │
                        ▼
               Auto-block at Firewall
```
**Pros**: Best of both worlds
**Cons**: Requires firewall API integration

## Deployment Scenarios

### Small Business (< 100 Mbps)
- Single sensor
- Suricata only
- Docker Compose deployment
- Local Elasticsearch/Grafana

### Enterprise (1-10 Gbps)
- Multiple sensors
- Suricata + Snort
- Distributed Elasticsearch cluster
- Dedicated Alert Manager
- NAC integration

### High-Speed (10+ Gbps)
- Multiple sensors with load balancing
- AF_PACKET v3 / XDP / DPDK
- Cluster mode Suricata
- Distributed architecture
- Hardware acceleration (FPGA/DPU)

## Rule Management

### Rule Sources
| Source | Update Frequency | Type |
|--------|------------------|------|
| Emerging Threats Open | Daily | Community |
| Emerging Threats Pro | Daily | Commercial |
| Snort Community | Weekly | Community |
| ThreatFox | Hourly | Malware IOCs |
| Abuse.ch Feodo/SSLBL | Daily | Botnet C2 |
| URLhaus | Hourly | Malware URLs |
| Custom Local | As needed | Organization-specific |

### Rule Categories
| Category | SID Range | Description |
|----------|-----------|-------------|
| Web App Attacks | 1000000-1000099 | SQLi, XSS, CMDi, Path Trav, XXE, SSRF |
| Auth Attacks | 1000100-1000199 | Brute Force, Credential Stuffing |
| Malware/C2 | 1000200-1000299 | Beaconing, DNS Tunneling, Suspicious UA |
| Reconnaissance | 1000300-1000399 | Port Scans, Version Detection |
| Exploits | 1000400-1000499 | Log4Shell, Spring4Shell, ProxyLogon, EternalBlue |
| Data Exfil | 1000500-1000599 | Large Transfer, DNS Exfil, FTP |
| Policy Violations | 1000600-1000699 | Tor, Crypto Mining, P2P, Cloud Storage |
| ICS/OT | 1000700-1000799 | Modbus, DNP3, ENIP |

## Performance Tuning

### Suricata Optimization
```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set: {cpu: [0]}
    - receive-cpu-set: {cpu: [1,2,3]}
    - worker-cpu-set: {cpu: [4-15]}

stream:
  memcap: 256mb
  reassembly:
    memcap: 128mb
    depth: 1mb

app-layer:
  http:
    memcap: 64mb
    request-body-limit: 100kb
```

### Hardware Recommendations
| Throughput | CPU Cores | RAM | NIC | Storage |
|------------|-----------|-----|-----|---------|
| 100 Mbps | 4 | 8 GB | 1 Gbps | 256 GB SSD |
| 1 Gbps | 8 | 16 GB | 10 Gbps | 500 GB NVMe |
| 10 Gbps | 16+ | 64 GB | 25 Gbps | 2 TB NVMe |
| 100 Gbps | 32+ | 128 GB | 100 Gbps | 10 TB NVMe |

## Security Hardening

### Container Security
- Non-root user (suricata/snort)
- Read-only root filesystem
- Dropped capabilities (minimal set)
- Seccomp profile
- AppArmor/SELinux profile

### Network Security
- Dedicated management VLAN
- TLS for all inter-service communication
- Mutual TLS for Elasticsearch/Filebeat
- API authentication for all services

### Access Control
- RBAC for Grafana/Kibana
- SSH key-only access
- MFA for administrative access
- Audit logging for all admin actions

## Monitoring & Alerting

### Key Metrics to Monitor
| Metric | Warning | Critical |
|--------|---------|----------|
| Alert Rate | > 100/min | > 500/min |
| Packet Drop Rate | > 1% | > 5% |
| CPU Usage | > 80% | > 95% |
| Memory Usage | > 80% | > 95% |
| Disk Usage | > 80% | > 95% |
| Rule Reload Failures | > 0 | > 0 |
| Elasticsearch Health | Yellow | Red |

### Log Retention
| Log Type | Retention | Storage |
|----------|-----------|---------|
| EVE JSON | 90 days | Elasticsearch |
| Alert Logs | 1 year | Elasticsearch + PostgreSQL |
| PCAP | 7 days | S3/MinIO |
| Metrics | 2 years | Prometheus |
| System Logs | 30 days | Loki/Elasticsearch |

## Maintenance Procedures

### Daily
- [ ] Check service health
- [ ] Review critical alerts
- [ ] Verify rule updates
- [ ] Check disk space

### Weekly
- [ ] Review false positives
- [ ] Update threat intelligence
- [ ] Review rule performance
- [ ] Check backup integrity

### Monthly
- [ ] Rule optimization
- [ ] Capacity planning
- [ ] Security patches
- [ ] Penetration testing

## Disaster Recovery

### RTO/RPO Targets
| Component | RTO | RPO |
|-----------|-----|-----|
| Suricata/Snort | 5 min | 0 min |
| Alert Manager | 10 min | 5 min |
| Elasticsearch | 30 min | 1 hour |
| Grafana/Prometheus | 15 min | 1 hour |
| Config/State | 1 hour | 24 hours |

### Backup Strategy
- **Config**: Daily to offsite
- **Elasticsearch**: Snapshot every 6 hours
- **PostgreSQL**: Continuous WAL archiving
- **PCAP Archive**: 7-day rolling to S3

## Compliance Mapping

| Framework | Controls Addressed |
|-----------|-------------------|
| NIST CSF | ID.SC-4, DE.CM-1, DE.CM-4, DE.CM-7, RS.AN-1, RS.AN-5 |
| PCI DSS | 10.2.1, 10.2.2, 10.3, 11.4, 11.5 |
| ISO 27001 | A.12.4.1, A.12.4.3, A.13.1.1, A.13.2.1 |
| MITRE ATT&CK | Detection coverage for 150+ techniques |

---

*Document Version: 1.0 | Last Updated: 2024*