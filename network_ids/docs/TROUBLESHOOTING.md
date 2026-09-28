# NIDS Troubleshooting Guide
# ============================================================

## Quick Diagnostics

### Service Health Check
```bash
# Check all NIDS services
./scripts/manage_service.sh check

# Individual service status
systemctl status suricata
systemctl status snort
systemctl status alert-manager
systemctl status filebeat
systemctl status logstash
systemctl status elasticsearch
systemctl status kibana
systemctl status grafana
systemctl status prometheus
```

### Quick Health Verification
```bash
# Suricata
suricata -T -c /etc/suricata/suricata.yaml
suricata --build-info

# Snort
snort -T -c /etc/snort/snort.conf
snort -V

# Elasticsearch
curl -s http://localhost:9200/_cluster/health | jq .

# Grafana
curl -s http://localhost:3000/api/health
```

---

## Common Issues & Solutions

### 1. Suricata Issues

#### Suricata Won't Start
```
# Check configuration syntax
suricata -T -c /etc/suricata/suricata.yaml -v

# Check logs
journalctl -u suricata -n 50
tail -50 /var/log/suricata/suricata.log

# Common causes:
# 1. Configuration syntax error
# 2. Interface not found
# 3. Permission denied on interface
# 4. Rules syntax error
# 5. Insufficient memory for memcap
```

#### Suricata High CPU Usage
```bash
# Check thread affinity
cat /etc/suricata/suricata.yaml | grep -A 20 "threading:"

# Reduce worker threads
# Adjust in suricata.yaml:
# threading:
#   cpu-affinity:
#     worker-cpu-set:
#       cpu: [4,5,6,7]  # Reduce from 12 to 4 cores

# Check packet drop rate
suricata -c /etc/suricata/suricata.yaml --dump-config | grep -i drop
```

#### Suricata Dropping Packets
```bash
# Check stats
tail -f /var/log/suricata/stats.log | jq -r '.decoder | to_entries[] | "\(.key): \(.value)"'

# Increase buffer sizes
# In suricata.yaml:
# af-packet:
#   - interface: eth0
#     buffer-size: 67108864   # 64MB
#     block-size: 1048576     # 1MB
#     block-timeout: 100
#     ring-size: 200000

# Enable XDP (Linux 4.18+)
# af-packet:
#   use-mmap: yes
#   xdp-mode: driver
```

#### Suricata Not Generating Alerts
```bash
# Check if rules loaded
suricata -c /etc/suricata/suricata.yaml --dump-config | grep -c "rule"

# Check rule syntax
suricata -T -c /etc/suricata/suricata.yaml

# Check rule matching
suricata -c /etc/suricata/suricata.yaml -r test.pcap -l /tmp/test -k none

# Check rule file permissions
ls -la /etc/suricata/rules/
```

#### High Memory Usage
```bash
# Check memcap settings
grep -r "memcap" /etc/suricata/suricata.yaml

# Reduce memcap values
# stream.memcap: 128mb
# detect-engine.memcap: 512mb
# defrag.memcap: 32mb
```

### 2. Snort Issues

#### Snort Won't Start
```bash
# Test configuration
snort -T -c /etc/snort/snort.conf

# Check DAQ module
snort --daq-list

# Check interface
snort --interface-list
```

#### Snort Not Seeing Traffic
```bash
# Check interface in promiscuous mode
ip link set eth0 promisc on

# Check BPF filter
snort -c /etc/snort/snort.conf -i eth0 --daq-var buffer_size=16777216
```

### 3. Alert Manager Issues

#### Alerts Not Processing
```bash
# Check alert manager logs
journalctl -u alert-manager -n 100

# Check EVE log tail
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Check queue
ls -la /var/log/suricata/
```

#### Notifications Not Sending
```bash
# Test Slack
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test alert from NIDS"}' \
  $SLACK_WEBHOOK_URL

# Test Email
python3 -c "
import smtplib
from email.mime.text import MIMEText
msg = MIMEText('Test')
msg['Subject'] = 'Test'
msg['From'] = 'nids@company.com'
msg['To'] = 'test@company.com'
s = smtplib.SMTP('smtp.gmail.com', 587)
s.starttls()
s.login('user', 'pass')
s.send_message(msg)
s.quit()
"
```

#### Automated Responses Not Triggering
```bash
# Check responder scripts
python3 /app/responders/block_ip.py --ip 192.168.1.100 --duration 60 --reason "Test"

# Check permissions
ls -la /app/responders/

# Check sudoers for iptables
sudo -l
```

### 4. Elasticsearch/Logstash Issues

#### Elasticsearch Not Starting
```bash
# Check JVM heap
cat /etc/elasticsearch/jvm.options | grep -E "Xms|Xmx"

# Check disk space
df -h /var/lib/elasticsearch

# Check logs
journalctl -u elasticsearch -n 50
```

#### Logstash Pipeline Issues
```bash
# Test pipeline
/usr/share/logstash/bin/logstash --config.test_and_exit -f /usr/share/logstash/pipeline/logstash.conf

# Check pipeline stats
curl -s http://localhost:9600/_node/stats/pipelines | jq .

# Check dead letter queue
ls -la /usr/share/logstash/data/dead_letter_queue/
```

#### Filebeat Not Shipping
```bash
# Test connection
filebeat test config
filebeat test output

# Check registry
cat /var/lib/filebeat/registry/filebeat/log.json | jq .

# Check logs
journalctl -u filebeat -n 50
```

### 4. Network/Interface Issues

#### Interface Not in Promiscuous Mode
```bash
# Enable promiscuous mode
ip link set eth0 promisc on

# Verify
ip link show eth0 | grep PROMISC

# Make persistent
cat > /etc/systemd/network/99-promiscuous.network << EOF
[Match]
Name=eth0

[Network]
DHCP=no

[Link]
Promiscuous=yes
EOF
```

#### BPF Filter Issues
```bash
# Test BPF filter
tcpdump -i eth0 -n "tcp port 80" -c 5

# Check Suricata BPF
grep -A 5 "bpf-filter" /etc/suricata/suricata.yaml

# Disable BPF for testing
# bpf-filter: ""
```

### 5. Rule/Performance Issues

#### High False Positive Rate
```bash
# Check false positive sources
# 1. Legitimate traffic matching rules
# 2. Overly broad rules
# 3. Missing whitelists

# Tune thresholds
# In thresholds.yaml:
# rules:
#   "1000001":
#     threshold:
#       count: 10
#       window: 300

# Add whitelists
# In whitelist.yaml:
# ips:
#   - "192.168.1.100"  # Legitimate scanner
```

#### Rule Performance Degradation
```bash
# Profile rules
suricata -c /etc/suricata/suricata.yaml -r traffic.pcap \
  --set profiling.rules.enabled=yes \
  --set profiling.keywords.enabled=yes

# Check rule performance
cat /var/log/suricata/rule_perf.log | head -30

# Disable expensive rules
# Rule tuning:
# - Remove unnecessary PCRE
# - Add fast_pattern
# - Use content instead of pcre where possible
```

### 6. Container/Docker Issues

#### Container Won't Start
```bash
# Check logs
docker-compose logs suricata

# Check permissions
ls -la /etc/suricata/ /var/log/suricata/

# Check capabilities
docker inspect nids-suricata | jq '.[0].HostConfig.CapAdd'
```

#### Network Issues in Container
```bash
# Check host networking
docker network ls
docker network inspect nids-network

# Check host network mode
docker inspect nids-suricata | grep -A 5 "NetworkMode"
```

### 7. Elasticsearch/Kibana Issues

#### Kibana Not Connecting to Elasticsearch
```bash
# Check Kibana logs
docker logs nids-kibana | tail -50

# Check Elasticsearch connectivity
curl -s http://elasticsearch:9200/_cluster/health

# Check Kibana config
cat /usr/share/kibana/config/kibana.yml
```

#### Index Lifecycle Management
```bash
# Check ILM policies
curl -s http://localhost:9200/_ilm/policy/suricata-policy | jq .

# Check index lifecycle
curl -s http://localhost:9200/_cat/ilm/explain/suricata-*?pretty

# Manual rollover
curl -X POST "localhost:9200/suricata-*/_rollover" -H 'Content-Type: application/json' -d '{"conditions": {"max_age": "7d", "max_size": "50gb"}}'
```

## Log Analysis Commands

### Suricata Logs
```bash
# Recent alerts
jq -r 'select(.event_type=="alert") | "\(.timestamp) [\(.alert.severity)] \(.alert.signature) \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"' /var/log/suricata/eve.json | tail -20

# Top signatures
jq -r 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -20

# Top source IPs
jq -r 'select(.event_type=="alert") | .src_ip' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -20

# HTTP anomalies
jq -r 'select(.event_type=="http" and .http.http_method=="POST") | "\(.timestamp) \(.src_ip) -> \(.dest_ip) \(.http.url)"' /var/log/suricata/eve.json | head -20

# DNS anomalies
jq -r 'select(.event_type=="dns" and .dns.rcode=="NXDOMAIN") | "\(.timestamp) \(.src_ip) -> \(.dns.query)"' /var/log/suricata/eve.json | head -20

# TLS anomalies
jq -r 'select(.event_type=="tls" and .tls.version=="SSLv3") | "\(.timestamp) \(.src_ip) -> \(.dest_ip) \(.tls.version)"' /var/log/suricata/eve.json | head -10
```

### Snort Logs
```bash
# Fast alerts
tail -f /var/log/snort/alert

# Unified2 to text
u2spewfast /var/log/snort/snort.u2.1234567890 | head -20

# Snort statistics
snort -c /etc/snort/snort.conf --dump-stats
```

## Performance Tuning Checklist

### Suricata
- [ ] CPU affinity configured
- [ ] Appropriate thread count
- [ ] Memcap values tuned
- [ ] Buffer sizes appropriate
- [ ] XDP/AF_PACKET v3 enabled
- [ ] Unnecessary protocols disabled
- [ ] Rule profiling enabled
- [ ] Expensive rules optimized

### System
- [ ] IRQ affinity configured
- [ ] RSS/RPS/RFS configured
- [ ] Huge pages enabled
- [ ] CPU governor: performance
- [ ] NUMA affinity correct
- [ ] IRQ balancing disabled

### Network
- [ ] RSS enabled on NIC
- [ ] Multiple RX queues
- [ ] Flow steering configured
- [ ] MTU set correctly (9000 for jumbo)
- [ ] Flow control disabled

## Emergency Procedures

### Complete Service Restart
```bash
# Graceful restart
systemctl restart suricata snort alert-manager filebeat logstash

# Force restart
systemctl restart suricata snort alert-manager filebeat logstash elasticsearch kibana grafana prometheus
```

### Emergency Rule Disable
```bash
# Disable specific rule
echo 're:1000001' > /etc/suricata/disable.conf
systemctl reload suricata

# Disable all custom rules
mv /etc/suricata/rules/local.rules /etc/suricata/rules/local.rules.disabled
systemctl reload suricata
```

### Emergency Stop
```bash
# Stop all NIDS services
systemctl stop suricata snort alert-manager filebeat logstash

# Verify stopped
systemctl status suricata snort alert-manager
```

## Log Locations Summary

| Component | Log Path |
|-----------|----------|
| Suricata EVE | `/var/log/suricata/eve.json` |
| Suricata Fast | `/var/log/suricata/fast.log` |
| Suricata Stats | `/var/log/suricata/stats.log` |
| Suricata HTTP | `/var/log/suricata/http.log` |
| Suricata DNS | `/var/log/suricata/dns.log` |
| Suricata TLS | `/var/log/suricata/tls.log` |
| Snort Alert | `/var/log/snort/alert` |
| Snort Unified2 | `/var/log/snort/snort.u2.*` |
| Alert Manager | `/var/log/nids/alert_manager.log` |
| Block IP | `/var/log/nids/block_ip.log` |
| Quarantine | `/var/log/nids/quarantine.log` |
| Email Notify | `/var/log/nids/notify_email.log` |
| Slack Notify | `/var/log/nids/notify_slack.log` |
| Webhook Notify | `/var/log/nids/notify_webhook.log` |
| Filebeat | `/var/log/filebeat/filebeat.log` |
| Logstash | `/var/log/logstash/logstash-plain.log` |
| Elasticsearch | `/var/log/elasticsearch/*.log` |
| Kibana | `/var/log/kibana/kibana.log` |
| Grafana | `/var/log/grafana/grafana.log` |
| Prometheus | `/var/log/prometheus/prometheus.log` |

## Useful Aliases

Add to `~/.bashrc`:
```bash
# NIDS aliases
alias suricata-status='systemctl status suricata'
alias suricata-logs='tail -f /var/log/suricata/eve.json | jq -r "select(.event_type==\"alert\") | \"\(.timestamp) [\(.alert.severity)] \(.alert.signature) \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)\""'
alias snort-status='systemctl status snort'
alias nids-alerts='tail -f /var/log/nids/alerts.log | jq -r "\"\(.timestamp) [\(.severity)] \(.rule_msg) \(.src_ip):\(.src_port) -> \(.dst_ip):\(.dst_port) [\(.source)]\""'
alias nids-attackers='jq -r "select(.event_type==\"alert\" and .timestamp > (now - 86400 | todate)) | .src_ip" /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -20'
alias nids-blocked='python3 /app/responders/block_ip.py --list'
alias nids-health='./scripts/manage_service.sh health'
alias nids-report='./scripts/manage_service.sh report'
```

---

*Guide Version: 1.0 | Last Updated: 2024*