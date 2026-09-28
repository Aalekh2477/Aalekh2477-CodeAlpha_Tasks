#!/bin/bash
# ============================================================
# NIDS Rule Update Script
# ============================================================
# Updates all rule sets for Suricata and Snort
# ============================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
SNORT_CONFIG="/etc/snort/snort.conf"
SURICATA_RULES_DIR="/etc/suricata/rules"
SNORT_RULES_DIR="/etc/snort/rules"
LOG_FILE="/var/log/nids/rule_update.log"

# Colors
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Logging
exec > >(tee -a "$LOG_FILE") 2>&1

check_root() {
    [[ $EUID -eq 0 ]] || { echo -e "${RED}[ERROR]${NC} Run as root"; exit 1; }
}

log_step() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Update Suricata rules
update_suricata_rules() {
    log_step "Updating Suricata Rules"

    if ! command -v suricata-update &> /dev/null; then
        log_error "suricata-update not found. Installing..."
        pip3 install --upgrade suricata-update
    fi

    # Enable standard sources
    suricata-update enable-source et/open
    suricata-update enable-source et/pro
    suricata-update enable-source tls/ssl
    suricata-update enable-source pcre
    suricata-update enable-source dns
    suricata-update enable-source http
    suricata-update enable-source tls
    suricata-update enable-source ssl
    suricata-update enable-source ssh
    suricata-update enable-source smtp
    suricata-update enable-source dns
    suricata-update enable-source http
    suricata-update enable-source tls
    suricata-update enable-source files

    # Disable noisy sources if needed
    # suricata-update disable-source et/malware

    log_info "Running suricata-update..."
    suricata-update --quiet

    # Check for new rules
    local new_rules=$(suricata-update --dry-run 2>&1 | grep -c "Would add" || true)
    log_info "New rules would be added: $new_rules"

    # Reload Suricata if running
    if systemctl is-active --quiet suricata; then
        log_info "Reloading Suricata..."
        systemctl reload suricata
        log_info "Suricata reloaded"
    fi
}

# Update Snort rules
update_snort_rules() {
    log_step "Updating Snort Rules"

    # Snort 3 community rules
    local COMMUNITY_RULES_URL="https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
    local RULES_DIR="/etc/snort/rules"

    log_info "Downloading Snort community rules..."
    cd /tmp
    wget -q "$COMMUNITY_RULES_URL" -O snort3-community-rules.tar.gz
    tar -xzf snort3-community-rules.tar.gz -C /etc/snort/
    rm snort3-community-rules.tar.gz

    # Set permissions
    chown -R snort:snort /etc/snort/rules

    log_info "Snort community rules updated"
}

# Update Emerging Threats rules manually (if suricata-update fails)
update_et_rules_manual() {
    log_step "Updating Emerging Threats Rules (Manual)"

    local ET_OPEN_URL="https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
    local ET_PRO_URL="https://rules.emergingthreatspro.com/${ET_PRO_CODE}/suricata/emerging.rules.tar.gz"

    cd /tmp

    # Download ET Open
    log_info "Downloading Emerging Threats Open rules..."
    wget -q "$ET_OPEN_URL" -O emerging.rules.tar.gz
    tar -xzf emerging.rules.tar.gz -C /etc/suricata/rules/
    rm emerging.rules.tar.gz

    # ET Pro (requires subscription)
    if [[ -n "${ET_PRO_CODE:-}" ]]; then
        log_info "Downloading Emerging Threats Pro rules..."
        wget -q "$ET_PRO_URL" -O emerging-pro.rules.tar.gz
        tar -xzf emerging-pro.rules.tar.gz -C /etc/suricata/rules/
        rm emerging-pro.rules.tar.gz
    fi

    # ThreatFox IOCs
    log_info "Downloading ThreatFox IOCs..."
    wget -q "https://threatfox.abuse.ch/export/json/full/" -O /tmp/threatfox.json
    # Convert to Suricata rules (would need custom parser)
    # This is a placeholder - in production you'd use a proper parser

    log_info "Manual rule update complete"
}

# Update ThreatFox IOCs
update_threatfox() {
    log_step "Updating ThreatFox IOCs"

    local THREATFOX_URL="https://threatfox.abuse.ch/export/json/full/"
    local OUTPUT_DIR="/etc/suricata/rules/threatfox"

    mkdir -p "$OUTPUT_DIR"

    log_info "Downloading ThreatFox data..."
    wget -q "$THREATFOX_URL" -O /tmp/threatfox.json

    # Parse and convert to Suricata rules
    python3 << 'PYEOF'
import json
import sys

with open('/tmp/threatfox.json') as f:
    data = json.load(f)

rules = []
sid = 2000000

for entry in data:
    ioc = entry.get('ioc', '')
    ioc_type = entry.get('ioc_type', '')
    threat_type = entry.get('threat_type', '')
    malware = entry.get('malware', '')
    confidence = entry.get('confidence_level', 50)

    if confidence < 75:
        continue

    if ioc_type == 'ip:port':
        ip, port = ioc.split(':')
        rule = f'alert ip any any -> {ip} {port} (msg:"THREATFOX {malware} C2 {ioc}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
        rules.append(rule)
        sid += 1
    elif ioc_type == 'ipv4':
        rule = f'alert ip any any -> {ioc} any (msg:"THREATFOX {malware} C2 IP {ioc}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
        rules.append(rule)
        sid += 1
    elif ioc_type == 'domain':
        rule = f'alert dns any any -> any any (msg:"THREATFOX {malware} Domain {ioc}"; dns.query; content:"{ioc}"; nocase; classtype:trojan-activity; sid:{sid}; rev:1;)'
        rules.append(rule)
        sid += 1
    elif ioc_type == 'url':
        rule = f'alert http any any -> any any (msg:"THREATFOX {malware} URL {ioc}"; http.uri; content:"{ioc}"; nocase; classtype:trojan-activity; sid:{sid}; rev:1;)'
        rules.append(rule)
        sid += 1

with open('/etc/suricata/rules/threatfox/threatfox.rules', 'w') as f:
    f.write('\n'.join(rules))

print(f"Generated {len(rules)} ThreatFox rules")
PYEOF

    log_info "ThreatFox rules updated"
}

# Update Abuse.ch rules
update_abuse_ch() {
    log_step "Updating Abuse.ch Blocklists"

    local FEODO_URL="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    local SSLBL_URL="https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    local URLHAUS_URL="https://urlhaus.abuse.ch/downloads/csv/"

    mkdir -p /etc/suricata/rules/abuse_ch

    # Feodo Tracker
    log_info "Downloading Feodo Tracker..."
    wget -q "https://feodotracker.abuse.ch/downloads/ipblocklist.json" -O /tmp/feodo.json

    python3 << 'PYEOF'
import json

with open('/tmp/feodo.json') as f:
    data = json.load(f)

rules = []
sid = 3000000

for entry in data:
    ip = entry.get('ip_address', '')
    port = entry.get('port', '')
    malware = entry.get('malware', 'feodo')

    if ip and port:
        rule = f'alert ip any any -> {ip} {port} (msg:"FEODO {malware} C2 {ip}:{port}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
        rules.append(rule)
        sid += 1
    elif ip:
        rule = f'alert ip any any -> {ip} any (msg:"FEODO {malware} C2 IP {ip}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
        rules.append(rule)
        sid += 1

with open('/etc/suricata/rules/abuse_ch/feodo.rules', 'w') as f:
    f.write('\n'.join(rules))

print(f"Generated {len(rules)} Feodo rules")
PYEOF

    log_info "Abuse.ch rules updated"
}

# Validate all rules
validate_rules() {
    log_step "Validating Rules"

    log_info "Testing Suricata configuration..."
    if command -v suricata &> /dev/null; then
        suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -20
        log_info "Suricata configuration test passed"
    else
        log_warn "Suricata not found, skipping validation"
    fi

    if command -v snort &> /dev/null; then
        log_info "Testing Snort configuration..."
        /usr/local/bin/snort -T -c /etc/snort/snort.conf 2>&1 | tail -20
        log_info "Snort configuration test passed"
    else
        log_warn "Snort not found, skipping validation"
    fi
}

# Reload services
reload_services() {
    log_step "Reloading Services"

    if systemctl is-active --quiet suricata; then
        log_info "Reloading Suricata..."
        systemctl reload suricata
        sleep 2
        systemctl status suricata --no-pager | head -5
    fi

    if systemctl is-active --quiet snort; then
        log_info "Reloading Snort..."
        systemctl reload snort
        sleep 2
        systemctl status snort --no-pager | head -5
    fi
}

# Show rule statistics
show_stats() {
    log_step "Rule Statistics"

    echo "Suricata Rules:"
    if [[ -d /etc/suricata/rules ]]; then
        find /etc/suricata/rules -name "*.rules" -type f | while read f; do
            count=$(grep -c "^alert " "$f" 2>/dev/null || echo 0)
            echo "  $(basename $f): $count rules"
        done
    fi

    echo ""
    echo "Snort Rules:"
    if [[ -d /etc/snort/rules ]]; then
        find /etc/snort/rules -name "*.rules" -type f | while read f; do
            count=$(grep -c "^alert " "$f" 2>/dev/null || echo 0)
            echo "  $(basename $f): $count rules"
        done
    fi
}

# Cleanup old rules
cleanup_old_rules() {
    log_step "Cleaning Up Old Rules"

    # Remove rules older than 30 days from backup directories
    find /etc/suricata/rules -name "*.rules.bak*" -mtime +30 -delete 2>/dev/null || true
    find /etc/snort/rules -name "*.rules.bak*" -mtime +30 -delete 2>/dev/null || true

    # Clean up old log files
    find /var/log/suricata -name "*.log.*" -mtime +30 -delete 2>/dev/null || true
    find /var/log/snort -name "*.log.*" -mtime +30 -delete 2>/dev/null || true
}

# Main
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  NIDS Rule Update Script${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Started at: $(date)"
    echo ""

    check_root

    # Parse arguments
    UPDATE_SURICATA=true
    UPDATE_SNORT=true
    UPDATE_THREATFOX=true
    UPDATE_ABUSE_CH=true
    MANUAL_ET=false
    VALIDATE=true
    RELOAD=true
    CLEANUP=true

    while [[ $# -gt 0 ]]; do
        case $1 in
            --suricata-only) UPDATE_SNORT=false; UPDATE_THREATFOX=false; UPDATE_ABUSE_CH=false;;
            --snort-only) UPDATE_SURICATA=false; UPDATE_THREATFOX=false; UPDATE_ABUSE_CH=false;;
            --no-threatfox) UPDATE_THREATFOX=false;;
            --no-abuse-ch) UPDATE_ABUSE_CH=false;;
            --manual-et) MANUAL_ET=true;;
            --no-validate) VALIDATE=false;;
            --no-reload) RELOAD=false;;
            --no-cleanup) CLEANUP=false;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --suricata-only    Update only Suricata rules"
                echo "  --snort-only       Update only Snort rules"
                echo "  --no-threatfox     Skip ThreatFox update"
                echo "  --no-abuse-ch      Skip Abuse.ch update"
                echo "  --manual-et        Use manual ET update (no suricata-update)"
                echo "  --no-validate      Skip rule validation"
                echo "  --no-reload        Skip service reload"
                echo "  --no-cleanup       Skip cleanup"
                exit 0
                ;;
        esac
        shift
    done

    # Execute updates
    $UPDATE_SURICATA && update_suricata_rules
    $MANUAL_ET && update_et_rules_manual
    $UPDATE_SNORT && update_snort_rules
    $UPDATE_THREATFOX && update_threatfox
    $UPDATE_ABUSE_CH && update_abuse_ch
    $VALIDATE && validate_rules
    $RELOAD && reload_services
    $CLEANUP && cleanup_old_rules
    show_stats

    log_info "All updates completed successfully!"
    echo "Completed at: $(date)"
}

main "$@"