#!/bin/bash
# ============================================================
# NIDS Service Management Script
# ============================================================
# Manage Suricata, Snort, and Alert Manager services
# ============================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Services
SERVICES=("suricata" "snort" "alert-manager" "filebeat" "logstash" "elasticsearch" "kibana" "grafana" "prometheus")

# Colors
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${BLUE}========================================${NC}\n${BLUE}$1${NC}\n${BLUE}========================================${NC}"; }

check_root() {
    [[ $EUID -eq 0 ]] || { log_error "Run as root"; exit 1; }
}

# Service management functions
service_start() {
    local service=$1
    log_info "Starting $service..."
    systemctl start "$service"
    sleep 2
    systemctl status "$service" --no-pager | head -5
}

service_stop() {
    local service=$1
    log_info "Stopping $service..."
    systemctl stop "$service"
    sleep 1
}

service_restart() {
    local service=$1
    log_info "Restarting $service..."
    systemctl restart "$service"
    sleep 3
    systemctl status "$service" --no-pager | head -5
}

service_reload() {
    local service=$1
    log_info "Reloading $service..."
    systemctl reload "$service"
    sleep 1
}

service_status() {
    local service=$1
    systemctl status "$service" --no-pager
}

service_enable() {
    local service=$1
    log_info "Enabling $service..."
    systemctl enable "$service"
}

service_disable() {
    local service=$1
    log_info "Disabling $service..."
    systemctl disable "$service"
}

service_logs() {
    local service=$1
    local lines=${2:-100}
    journalctl -u "$service" -n "$lines" -f
}

service_logs_tail() {
    local service=$1
    local lines=${2:-50}
    journalctl -u "$service" -n "$lines" --no-pager
}

# Check all services
check_all() {
    log_step "Service Status Overview"
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            status="${GREEN}ACTIVE${NC}"
        elif systemctl list-unit-files | grep -q "^$service.service"; then
            status="${RED}INACTIVE${NC}"
        else
            status="${YELLOW}NOT INSTALLED${NC}"
        fi
        printf "  %-20s %s\n" "$service:" "$status"
    done
}

# Health check
health_check() {
    log_step "Health Check"

    # Disk space
    log_info "Disk Usage:"
    df -h /var/log /var/lib/suricata /var/lib/snort 2>/dev/null | grep -v tmpfs | column -t

    # Memory
    log_info "Memory Usage:"
    free -h

    # CPU
    log_info "CPU Load:"
    uptime

    # Network interfaces
    log_info "Network Interfaces:"
    ip -br link show | grep -E "(eth|ens|eno|enp)"

    # Suricata specific
    if systemctl is-active --quiet suricata; then
        log_info "Suricata Stats:"
        if [[ -f /var/log/suricata/stats.log ]]; then
            tail -5 /var/log/suricata/stats.log | jq -r '. | to_entries[] | "\(.key): \(.value)"' 2>/dev/null || tail -5 /var/log/suricata/stats.log
        fi
    fi

    # Elasticsearch
    if systemctl is-active --quiet elasticsearch || curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
        log_info "Elasticsearch Health:"
        curl -s http://localhost:9200/_cluster/health | jq -r '.status, .number_of_nodes, .active_primary_shards, .active_shards' 2>/dev/null || echo "Elasticsearch not accessible"
    fi

    # Disk space for Elasticsearch
    if [[ -d /var/lib/elasticsearch ]]; then
        log_info "Elasticsearch Disk Usage:"
        du -sh /var/lib/elasticsearch 2>/dev/null || true
    fi
}

# Backup configuration
backup_config() {
    local BACKUP_DIR="/var/backups/nids_$(date +%Y%m%d_%H%M%S)"
    log_info "Backing up configuration to $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    cp -r /etc/suricata "$BACKUP_DIR/"
    cp -r /etc/snort "$BACKUP_DIR/"
    cp -r /etc/filebeat "$BACKUP_DIR/"
    cp -r /etc/logstash "$BACKUP_DIR/"
    cp -r /etc/elasticsearch "$BACKUP_DIR/"
    cp -r /etc/grafana "$BACKUP_DIR/"
    cp -r /etc/prometheus "$BACKUP_DIR/"
    log_info "Backup complete: $BACKUP_DIR"
}

# Restore configuration
restore_config() {
    local BACKUP_DIR=$1
    [[ -d "$BACKUP_DIR" ]] || { log_error "Backup directory not found: $BACKUP_DIR"; exit 1; }

    log_warn "Restoring configuration from $BACKUP_DIR"
    read -p "This will overwrite current configuration. Continue? (y/N) " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || { log_info "Cancelled"; exit 1; }

    systemctl stop suricata snort filebeat logstash alert-manager 2>/dev/null || true

    cp -r "$BACKUP_DIR/suricata" /etc/
    cp -r "$BACKUP_DIR/snort" /etc/
    cp -r "$BACKUP_DIR/filebeat" /etc/
    cp -r "$BACKUP_DIR/logstash" /etc/
    cp -r "$BACKUP_DIR/elasticsearch" /etc/
    cp -r "$BACKUP_DIR/grafana" /etc/
    cp -r "$BACKUP_DIR/prometheus" /etc/

    systemctl start suricata snort filebeat logstash alert-manager
    log_info "Configuration restored"
}

# Update rules
update_rules() {
    log_step "Updating Rules"
    /usr/local/bin/update-suricata-rules 2>/dev/null || /usr/local/bin/update_suricata_rules.sh 2>/dev/null || true
    /usr/local/bin/update-snort-rules 2>/dev/null || true
    log_info "Rules updated"
}

# Test rules
test_rules() {
    log_step "Testing Rules"
    /usr/local/bin/test-suricata-rules 2>/dev/null || /usr/local/bin/test_rules.sh 2>/dev/null || true
}

# View logs
view_logs() {
    local service=${1:-suricata}
    local lines=${2:-100}

    case $service in
        suricata)
            tail -f /var/log/suricata/eve.json | jq -r '. | select(.event_type=="alert") | "\(.timestamp) [\(.alert.severity)] \(.alert.signature) \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"'
            ;;
        snort)
            tail -f /var/log/snort/alert
            ;;
        alert-manager)
            tail -f /var/log/nids/alert_manager.log
            ;;
        responders)
            tail -f /var/log/nids/block_ip.log /var/log/nids/quarantine.log /var/log/nids/notify_*.log 2>/dev/null
            ;;
        *)
            journalctl -u "$service" -f
            ;;
    esac
}

# Show recent alerts
show_alerts() {
    local limit=${1:-50}
    log_info "Recent Alerts (last $limit):"

    if [[ -f /var/log/nids/alerts.log ]]; then
        tail -n "$limit" /var/log/nids/alerts.log | jq -r '"\(.timestamp) [\(.severity)] \(.rule_msg) \(.src_ip):\(.src_port) -> \(.dst_ip):\(.dst_port) [\(.source)]"' 2>/dev/null || tail -n "$limit" /var/log/nids/alerts.log
    else
        log_warn "Alert log not found"
    fi
}

# Show top attackers
show_top_attackers() {
    local limit=${1:-20}
    log_info "Top Attackers (last 24h):"

    if [[ -f /var/log/suricata/eve.json ]]; then
        jq -r 'select(.event_type=="alert" and .timestamp > (now - 86400 | todate)) | .src_ip' /var/log/suricata/eve.json 2>/dev/null | sort | uniq -c | sort -rn | head -"$limit" | while read count ip; do
            printf "%-5s %s\n" "$count" "$ip"
        done
    else
        log_warn "EVE log not found"
    fi
}

# Show blocked IPs
show_blocked() {
    log_info "Currently Blocked IPs:"
    if command -v nft &> /dev/null; then
        nft list chain inet filter NIDS_BLOCK 2>/dev/null | grep -E "ip saddr|ip6 saddr" | awk '{print $3}' | sort -u | while read ip; do
            echo "  $ip"
        done
    fi

    if command -v iptables &> /dev/null; then
        iptables -L NIDS_BLOCK -n 2>/dev/null | grep DROP | awk '{print $4}' | while read ip; do
            echo "  $ip"
        done
    fi
}

# Unblock IP
unblock_ip() {
    local ip=$1
    [[ -z "$ip" ]] && { log_error "IP address required"; exit 1; }

    log_info "Unblocking $ip..."

    if command -v nft &> /dev/null; then
        nft delete rule inet filter NIDS_BLOCK ip saddr "$ip" 2>/dev/null || true
        nft delete rule inet filter NIDS_BLOCK ip6 saddr "$ip" 2>/dev/null || true
    fi

    if command -v iptables &> /dev/null; then
        iptables -D NIDS_BLOCK -s "$ip" -j DROP 2>/dev/null || true
        ip6tables -D NIDS_BLOCK -s "$ip" -j DROP 2>/dev/null || true
    fi

    log_info "Unblocked $ip"
}

# Emergency stop
emergency_stop() {
    log_warn "EMERGENCY STOP - Stopping all NIDS services"
    for service in suricata snort alert-manager filebeat logstash; do
        systemctl stop "$service" 2>/dev/null || true
    done
    log_warn "All NIDS services stopped"
}

# Emergency start
emergency_start() {
    log_info "Emergency start - Starting all NIDS services"
    for service in elasticsearch logstash filebeat suricata snort alert-manager kibana grafana prometheus; do
        systemctl start "$service" 2>/dev/null || true
    done
    sleep 5
    check_all
}

# Generate report
generate_report() {
    local REPORT_FILE="/tmp/nids_status_report_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "NIDS Status Report - $(date)"
        echo "========================================"
        echo ""
        echo "Service Status:"
        for service in "${SERVICES[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo "  $service: ACTIVE"
            elif systemctl list-unit-files | grep -q "^$service.service"; then
                echo "  $service: INACTIVE"
            else
                echo "  $service: NOT INSTALLED"
            fi
        done
        echo ""
        echo "Disk Usage:"
        df -h /var/log /var/lib/suricata /var/lib/snort 2>/dev/null | grep -v tmpfs
        echo ""
        echo "Memory:"
        free -h
        echo ""
        echo "Recent Alerts (last 10):"
        tail -10 /var/log/nids/alerts.log 2>/dev/null | jq -r '"\(.timestamp) [\(.severity)] \(.rule_msg) \(.src_ip):\(.src_port) -> \(.dst_ip):\(.dst_port)"' 2>/dev/null || tail -10 /var/log/nids/alerts.log 2>/dev/null
        echo ""
        echo "Top 10 Attackers (24h):"
        jq -r 'select(.event_type=="alert" and .timestamp > (now - 86400 | todate)) | .src_ip' /var/log/suricata/eve.json 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read count ip; do echo "  $count $ip"; done
    } > "$REPORT_FILE"

    log_info "Report generated: $REPORT_FILE"
    cat "$REPORT_FILE"
}

# Main
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  NIDS Service Manager${NC}"
    echo -e "${BLUE}========================================${NC}"

    check_root

    case ${1:-} in
        start)
            check_root
            for service in "${@:2}"; do
                service_start "$service"
            done
            [[ $# -eq 1 ]] && for s in "${SERVICES[@]}"; do service_start "$s"; done
            ;;
        stop)
            check_root
            for service in "${@:2}"; do
                service_stop "$service"
            done
            [[ $# -eq 1 ]] && for s in "${SERVICES[@]}"; do service_stop "$s"; done
            ;;
        restart)
            check_root
            for service in "${@:2}"; do
                service_restart "$service"
            done
            [[ $# -eq 1 ]] && for s in "${SERVICES[@]}"; do service_restart "$s"; done
            ;;
        reload)
            check_root
            for service in "${@:2}"; do
                service_reload "$service"
            done
            [[ $# -eq 1 ]] && for s in "${SERVICES[@]}"; do service_reload "$s"; done
            ;;
        status)
            for service in "${@:2}"; do
                service_status "$service"
            done
            [[ $# -eq 1 ]] && check_all
            ;;
        enable)
            check_root
            for service in "${@:2}"; do
                service_enable "$service"
            done
            ;;
        disable)
            check_root
            for service in "${@:2}"; do
                service_disable "$service"
            done
            ;;
        logs)
            service_logs "${2:-suricata}" "${3:-100}"
            ;;
        logs-tail)
            service_logs_tail "${2:-suricata}" "${3:-50}"
            ;;
        check)
            check_all
            ;;
        health)
            health_check
            ;;
        backup)
            check_root
            backup_config
            ;;
        restore)
            check_root
            restore_config "${2:-}"
            ;;
        update-rules)
            check_root
            update_rules
            ;;
        test-rules)
            test_rules
            ;;
        alerts)
            show_alerts "${2:-50}"
            ;;
        attackers)
            show_top_attackers "${2:-20}"
            ;;
        blocked)
            show_blocked
            ;;
        unblock)
            check_root
            unblock_ip "${2:-}"
            ;;
        emergency-stop)
            check_root
            emergency_stop
            ;;
        emergency-start)
            check_root
            emergency_start
            ;;
        report)
            generate_report
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|reload|status|enable|disable|logs|logs-tail|check|health|backup|restore|update-rules|test-rules|alerts|attackers|blocked|unblock|emergency-stop|emergency-start|report} [service...]"
            echo ""
            echo "Services: ${SERVICES[*]}"
            echo ""
            echo "Examples:"
            echo "  $0 start                    # Start all services"
            echo "  $0 start suricata           # Start only Suricata"
            echo "  $0 status                   # Check all services"
            echo "  $0 logs suricata            # Follow Suricata logs"
            echo "  $0 alerts 100               # Show last 100 alerts"
            echo "  $0 attackers 50             # Show top 50 attackers"
            echo "  $0 blocked                  # Show blocked IPs"
            echo "  $0 unblock 192.168.1.100    # Unblock an IP"
            echo "  $0 emergency-stop           # Stop all NIDS services"
            echo "  $0 report                   # Generate status report"
            exit 1
            ;;
    esac
}

main "$@"