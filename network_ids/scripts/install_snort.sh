#!/bin/bash
# ============================================================
# Snort Installation Script for Ubuntu/Debian
# ============================================================
# Installs Snort 3 with DAQ and required dependencies
# ============================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SNORT_VERSION="${SNORT_VERSION:-3.1.70.0}"
DAQ_VERSION="${DAQ_VERSION:-3.0.9}"
INSTALL_PREFIX="/usr/local"
CONFIG_DIR="/etc/snort"
LOG_DIR="/var/log/snort"
RULES_DIR="/etc/snort/rules"
USER="snort"
GROUP="snort"

# Functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    [[ $EUID -eq 0 ]] || { log_error "Run as root"; exit 1; }
}

detect_os() {
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    log_info "Detected OS: $OS $VERSION"
}

install_dependencies() {
    log_info "Installing dependencies..."
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                build-essential \
                cmake \
                libpcap-dev \
                libpcre3-dev \
                libdumbnet-dev \
                libdnet \
                libluajit-5.1-dev \
                libhwloc-dev \
                libssl-dev \
                libboost-all-dev \
                libhwloc-dev \
                libmnl-dev \
                libnetfilter-queue-dev \
                libnetfilter-queue1 \
                libnfnetlink-dev \
                libnfnetlink0 \
                libdaq-dev \
                libdaq-modules \
                pkg-config \
                flex \
                bison \
                git \
                wget \
                curl \
                unzip \
                iptables \
                iproute2 \
                net-tools \
                tcpdump \
                ethtool
            ;;
        centos|rhel|fedora)
            dnf install -y \
                gcc \
                gcc-c++ \
                cmake \
                libpcap-devel \
                pcre-devel \
                libdnet-devel \
                luajit-devel \
                hwloc-devel \
                openssl-devel \
                boost-devel \
                libmnl-devel \
                libnetfilter_queue-devel \
                libnfnetlink-devel \
                daq-devel \
                flex \
                bison \
                git \
                wget \
                curl \
                unzip \
                iptables \
                iproute \
                net-tools \
                tcpdump \
                ethtool
            ;;
        *)
            log_error "Unsupported OS: $OS"; exit 1;;
    esac
}

create_user() {
    log_info "Creating snort user..."
    if ! id "$USER" &>/dev/null; then
        groupadd -r "$GROUP"
        useradd -r -g "$GROUP" -d /var/lib/snort -s /sbin/nologin "$USER"
    fi
}

build_daq() {
    log_info "Building DAQ $DAQ_VERSION..."
    cd /tmp
    wget -q "https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz"
    tar -xzf "daq-${DAQ_VERSION}.tar.gz"
    cd "daq-${DAQ_VERSION}"
    ./configure --prefix=$INSTALL_PREFIX
    make -j$(nproc)
    make install
    ldconfig
}

build_snort() {
    log_info "Building Snort $SNORT_VERSION..."
    cd /tmp
    wget -q "https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz"
    tar -xzf "snort-${SNORT_VERSION}.tar.gz"
    cd "snort-${SNORT_VERSION}"

    ./configure \
        --prefix=$INSTALL_PREFIX \
        --sysconfdir=$CONFIG_DIR \
        --localstatedir=$LOG_DIR \
        --enable-sourcefire \
        --enable-mpls \
        --enable-targetbased \
        --enable-ppm \
        --enable-perfprofiling \
        --enable-zlib \
        --enable-active-response \
        --enable-normalizer \
        --enable-reload \
        --enable-react \
        --enable-flexresp3

    make -j$(nproc)
    make install
    ldconfig
}

configure_snort() {
    log_info "Configuring Snort..."

    mkdir -p "$CONFIG_DIR/rules"
    mkdir -p "$LOG_DIR"
    mkdir -p /var/lib/snort/rules
    mkdir -p /var/run/snort

    chown -R "$USER:$GROUP" "$CONFIG_DIR" "$LOG_DIR" /var/lib/snort /var/run/snort

    # Create basic snort.conf
    cat > $CONFIG_DIR/snort.conf << 'EOF'
# Snort 3 Configuration
# ============================================================

# Network variables
ipvar HOME_NET [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]
ipvar EXTERNAL_NET !$HOME_NET

# Port variables
portvar HTTP_PORTS [80,81,311,3128,8000,8080,8081,8082,8085,8088,8090,8888,9000,9080,9090,9091,9443]
portvar SHELLCODE_PORTS !$HTTP_PORTS
portvar HTTP_PORTS 80
portvar SHELLCODE_PORTS !80
portvar HTTP_PORTS 80
portvar ORACLE_PORTS 1521
portvar SSH_PORTS 22

# Rule paths
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules
var WHITE_LIST_PATH /etc/snort/rules
var BLACK_LIST_PATH /etc/snort/rules

# Include default configurations
include $RULE_PATH/snort_defaults.lua

# Include local rules
include $RULE_PATH/local.rules

# Logging
config logdir: /var/log/snort
config alertfile: alert
config logdir: /var/log/snort
config logdir: /var/log/snort
config alertfile: alert

# Performance
config detection: search-method ac-bnfa-q
config detection: split-any-any
config detection: search-optimize
config paf_max: 16384

# Output
output alert_fast: alert.fast
output alert_syslog: LOG_AUTH LOG_ALERT
output unified2: filename snort.u2, limit 128

# Include rules
include $RULE_PATH/local.rules
include $RULE_PATH/community.rules
EOF

    # Create local rules file
    cat > $RULES_DIR/local.rules << 'EOF'
# Snort 3 Local Rules
# SID Range: 1000000-1999999

# SQL Injection
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-APP SQL Injection Attempt";
    flow:to_server,established;
    content:"union"; nocase;
    content:"select"; nocase; distance:0; within:50;
    classtype:web-application-attack;
    sid:1000001; rev:1;
)

# Command Injection
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-APP Command Injection";
    flow:to_server,established;
    pcre:"/[;&|`\$\(\)]/";
    pcre:"/(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|php)/i";
    classtype:web-application-attack;
    sid:1000002; rev:1;
)

# Brute Force SSH
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"BRUTE-FORCE SSH Authentication Failure";
    flow:to_server,established;
    content:"SSH"; nocase;
    threshold: type both, track by_src, count 5, seconds 300;
    classtype:attempted-admin;
    sid:1000101; rev:1;
)

# Port Scan
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SCAN SYN Port Scan";
    flags:S;
    threshold: type both, track by_src, count 50, seconds 60;
    classtype:attempted-recon;
    sid:1000301; rev:1;
)
EOF

    # Set permissions
    chown -R "$USER:$GROUP" "$CONFIG_DIR" "$LOG_DIR" /var/lib/snort /var/run/snort
}

create_systemd_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort 3 NIDS
Documentation=man:snort(8)
After=network.target

[Service]
Type=simple
User=$USER
Group=$GROUP
ExecStartPre=$INSTALL_PREFIX/bin/snort -T -c $CONFIG_DIR/snort.conf
ExecStart=$INSTALL_PREFIX/bin/snort -c $CONFIG_DIR/snort.conf -i eth0 -u $USER -g $GROUP
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=snort

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR /var/lib/snort /var/run/snort
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable snort
}

verify_installation() {
    log_info "Verifying installation..."

    # Test configuration
    $INSTALL_PREFIX/bin/snort -T -c $CONFIG_DIR/snort.conf

    # Check version
    $INSTALL_PREFIX/bin/snort -V

    # Start service
    systemctl start snort
    sleep 3
    systemctl status snort --no-pager
}

main() {
    log_info "Starting Snort 3 installation..."
    check_root
    detect_os
    install_dependencies
    create_user
    build_daq
    build_snort
    configure_snort
    create_systemd_service
    verify_installation

    log_info "Snort 3 installation complete!"
    echo "Config: $CONFIG_DIR/snort.conf"
    echo "Logs: $LOG_DIR/"
    echo "Rules: $RULES_DIR/"
    echo "Commands: systemctl start|stop|restart|status snort"
}
main "$@"