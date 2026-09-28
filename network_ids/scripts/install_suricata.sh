#!/bin/bash
# ============================================================
# Suricata Installation Script for Ubuntu/Debian
# ============================================================
# Installs Suricata IDS/IPS with optimal configuration for NIDS
# ============================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SURICATA_VERSION="${SURICATA_VERSION:-7.0.5}"
INSTALL_PREFIX="/usr"
CONFIG_DIR="/etc/suricata"
LOG_DIR="/var/log/suricata"
RULES_DIR="/etc/suricata/rules"
USER="suricata"
GROUP="suricata"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $VERSION"
}

install_dependencies() {
    log_info "Installing dependencies..."

    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                build-essential \
                libpcap-dev \
                libnet1-dev \
                libyaml-dev \
                libjansson-dev \
                libmagic-dev \
                libgeoip-dev \
                liblua5.3-dev \
                libhiredis-dev \
                libevent-dev \
                libnetfilter-queue-dev \
                libnetfilter-log-dev \
                libnfnetlink-dev \
                libcap-ng-dev \
                libnss3-dev \
                libnspr4-dev \
                libprotobuf-c-dev \
                protobuf-c-compiler \
                python3-yaml \
                python3-jinja2 \
                pkg-config \
                autoconf \
                automake \
                libtool \
                git \
                wget \
                curl \
                unzip \
                ethtool \
                iftop \
                htop \
                iptables \
                iproute2 \
                net-tools \
                tcpdump \
                tshark
            ;;
        centos|rhel|fedora)
            dnf install -y \
                gcc \
                gcc-c++ \
                make \
                libpcap-devel \
                libnet-devel \
                libyaml-devel \
                jansson-devel \
                file-devel \
                GeoIP-devel \
                lua-devel \
                hiredis-devel \
                libevent-devel \
                libnetfilter_queue-devel \
                libnetfilter_log-devel \
                libnfnetlink-devel \
                libcap-ng-devel \
                nss-devel \
                nspr-devel \
                protobuf-c-devel \
                protobuf-c-compiler \
                python3-yaml \
                python3-jinja2 \
                pkgconfig \
                autoconf \
                automake \
                libtool \
                git \
                wget \
                curl \
                unzip \
                ethtool \
                iftop \
                htop \
                iptables \
                iproute \
                net-tools \
                tcpdump \
                wireshark-cli
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

create_user() {
    log_info "Creating suricata user..."
    if ! id "$USER" &>/dev/null; then
        groupadd -r "$GROUP"
        useradd -r -g "$GROUP" -d /var/lib/suricata -s /sbin/nologin "$USER"
        log_info "Created user: $USER"
    else
        log_info "User $USER already exists"
    fi
}

download_suricata() {
    log_info "Downloading Suricata $SURICATA_VERSION..."
    cd /tmp
    wget -q "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz"
    tar -xzf "suricata-${SURICATA_VERSION}.tar.gz"
    cd "suricata-${SURICATA_VERSION}"
}

build_suricata() {
    log_info "Building Suricata..."
    ./configure \
        --prefix=$INSTALL_PREFIX \
        --sysconfdir=$CONFIG_DIR \
        --localstatedir=$LOG_DIR \
        --enable-nfqueue \
        --enable-geoip \
        --enable-lua \
        --enable-rust \
        --enable-nss \
        --enable-profiling \
        --enable-profiling-lockfree \
        --enable-af-packet \
        --enable-af-packet=v3 \
        --enable-dpdk \
        --enable-ebpf \
        --enable-xdp

    make -j$(nproc)
    make install-full
    make install-conf

    # Update shared library cache
    ldconfig
}

configure_suricata() {
    log_info "Configuring Suricata..."

    # Create directories
    mkdir -p "$CONFIG_DIR/rules"
    mkdir -p "$LOG_DIR"
    mkdir -p /var/lib/suricata/rules
    mkdir -p /var/run/suricata

    # Set permissions
    chown -R "$USER:$GROUP" "$CONFIG_DIR" "$LOG_DIR" /var/lib/suricata /var/run/suricata

    # Download initial rules
    log_info "Downloading Emerging Threats rules..."
    suricata-update enable-source et/open
    suricata-update enable-source et/pro
    suricata-update

    # Enable additional rule sources
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

    # Update rules
    suricata-update
}

create_systemd_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/suricata.service << EOF
[Unit]
Description=Suricata IDS/IPS
Documentation=man:suricata(8)
After=network.target

[Service]
Type=simple
User=$USER
Group=$GROUP
ExecStartPre=/usr/bin/suricata -T -c $CONFIG_DIR/suricata.yaml
ExecStart=/usr/bin/suricata -c $CONFIG_DIR/suricata.yaml -i eth0 --user $USER --group $GROUP
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=suricata

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR /var/lib/suricata /var/run/suricata
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_SYS_NICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable suricata
}

configure_network() {
    log_info "Configuring network interface..."

    # Enable promiscuous mode
    cat > /etc/systemd/network/99-promiscuous.netdev << EOF
[NetDev]
Name=eth0
Kind=ethernet
EOF

    cat > /etc/systemd/network/99-promiscuous.network << EOF
[Match]
Name=eth0

[Network]
DHCP=no

[Link]
Promiscuous=yes
EOF

    # Enable packet capture capabilities
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/suricata
}

enable_service() {
    log_info "Starting Suricata service..."
    systemctl start suricata
    sleep 3
    systemctl status suricata --no-pager
}

verify_installation() {
    log_info "Verifying installation..."

    # Test configuration
    suricata -T -c $CONFIG_DIR/suricata.yaml -v

    # Check version
    suricata --build-info

    # Check service status
    systemctl is-active --quiet suricata && log_info "Suricata is running" || log_error "Suricata failed to start"

    # Check logs
    sleep 2
    tail -20 $LOG_DIR/eve.json 2>/dev/null | head -5 || true
}

install_management_tools() {
    log_info "Installing management tools..."

    # Install suricata-update if not present
    if ! command -v suricata-update &> /dev/null; then
        pip3 install --upgrade suricata-update
    fi

    # Install evebox for log viewing
    if ! command -v evebox &> /dev/null; then
        wget -q https://github.com/jasonish/evebox/releases/download/v1.2.1/evebox-1.2.1-linux-amd64.tar.gz -O /tmp/evebox.tar.gz
        tar -xzf /tmp/evebox.tar.gz -C /tmp
        mv /tmp/evebox /usr/local/bin/
        chmod +x /usr/local/bin/evebox
    fi
}

create_management_scripts() {
    log_info "Creating management scripts..."

    # Rule update script
    cat > /usr/local/bin/update-suricata-rules << 'EOF'
#!/bin/bash
# Update Suricata rules
set -e
echo "Updating Suricata rules..."
suricata-update
systemctl reload suricata
echo "Rules updated and Suricata reloaded"
EOF
    chmod +x /usr/local/bin/update-suricata-rules

    # Test rules script
    cat > /usr/local/bin/test-suricata-rules << 'EOF'
#!/bin/bash
# Test Suricata rules
set -e
echo "Testing Suricata rules..."
suricata -T -c /etc/suricata/suricata.yaml -v
EOF
    chmod +x /usr/local/bin/test-suricata-rules

    # Log rotation
    cat > /etc/logrotate.d/suricata << EOF
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 suricata suricata
    sharedscripts
    postrotate
        systemctl reload suricata > /dev/null 2>&1 || true
    endscript
}
EOF
}

print_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Suricata Installation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Version: $(suricata -V | head -1)"
    echo "Config: $CONFIG_DIR/suricata.yaml"
    echo "Logs: $LOG_DIR/"
    echo "Rules: $RULES_DIR/"
    echo ""
    echo "Service Commands:"
    echo "  systemctl start suricata"
    echo "  systemctl stop suricata"
    echo "  systemctl restart suricata"
    echo "  systemctl status suricata"
    echo ""
    echo "Management Commands:"
    echo "  update-suricata-rules    # Update rules"
    echo "  test-suricata-rules      # Test configuration"
    echo "  suricata -T -c $CONFIG_DIR/suricata.yaml -v  # Validate config"
    echo ""
    echo "Logs:"
    echo "  tail -f $LOG_DIR/eve.json"
    echo "  tail -f $LOG_DIR/fast.log"
    echo "  tail -f $LOG_DIR/stats.log"
    echo ""
    echo "EveBox (log viewer):"
    echo "  evebox -D /var/lib/suricata"
    echo "  Then open http://localhost:5636"
    echo ""
    echo -e "${YELLOW}Important:${NC} Configure network interface in $CONFIG_DIR/suricata.yaml"
    echo -e "${YELLOW}Important:${NC} Update HOME_NET/EXTERNAL_NET in $CONFIG_DIR/networks.yaml"
}

# Main execution
main() {
    log_info "Starting Suricata installation..."

    check_root
    detect_os
    install_dependencies
    create_user
    download_suricata
    build_suricata
    configure_suricata
    create_systemd_service
    configure_network
    enable_service
    verify_installation
    install_management_tools
    create_management_scripts
    print_summary
}

main "$@"