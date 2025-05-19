#!/bin/bash
#
# Enhanced Tor Transparent Proxy Script
# Purpose: Routes all system traffic through Tor network with improved safeguards
# License: MIT
#

# Configuration
LOG_FILE="/var/log/tor-routing.log"
BACKUP_DIR="/var/backups/tor-routing"
BACKUP_FILE="$BACKUP_DIR/iptables-backup-$(date +%Y%m%d-%H%M%S).rules"
TOR_USER="debian-tor"
TOR_GROUP="debian-tor"
TOR_UID=$(id -u $TOR_USER 2>/dev/null)
TOR_TRANS_PORT="9040"
TOR_DNS_PORT="5353"
TOR_CONTROL_PORT="9051"
NON_TOR_USERS="root $TOR_USER"  # Users allowed to access clearnet
NON_TOR_NETS="127.0.0.0/8 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12"  # Local networks
TORRC="/etc/tor/torrc"
CHECK_SITE="https://check.torproject.org"
STATUS_FILE="/var/run/tor-routing.status"
SCRIPT_VERSION="2.0.0"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
function log {
    local level=$1
    local message=$2
    local color=""
    
    case $level in
        "INFO") color=$GREEN ;;
        "WARN") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "DEBUG") color=$BLUE ;;
        *) color=$NC ;;
    esac
    
    echo -e "${color}$(date '+%Y-%m-%d %H:%M:%S') - [$level] $message${NC}" | tee -a "$LOG_FILE"
}

function check_root {
    if [ "$EUID" -ne 0 ]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi
}

function prepare_environment {
    # Create backup directory if it doesn't exist
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
    fi
    
    # Create log file if it doesn't exist
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
        chmod 640 "$LOG_FILE"
    fi
}

function check_dependencies {
    MISSING_DEPS=0
    local REQUIRED_CMDS="tor iptables ip6tables iptables-save iptables-restore systemctl curl netstat"
    
    log "INFO" "Checking dependencies..."
    for cmd in $REQUIRED_CMDS; do
        if ! command -v $cmd &>/dev/null; then
            log "ERROR" "Required command '$cmd' not found"
            MISSING_DEPS=1
        fi
    done
    
    # Check if resolvconf is installed for DNS handling
    if ! command -v resolvconf &>/dev/null; then
        log "WARN" "resolvconf not found - DNS handling might be limited"
    fi
    
    if [ $MISSING_DEPS -eq 1 ]; then
        log "ERROR" "Please install missing dependencies and try again"
        exit 1
    fi
}

function check_tor_config {
    log "INFO" "Checking Tor configuration..."
    
    # Check if Tor config exists
    if [ ! -f "$TORRC" ]; then
        log "ERROR" "Tor configuration file not found: $TORRC"
        exit 1
    fi
    
    # Check for required settings
    local MISSING_CONFIG=0
    
    # Check TransPort
    if ! grep -q "^TransPort" "$TORRC"; then
        log "WARN" "TransPort setting not found in $TORRC"
        log "INFO" "Adding TransPort $TOR_TRANS_PORT to $TORRC"
        echo "TransPort $TOR_TRANS_PORT" >> "$TORRC"
    fi
    
    # Check DNSPort
    if ! grep -q "^DNSPort" "$TORRC"; then
        log "WARN" "DNSPort setting not found in $TORRC"
        log "INFO" "Adding DNSPort $TOR_DNS_PORT to $TORRC"
        echo "DNSPort $TOR_DNS_PORT" >> "$TORRC"
    fi
    
    # Check ControlPort (for circuit management)
    if ! grep -q "^ControlPort" "$TORRC"; then
        log "WARN" "ControlPort setting not found in $TORRC"
        log "INFO" "Adding ControlPort $TOR_CONTROL_PORT to $TORRC"
        echo "ControlPort $TOR_CONTROL_PORT" >> "$TORRC"
    fi
    
    # Check if we need to restart Tor after config changes
    if [ $MISSING_CONFIG -eq 1 ]; then
        log "INFO" "Restarting Tor to apply configuration changes..."
        systemctl restart tor || {
            log "ERROR" "Failed to restart Tor service."
            exit 1
        }
        # Give Tor some time to start up
        sleep 5
    fi
}

function start_tor {
    log "INFO" "Checking Tor service status..."
    if ! systemctl is-active --quiet tor; then
        log "INFO" "Starting Tor service..."
        systemctl start tor || {
            log "ERROR" "Failed to start Tor service"
            restore_firewall
            exit 1
        }
        
        # Wait for Tor to fully bootstrap
        log "INFO" "Waiting for Tor to bootstrap (up to 60 seconds)..."
        local attempts=0
        while [ $attempts -lt 60 ]; do
            if systemctl is-active --quiet tor; then
                sleep 1
                # Check if Tor is ready by looking for the "Bootstrapped 100%" message
                if grep -q "Bootstrapped 100" /var/log/tor/log 2>/dev/null; then
                    log "INFO" "Tor is fully bootstrapped"
                    break
                fi
            else
                log "ERROR" "Tor service failed to start"
                restore_firewall
                exit 1
            fi
            attempts=$((attempts + 1))
        done
        
        if [ $attempts -eq 60 ]; then
            log "WARN" "Tor bootstrap timed out, but continuing anyway..."
        fi
    else
        log "INFO" "Tor service already running"
    fi
}

function backup_current_settings {
    log "INFO" "Backing up current network settings..."
    
    # Create backup directory if it doesn't exist
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
    fi
    
    # Back up current iptables rules
    iptables-save > "$BACKUP_FILE.v4" || {
        log "ERROR" "Failed to back up IPv4 iptables rules"
        exit 1
    }
    
    # Back up current ip6tables rules
    ip6tables-save > "$BACKUP_FILE.v6" || {
        log "ERROR" "Failed to back up IPv6 iptables rules"
        exit 1
    }
    
    # Back up resolv.conf
    if [ -f "/etc/resolv.conf" ]; then
        cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.backup" || {
            log "WARN" "Failed to back up resolv.conf"
        }
    fi
    
    log "INFO" "Network settings backed up to $BACKUP_FILE"
}

function setup_kill_switch {
    # Create a systemd service for the kill switch
    local SERVICE_FILE="/etc/systemd/system/tor-routing-killswitch.service"
    
    # Get absolute path to this script
    local SCRIPT_PATH=$(readlink -f "$0")
    
    log "INFO" "Setting up network kill switch..."
    
    # Check if script path was resolved correctly
    if [ -z "$SCRIPT_PATH" ] || [ ! -f "$SCRIPT_PATH" ]; then
        log "WARN" "Could not determine full script path. Using fallback method."
        # Fallback to which or command path
        SCRIPT_PATH=$(which "$0" 2>/dev/null || command -v "$0" 2>/dev/null || echo "$0")
        
        # If still not resolved, try PWD
        if [ ! -f "$SCRIPT_PATH" ]; then
            SCRIPT_PATH="$PWD/$(basename "$0")"
        fi
    fi
    
    log "DEBUG" "Using script path: $SCRIPT_PATH for kill switch"
    
    # Create service file with explicit path
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Tor Routing Kill Switch
After=network.target
Requires=tor.service

[Service]
Type=oneshot
ExecStart=/bin/true
ExecStop=$SCRIPT_PATH emergency-stop
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Make sure service file permissions are correct
    chmod 644 "$SERVICE_FILE"
    
    # Reload systemd to recognize the new service
    systemctl daemon-reload
    
    # Enable and start the kill switch
    systemctl enable tor-routing-killswitch.service || {
        log "ERROR" "Failed to enable kill switch service"
        log "DEBUG" "Service file content:"
        cat "$SERVICE_FILE"
        log "WARN" "Continuing without kill switch"
        return 1
    }
    
    systemctl start tor-routing-killswitch.service || {
        log "ERROR" "Failed to start kill switch service"
        systemctl status tor-routing-killswitch.service
        log "WARN" "Continuing without kill switch"
        return 1
    }
    
    # Verify the service is running
    if systemctl is-active --quiet tor-routing-killswitch.service; then
        log "INFO" "Kill switch installed and active - will block all traffic if Tor stops"
    else
        log "WARN" "Kill switch service installed but not active"
    fi
}

function configure_dns {
    log "INFO" "Configuring DNS to use Tor..."
    
    # Back up current resolv.conf if it exists and we haven't already
    if [ -f "/etc/resolv.conf" ] && [ ! -f "$BACKUP_DIR/resolv.conf.backup" ]; then
        cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.backup"
    fi
    
    # Point DNS to local Tor DNSPort
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    
    # If resolvconf is available, use it for more permanent DNS setup
    if command -v resolvconf &>/dev/null; then
        echo "nameserver 127.0.0.1" > /etc/resolvconf/resolv.conf.d/head
        resolvconf -u
    fi
    
    log "INFO" "DNS configured to use Tor"
}

function enable_routing {
    # Prepare environment and backup
    prepare_environment
    backup_current_settings
    
    # Check configuration and start tor
    check_tor_config
    start_tor
    
    log "INFO" "Applying Tor transparent proxy iptables rules..."
    
    # Get Tor UID if not already set
    if [ -z "$TOR_UID" ]; then
        TOR_UID=$(id -u $TOR_USER 2>/dev/null)
        if [ -z "$TOR_UID" ]; then
            log "ERROR" "Failed to get Tor UID. Check if user $TOR_USER exists."
            restore_firewall
            exit 1
        fi
    fi
    
    # Flush existing rules
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    ip6tables -F
    ip6tables -t nat -F
    ip6tables -t mangle -F
    
    # Block all IPv6 traffic first (Tor doesn't support IPv6 for circuits)
    ip6tables -P INPUT DROP
    ip6tables -P OUTPUT DROP
    ip6tables -P FORWARD DROP
    
    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow Tor process
    iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
    
    # Allow traffic from specified users
    for user in $NON_TOR_USERS; do
        local uid=$(id -u $user 2>/dev/null)
        if [ ! -z "$uid" ]; then
            iptables -A OUTPUT -m owner --uid-owner $uid -j ACCEPT
        fi
    done
    
    # Allow traffic to local networks
    for net in $NON_TOR_NETS; do
        iptables -A OUTPUT -d $net -j ACCEPT
    done
    
    # Redirect DNS traffic to Tor's DNSPort
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT
    
    # Redirect all other TCP traffic to Tor's TransPort
    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TOR_TRANS_PORT
    
    # Set default policies
    iptables -P OUTPUT DROP
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    
    # Configure DNS to use Tor
    configure_dns
    
    # Setup kill switch
    setup_kill_switch
    
    # Update status file
    echo "enabled" > "$STATUS_FILE"
    
    log "INFO" "Tor routing enabled successfully"
}

function restore_firewall {
    local file_v4="$BACKUP_FILE.v4"
    local file_v6="$BACKUP_FILE.v6"
    
    # If specific backup files aren't provided, find the latest ones
    if [ ! -f "$file_v4" ]; then
        file_v4=$(find "$BACKUP_DIR" -name "iptables-backup-*.rules.v4" -type f | sort -r | head -n1)
    fi
    
    if [ ! -f "$file_v6" ]; then
        file_v6=$(find "$BACKUP_DIR" -name "iptables-backup-*.rules.v6" -type f | sort -r | head -n1)
    fi
    
    if [ -f "$file_v4" ]; then
        log "INFO" "Restoring IPv4 firewall rules from $file_v4"
        iptables-restore < "$file_v4"
    else
        log "WARN" "No IPv4 firewall backup found, flushing rules instead"
        iptables -F
        iptables -t nat -F
        iptables -t mangle -F
        iptables -P INPUT ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -P FORWARD ACCEPT
    fi
    
    if [ -f "$file_v6" ]; then
        log "INFO" "Restoring IPv6 firewall rules from $file_v6"
        ip6tables-restore < "$file_v6"
    else
        log "WARN" "No IPv6 firewall backup found, flushing rules instead"
        ip6tables -F
        ip6tables -t nat -F
        ip6tables -t mangle -F
        ip6tables -P INPUT ACCEPT
        ip6tables -P OUTPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
    fi
    
    # Restore DNS settings
    if [ -f "$BACKUP_DIR/resolv.conf.backup" ]; then
        log "INFO" "Restoring DNS settings"
        cp "$BACKUP_DIR/resolv.conf.backup" /etc/resolv.conf
        
        # If resolvconf is available, restore its settings too
        if command -v resolvconf &>/dev/null; then
            if [ -f "$BACKUP_DIR/resolv.conf.d-head.backup" ]; then
                cp "$BACKUP_DIR/resolv.conf.d-head.backup" /etc/resolvconf/resolv.conf.d/head
                resolvconf -u
            fi
        fi
    fi
}

function disable_routing {
    log "INFO" "Disabling Tor routing..."
    
    # Disable kill switch
    if systemctl is-active --quiet tor-routing-killswitch.service; then
        systemctl stop tor-routing-killswitch.service
        systemctl disable tor-routing-killswitch.service
    fi
    
    # Restore firewall settings
    restore_firewall
    
    # Update status file
    echo "disabled" > "$STATUS_FILE"
    
    log "INFO" "Tor routing disabled"
}

function emergency_stop {
    log "WARN" "Emergency stop triggered (likely Tor service failure)"
    
    # Clean up and block all traffic
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    ip6tables -F
    ip6tables -t nat -F
    ip6tables -t mangle -F
    
    # Set default policies to drop all traffic
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    ip6tables -P INPUT DROP
    ip6tables -P OUTPUT DROP
    ip6tables -P FORWARD DROP
    
    # Allow only local traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow SSH for recovery (optional)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
    
    log "WARN" "Network traffic has been locked down due to Tor failure!"
    log "WARN" "Run '$0 off' to restore normal networking"
}

function check_status {
    log "INFO" "Checking Tor routing status..."
    
    # Check if Tor service is running
    if ! systemctl is-active --quiet tor; then
        log "INFO" "Status: Tor service is not running"
        return
    fi
    
    # Check if our rules are active
    if iptables -t nat -L OUTPUT | grep -q "REDIRECT.*$TOR_TRANS_PORT"; then
        log "INFO" "Status: Tor routing is ACTIVE"
        
        # Try to verify Tor connection
        if command -v curl &>/dev/null; then
            log "INFO" "Checking connection to Tor network..."
            if curl -s "$CHECK_SITE" | grep -q "Congratulations"; then
                log "INFO" "Tor verification: SUCCESSFUL - You are using Tor"
            else
                log "WARN" "Tor verification: FAILED - Not using Tor properly"
            fi
        fi
    else
        log "INFO" "Status: Tor routing is INACTIVE"
    fi
}

function new_identity {
    log "INFO" "Requesting new Tor identity..."
    
    # Check if Tor Control Port is enabled and accessible
    if ! netstat -ltn | grep -q ":$TOR_CONTROL_PORT"; then
        log "ERROR" "Tor Control Port not accessible on port $TOR_CONTROL_PORT"
        log "WARN" "Add 'ControlPort $TOR_CONTROL_PORT' to $TORRC and restart Tor"
        return 1
    fi
    
    # Request new identity
    if command -v nc &>/dev/null; then
        if command -v tor-ctrl &>/dev/null; then
            # Use tor-ctrl if available
            tor-ctrl newnym
            log "INFO" "New Tor identity requested"
        else
            # Manual method
            echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT" | nc 127.0.0.1 $TOR_CONTROL_PORT
            log "INFO" "New Tor identity requested"
        fi
    else
        log "ERROR" "nc (netcat) not found - cannot send control commands to Tor"
        return 1
    fi
}

function print_help {
    cat << EOF
Enhanced Tor Transparent Proxy Script v$SCRIPT_VERSION

Usage: $0 {on|off|status|newid|emergency-stop|help}

Commands:
  on             Enable Tor routing (all traffic goes through Tor)
  off            Disable Tor routing (restore normal networking)
  status         Check the current status of Tor routing
  newid          Request a new Tor identity/circuit
  emergency-stop Immediately block all network traffic (kill switch)
  help           Show this help message

This script configures your system to route all internet traffic through 
the Tor network for anonymity.

EOF
}

# === Entry Point ===
check_root
check_dependencies

# Process command
case "$1" in
    "on")
        log "INFO" "=== Enabling Tor Routing ==="
        enable_routing
        check_status
        ;;
    "off")
        log "INFO" "=== Disabling Tor Routing ==="
        disable_routing
        ;;
    "status")
        check_status
        ;;
    "newid")
        new_identity
        ;;
    "emergency-stop")
        emergency_stop
        ;;
    "help")
        print_help
        ;;
    *)
        print_help
        exit 1
        ;;
esac

exit 0
