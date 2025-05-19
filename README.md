# Tor Transparent Proxy Script

A robust Linux-based script for routing all system network traffic through the Tor network, enhancing privacy and anonymity.

## Overview

This script provides a comprehensive solution for configuring your Linux system to route all internet traffic through the Tor network. It includes features like network kill switch protection, identity management, and status monitoring.

## Prerequisites

- Linux operating system
- Root/sudo privileges
- Required packages: tor, iptables, systemctl, curl

## Installation

No installation is required. Simply ensure you have the necessary prerequisites installed and the script has executable permissions.

## Usage

Run the script with sudo privileges:

```bash
sudo ./hide.sh [command]
```

### Available Commands

- `on`: Enable Tor routing (routes all traffic through Tor)
- `off`: Disable Tor routing (restores normal networking)
- `status`: Check the current status of Tor routing
- `newid`: Request a new Tor identity/circuit
- `emergency-stop`: Immediately block all network traffic (kill switch)
- `help`: Display help information

## Features

- Transparent proxy routing through Tor
- DNS leak protection
- Network kill switch functionality
- IPv6 traffic blocking for enhanced security
- Backup and restore of network configurations
- Identity rotation capability

## Security Notice

This script modifies system-wide network settings. Always ensure you understand the implications of routing all traffic through Tor before use. While this enhances privacy, it may impact network performance and certain application functionality.

## License

MIT License