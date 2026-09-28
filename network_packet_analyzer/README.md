# Network Packet Analyzer

A comprehensive Python tool for capturing and analyzing network traffic packets using Scapy.

## Features

- **Live Packet Capture**: Capture packets in real-time from any network interface
- **Packet Filtering**: Use BPF (Berkeley Packet Filter) syntax for filtering
- **Protocol Analysis**: Detailed analysis of Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, ARP, and more
- **Statistics**: Real-time statistics on protocols, top IPs, ports, and packet sizes
- **PCAP Support**: Save captures to PCAP files and analyze existing PCAP files
- **Cross-platform**: Works on Linux, macOS, and Windows

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install scapy directly
pip install scapy
```

## Usage

### Prerequisites
- **Linux/macOS**: Run with `sudo` for packet capture
- **Windows**: Run as Administrator, install [Npcap](https://npcap.com/) (WinPcap alternative)

### Basic Examples

```bash
# List available network interfaces
python packet_analyzer.py --list-interfaces

# Capture on default interface (Ctrl+C to stop)
sudo python packet_analyzer.py

# Capture on specific interface
sudo python packet_analyzer.py -i eth0

# Capture with BPF filter (only HTTP traffic)
sudo python packet_analyzer.py -f "tcp port 80"

# Capture only DNS traffic
sudo python packet_analyzer.py -f "udp port 53"

# Capture 100 packets and save to file
sudo python packet_analyzer.py -c 100 -o capture.pcap

# Capture for 30 seconds
sudo python packet_analyzer.py -t 30

# Analyze existing PCAP file with verbose output
python packet_analyzer.py -r capture.pcap -v
```

### BPF Filter Examples

| Filter | Description |
|--------|-------------|
| `tcp` | Only TCP packets |
| `udp` | Only UDP packets |
| `icmp` | Only ICMP packets |
| `port 80` | Traffic on port 80 (both directions) |
| `src port 80` | Traffic from port 80 |
| `dst port 443` | Traffic to port 443 |
| `host 192.168.1.1` | Traffic to/from specific IP |
| `net 192.168.1.0/24` | Traffic to/from network |
| `tcp port 80 or udp port 53` | HTTP or DNS traffic |
| `not port 22` | Everything except SSH |

### Output Explanation

The tool displays packet information in a structured format:

```
================================================================================
Packet #1 | 2024-01-15 10:30:45.123 | Length: 74 bytes
================================================================================
  [Ethernet] 00:11:22:33:44:55 -> AA:BB:CC:DD:EE:FF | Type: IPv4 (0x0800)
  [IPv4] 192.168.1.100 -> 8.8.8.8 | Proto: UDP | TTL: 64 | Len: 60
  [UDP] DNS(53) -> 12345(12345) | Len: 40 | Checksum: 0x1a2b
  [DNS] ID: 12345 | Query | Questions: 1 | Answers: 0
    Query: google.com (Type: 1)
  [Payload] 40 bytes
    Preview: ..........google.com.....
```

### Protocol Support

| Layer | Protocols |
|-------|-----------|
| Data Link | Ethernet, ARP |
| Network | IPv4, IPv6, ICMP, ICMPv6 |
| Transport | TCP, UDP |
| Application | DNS, HTTP/HTTPS, TLS |

## Project Structure

```
network_packet_analyzer/
├── packet_analyzer.py    # Main analyzer script
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Learning Objectives

This tool helps you understand:

1. **Packet Structure**: How Ethernet frames, IP packets, TCP/UDP segments are structured
2. **Protocol Headers**: Fields in each protocol header and their purposes
3. **Data Flow**: How data moves through network layers
4. **Protocol Behavior**: TCP handshakes, DNS queries/responses, HTTP requests
5. **Network Analysis**: Identifying traffic patterns, troubleshooting connectivity

## Common Use Cases

- Network troubleshooting and debugging
- Security analysis and intrusion detection
- Protocol development and testing
- Network performance monitoring
- Educational purposes (learning network protocols)

## Troubleshooting

### Permission Denied
```bash
# Linux/macOS
sudo python packet_analyzer.py

# Windows - Run PowerShell/CMD as Administrator
```

### No Packets Captured
- Ensure you're on the correct interface (`--list-interfaces`)
- Check if traffic is actually flowing on that interface
- Try without filters first

### Scapy Import Errors
```bash
pip install --upgrade scapy
```

### Windows Npcap Issues
- Install Npcap from https://npcap.com/
- Check "Install Npcap in WinPcap API-compatible Mode" during installation

## License

MIT License - Feel free to use and modify for educational purposes.