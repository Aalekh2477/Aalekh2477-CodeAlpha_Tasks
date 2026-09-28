# Task 03 — Network Packet Analyzer

> **CodeAlpha Cybersecurity Internship** | Network Security & Traffic Analysis  
> **Difficulty:** ⭐⭐⭐ Intermediate | **Estimated Time:** 6–8 hours

---

## 🎯 Objective

Build a **production-grade network packet analyzer** in Python using **Scapy** — capable of live capture, deep protocol decoding, BPF filtering, real-time statistics, and PCAP file I/O. Cross-platform (Linux, macOS, Windows).

---

## 📂 Folder Structure

```
03_network_packet_analyzer/
├── packet_analyzer.py          # Main analyzer class + CLI (full-featured)
├── simple_capture.py           # Beginner-friendly minimal capture script
├── demo_analysis.py            # PCAP analysis example script
├── sample_packets.pcap         # Sample capture for testing offline
├── requirements.txt            # pip install -r requirements.txt
└── README.md                   # This file
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- **Linux/macOS:** `sudo` for packet capture
- **Windows:** Run as **Administrator** + install [Npcap](https://npcap.com/) (check "WinPcap API-compatible Mode")

### Installation
```bash
cd 03_network_packet_analyzer
pip install -r requirements.txt
# Or manually: pip install scapy
```

---

## 🖥️ Usage Guide

### 1️⃣ List Network Interfaces
```bash
python packet_analyzer.py --list-interfaces
```
**Output:**
```
Available interfaces:
  0: eth0 (192.168.1.100)
  1: wlan0 (192.168.1.101)
  2: lo (127.0.0.1)
```

### 2️⃣ Live Capture — Basic
```bash
# Capture on default interface (Ctrl+C to stop)
sudo python packet_analyzer.py

# Capture on specific interface
sudo python packet_analyzer.py -i eth0
```

### 3️⃣ Live Capture — With BPF Filter
```bash
# HTTP traffic only
sudo python packet_analyzer.py -f "tcp port 80"

# DNS traffic only
sudo python packet_analyzer.py -f "udp port 53"

# Specific host
sudo python packet_analyzer.py -f "host 192.168.1.50"

# Exclude SSH
sudo python packet_analyzer.py -f "not port 22"

# Complex: HTTP or DNS, not localhost
sudo python packet_analyzer.py -f "(tcp port 80 or udp port 53) and not host 127.0.0.1"
```

### 4️⃣ Capture to PCAP File
```bash
# Capture 100 packets, save to file
sudo python packet_analyzer.py -c 100 -o capture.pcap

# Capture for 30 seconds
sudo python packet_analyzer.py -t 30 -o timed_capture.pcap

# Capture with filter to file
sudo python packet_analyzer.py -f "tcp port 443" -c 50 -o https_capture.pcap
```

### 5️⃣ Analyze PCAP Offline (No Root Needed)
```bash
# Basic analysis
python packet_analyzer.py -r capture.pcap

# Verbose output (full layer decode)
python packet_analyzer.py -r capture.pcap -v

# Use sample file
python packet_analyzer.py -r sample_packets.pcap -v
```

### 6️⃣ Beginner Script (Simple Capture)
```bash
# Minimal example — good for learning
sudo python simple_capture.py
```

### 7️⃣ Demo Analysis Script
```bash
# Pre-written analysis of sample_packets.pcap
python demo_analysis.py
```

---

## 📦 Sample Output

### Live Capture (Standard)
```
================================================================================
Packet #1 | 2024-01-15 10:30:45.123 | Length: 74 bytes
================================================================================
  [Ethernet] 00:11:22:33:44:55 → AA:BB:CC:DD:EE:FF | Type: IPv4 (0x0800)
  [IPv4] 192.168.1.100 → 8.8.8.8 | Proto: UDP | TTL: 64 | Len: 60
  [UDP] 53312 → 53 (DNS) | Len: 40 | Checksum: 0x1a2b
  [DNS] ID: 12345 | Query | Questions: 1 | Answers: 0
    Query: google.com (Type: A)
  [Payload] 40 bytes
    Preview: ..........google.com.....
```

### Verbose Mode (`-v`)
```
================================================================================
Packet #1 | 2024-01-15 10:30:45.123 | Length: 74 bytes
================================================================================
  [Ethernet] 
    dst: 00:11:22:33:44:55
    src: AA:BB:CC:DD:EE:FF
    type: 0x0800 (IPv4)
  [IPv4]
    version: 4 | ihl: 5 | tos: 0x00 | len: 60
    id: 12345 | flags: DF | frag: 0 | ttl: 64 | proto: 17 (UDP)
    src: 192.168.1.100 | dst: 8.8.8.8
    checksum: 0xabcd
  [UDP]
    sport: 53312 | dport: 53 | len: 40 | checksum: 0x1a2b
  [DNS]
    id: 12345 | qr: 0 (Query) | opcode: 0 | aa: 0 | tc: 0 | rd: 1
    qdcount: 1 | ancount: 0 | nscount: 0 | arcount: 0
    Questions:
      1. google.com (Type: A, Class: IN)
  [Payload] 40 bytes
    0000: 00 01 00 00 00 00 00 00  03 77 77 77 06 67 6f 6f  .........www.goo
    0010: 67 6c 65 03 63 6f 6d 00  00 01 00 01              gle.com....
```

### Summary Statistics (on Ctrl+C)
```
================================================================================
CAPTURE SUMMARY
================================================================================
Total Packets: 1,247
Duration: 45.2 seconds
Average Rate: 27.6 packets/sec

Protocol Distribution:
  TCP:     892 (71.5%) ████████████████████
  UDP:     312 (25.0%) ██████████
  ICMP:     23 (1.8%)  █
  ARP:      15 (1.2%)  █
  Other:     5 (0.4%)

Top Source IPs:
  192.168.1.100: 423 packets
  8.8.8.8:       312 packets
  192.168.1.1:   156 packets

Top Destination Ports:
  443 (HTTPS):   567
  53 (DNS):      312
  80 (HTTP):     123
  22 (SSH):       45
```

---

## 🔧 BPF Filter Cheatsheet

| Filter | Description |
|--------|-------------|
| `tcp` | Only TCP packets |
| `udp` | Only UDP packets |
| `icmp` | Only ICMP packets |
| `port 80` | Traffic on port 80 (both directions) |
| `src port 80` | Traffic **from** port 80 |
| `dst port 443` | Traffic **to** port 443 |
| `host 192.168.1.1` | Traffic to/from specific IP |
| `net 192.168.1.0/24` | Traffic to/from network |
| `tcp port 80 or udp port 53` | HTTP **or** DNS |
| `not port 22` | Everything **except** SSH |
| `tcp[tcpflags] & tcp-syn != 0` | Only SYN packets (connection attempts) |
| `tcp[13] == 2` | SYN only (raw flag value) |
| `greater 1500` | Packets larger than 1500 bytes |

> **Tip:** Test filters with `tcpdump -i eth0 -n "your filter"` first.

---

## 📚 Protocol Support

| Layer | Protocols Decoded |
|-------|-------------------|
| **Data Link** | Ethernet (MAC, type), ARP (request/reply) |
| **Network** | IPv4 (flags, TTL, proto), IPv6, ICMP (types/codes), ICMPv6 |
| **Transport** | TCP (flags: SYN/ACK/FIN/RST/PSH/URG/ECE/CWR, seq/ack, window), UDP |
| **Application** | DNS (query/response, record types), HTTP/HTTPS (method, path, headers), TLS (handshake, version, cipher, SNI) |

---

## 🏗️ Code Architecture

### `packet_analyzer.py` — Main Class
```python
class PacketAnalyzer:
    def __init__(self, interface=None, filter_str="", count=0, timeout=0, output_file=None):
        # Configuration
        self.interface = interface
        self.filter_str = filter_str
        self.count = count
        self.timeout = timeout
        self.output_file = output_file
        self.packets = []
        self.stats = defaultdict(int)  # Real-time counters
        self.running = False

    def parse_packet(self, pkt):
        # Walks layers: Ether → IP/IPv6 → TCP/UDP/ICMP → App (DNS/HTTP/TLS)
        # Returns formatted string for display

    def display_summary(self):
        # Prints protocol distribution, top IPs, top ports

    def save_packets(self):
        # wrpcap(self.output_file, self.packets)
```

### Key Methods
| Method | Purpose |
|--------|---------|
| `parse_packet(pkt)` | Layer-by-layer decode with formatted output |
| `get_protocol_name(proto_num)` | Maps IP protocol numbers to names |
| `get_tcp_flags(flags_int)` | Converts TCP flag bitmap to readable string (S, SA, F, RA, etc.) |
| `get_port_name(port)` | Common port → service name (e.g., 443 → HTTPS) |
| `signal_handler()` | Graceful Ctrl+C → summary + save PCAP |

---

## 🧪 Testing Checklist

- [ ] `python packet_analyzer.py --list-interfaces` shows interfaces
- [ ] `sudo python packet_analyzer.py -c 5` captures 5 packets, exits cleanly
- [ ] `sudo python packet_analyzer.py -f "tcp port 80"` filters correctly
- [ ] `sudo python packet_analyzer.py -c 10 -o test.pcap` creates valid PCAP
- [ ] `python packet_analyzer.py -r test.pcap -v` reads and decodes verbosely
- [ ] `python simple_capture.py` runs without errors
- [ ] `python demo_analysis.py` analyzes sample_packets.pcap
- [ ] Ctrl+C during capture shows summary + saves PCAP (if `-o` used)

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| **Permission Denied** | Linux/macOS: `sudo` | Windows: Run PowerShell/CMD as **Administrator** |
| **No Packets Captured** | Check interface with `--list-interfaces`; verify traffic exists; try without filter |
| **Scapy Import Error** | `pip install --upgrade scapy` |
| **Windows Npcap Issues** | Install from https://npcap.com/ → check **"Install Npcap in WinPcap API-compatible Mode"** |
| **IPv6 Not Decoding** | Ensure scapy version ≥ 2.5.0 (`pip install --upgrade scapy`) |
| **HTTP Not Parsing** | HTTPS is encrypted — only HTTP (port 80) shows plaintext |

---

## 📚 Learning Resources

| Topic | Resource |
|-------|----------|
| Scapy Documentation | https://scapy.readthedocs.io/ |
| BPF Filter Syntax | https://biot.com/capstats/bpf.html |
| Wireshark Display Filters | https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html |
| TCP/IP Guide | https://www.tcpipguide.com/ |
| PCAP Format | https://wiki.wireshark.org/Development/LibpcapFileFormat |

---

## ✅ Submission Deliverables

- [ ] `packet_analyzer.py` — full-featured analyzer
- [ ] `simple_capture.py` — beginner script
- [ ] `demo_analysis.py` — PCAP analysis example
- [ ] `sample_packets.pcap` — sample capture
- [ ] `requirements.txt` — dependencies
- [ ] LinkedIn post with terminal screenshots (live capture, verbose output, stats)
- [ ] Video demo (2–3 min): list interfaces → live HTTP capture → PCAP save → offline analysis
- [ ] CodeAlpha submission form completed

---

## 🔗 Navigation

← **Task 02** [`../02_phishing_awareness_module/README.md`](../02_phishing_awareness_module/README.md) | **Master README** [`../README.md`](../README.md) | **Task 04 →** [`../04_network_ids/README.md`](../04_network_ids/README.md)