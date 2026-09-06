# EYE Network Vision

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![PyQt6](https://img.shields.io/badge/PyQt6-6.5%2B-green)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-red)
![License](https://img.shields.io/badge/license-MIT-orange)

**EYE Network Vision** is a modular network visibility and security analysis platform built in Python. It goes beyond passive packet capture by building a structured view of your network: discovering segments, identifying hosts, classifying traffic flows, and surfacing security-relevant insights through both CLI and a real-time PyQt6 GUI.

---

## Why EYE Network Vision?

Most packet analyzers stop at collecting packets. EYE Network Vision is built to **understand the network**:

- **Who is communicating?**
- **Which devices belong to the local segment?**
- **Which connections leave the network?**
- **How are hosts related?**
- **What does the traffic reveal about the environment?**

Instead of drowning you in raw packets, it builds **models, relationships, and classifications** — making it useful for network mapping, incident response, and continuous monitoring.

---

## Key Features

### Core Capabilities
- **Automatic interface discovery** — enumerates active network interfaces with IPv4/netmask/broadcast
- **Automatic segment detection** — derives local CIDRs from interface configuration
- **Live packet capture** — real-time traffic ingestion via Scapy with callback-driven architecture
- **ARP-based active discovery** — sends ARP requests to enumerate live hosts on a segment
- **Passive node discovery** — extracts node identities from captured traffic flows
- **Traffic classification** — categorizes flows as `LOCAL`, `OUTBOUND`, `INBOUND`, or `EXTERNAL`
- **Structured data models** — `NetworkSegment`, `NetworkNode`, `TrafficFlow` with clean separation of concerns
- **Analysis engine** — aggregates traffic statistics, node details, and classification counts
- **Export & reporting** — export nodes, traffic, and full reports to CSV/TXT

### Graphical Interface (`--gui` / default)
- **Hacker-style dark theme** — professional terminal aesthetic with high-contrast color coding
- **Real-time statistics** — live cards for Nodes, Flows, Local, Outbound, Inbound, External
- **Overview tab** — segment metadata, active nodes table, traffic classification table
- **Capture tab** — interface selection, ARP discovery, live capture with terminal log
- **Nodes tab** — detailed node inventory with IP, MAC, hostname, status, services
- **Traffic tab** — full flow table with classification coloring
- **Dashboard tab** — live matplotlib charts:
  - Traffic classification pie chart
  - Protocol distribution bar chart
  - Bandwidth timeline
  - Node activity chart
- **Reports tab** — one-click export for nodes, traffic, and full security reports

### Command Line Interface (`--cli`)
- Interactive terminal menu
- Segment selection and creation
- Traffic capture with keyboard-interrupt stop
- Post-capture analysis and reporting

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User                                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
                ┌───────────▼────────────┐
                │   User Interface       │
                │  (CLI / PyQt6 GUI)     │
                └───────────┬────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │   NetworkSegment      │
                │  (CIDR, interface,    │
                │   nodes, traffic)     │
                └───────────┬───────────┘
                            │
           ┌────────────────┼────────────────┐
           │                │                │
           ▼                ▼                ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────┐
│ InterfaceScanner │ │ScapyCollector│ │NetworkAnalyzer│
│ - psutil         │ │- ARP disc.   │ │- classify     │
│ - IPv4/netmask   │ │- sniff()     │ │- discover     │
│ - broadcast      │ │- callbacks   │ │- report gen.  │
└──────────────────┘ └──────┬───────┘ └──────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  TrafficFlow     │
                    │  source, dst,    │
                    │  proto, size     │
                    └──────────────────┘
```

### Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| `main.py` | Entry point, privilege check, mode dispatch |
| `interface/user_interface.py` | CLI menus, terminal interaction |
| `interface/pyqt_interface.py` | PyQt6 GUI, theming, real-time dashboards |
| `collectors/interface_scanner.py` | Network interface enumeration |
| `collectors/scapy_collector.py` | ARP discovery, live packet capture |
| `models/segment.py` | Segment state: nodes, traffic, metadata |
| `models/node.py` | Node state: IP, MAC, hostname, services |
| `models/traffic.py` | Flow state: source, destination, protocol, size |
| `tools/analyzer.py` | Traffic classification, node discovery, reporting |

---

## Installation

### Prerequisites

- Python 3.10+
- Root / Administrator privileges (required for packet capture)
- Linux recommended (macOS and Windows partially supported)

### Setup

```bash
# Clone the repository
git clone https://github.com/AdolfMacro/EYE-Network-Vision.git
cd EYE-Network-Vision

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

```
scapy>=2.5.0
PyQt6>=6.5.0
psutil>=5.9.0
matplotlib>=3.7.0
```

---

## Usage

Run with **root privileges**:

### Graphical Interface (default)

```bash
sudo python3 main.py
```

### Command Line Interface

```bash
sudo python3 main.py --cli
```

### CLI Workflow

```
[+] Analyze Network Segment
[+] Discover Nodes
[+] Capture Traffic
[+] Generate Report
[+] Exit
```

### GUI Workflow

1. **Create a segment** — select an interface and auto-generated CIDR
2. **Select a segment** — view metadata and statistics in the sidebar
3. **Discover nodes** — ARP scan to find active hosts
4. **Start capture** — live traffic ingestion with real-time classification
5. **View dashboard** — live charts update as packets arrive
6. **Export** — save nodes, traffic, or full report to file

---

## Traffic Classification

| Class | Meaning |
|-------|---------|
| `LOCAL` | Both source and destination are inside the segment |
| `OUTBOUND` | Internal host communicating with an external destination |
| `INBOUND` | External source communicating with an internal host |
| `EXTERNAL` | Neither side belongs to the segment |

---

## Data Models

### NetworkSegment
```python
name: str
cidr: str
interface: str
nodes: List[NetworkNode]
traffic: List[TrafficFlow]
access: List
netmask: str
network: str
broadcast: str
hosts: int
```

### NetworkNode
```python
ip: str
hostname: str
status: str
mac: str
vendor: str
services: List[str]
last_seen: str
discovery_method: str
```

### TrafficFlow
```python
source: str
destination: str
protocol: int
size: int
timestamp: str
classification: str
```

---

## Project Structure

```
EYE-Network-Vision/
├── main.py                    # Entry point, privilege check, mode dispatch
├── interface/
│   ├── user_interface.py      # CLI interface
│   └── pyqt_interface.py      # PyQt6 GUI with hacker theme
├── collectors/
│   ├── scapy_collector.py     # ARP discovery + live packet capture
│   └── interface_scanner.py   # Network interface enumeration
├── models/
│   ├── segment.py             # NetworkSegment model
│   ├── node.py                # NetworkNode model
│   └── traffic.py             # TrafficFlow model
├── tools/
│   └── analyzer.py            # Traffic classification + analysis engine
├── docs/
│   └── Pmap.md                # Development roadmap and architecture map
├── requirements.txt
└── README.md
```

---

## Roadmap

### Phase 1 — Network Visibility ✅
- Interface detection
- Segment detection
- ARP discovery
- Packet capture
- Traffic classification
- Node discovery
- CLI + GUI
- Exportable reports

### Phase 2 — Node Intelligence
- Hostname lookup
- MAC vendor lookup (OUI database)
- Service detection via banner grabbing
- Port scanning
- OS fingerprinting
- Passive asset discovery

### Phase 3 — Behavior Analysis
- Suspicious communication detection
- Unusual outbound traffic alerts
- Unknown device detection
- Abnormal port usage detection
- DGA/DNS tunneling detection
- NTP amplification detection
- Port scan detection
- Risk scoring engine

### Phase 4 — Security Engine
- IDS rule integration
- Attack pattern detection
- TLS/JA3 fingerprinting
- Credential extraction from cleartext protocols
- Pattern-based data leakage detection
- Alert system
- GeoIP lookup
- Threat intelligence integration

### Phase 5 — Advanced Analysis
- PCAP save/load with full metadata
- Capture filters (BPF syntax)
- Multi-interface capture
- Deep packet inspection (L2–L7)
- TCP stream reassembly
- DNS/DHCP/SIP protocol parsers
- VLAN and tunnel decapsulation
- File extraction from HTTP/FTP/SMB
- Email and certificate extraction
- Network topology visualization
- Communication graphs
- Plugin system
- REST API
- Persistent storage

---

## Design Principles

- **Separation of Concerns** — Interface, Collector, Model, Analyzer, and Report layers are independent
- **Callback-driven capture** — GUI stays responsive during long-running sniff operations
- **No blocking UI** — all network I/O happens in background threads
- **Extensible models** — new traffic types and node attributes can be added without touching the capture layer
- **Security-first mindset** — the tool is built to understand networks, not just dump packets

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Mani Kamran**

- GitHub: [@AdolfMacro](https://github.com/AdolfMacro)
- Repository: [EYE-Network-Vision](https://github.com/AdolfMacro/EYE-Network-Vision)

---

*"Understand what exists inside a network before analyzing attacks."*
