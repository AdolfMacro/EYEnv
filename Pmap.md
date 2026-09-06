# EYE Network Vision
## Project Map & Development Handoff

Last Update:
2026-09-06

Author:
Mani Kamran

Repository:
https://github.com/AdolfMacro

---

# 1. Project Goal

EYE Network Vision is a modular network security analyzer.

The goal is not only packet capture.

The project tries to build a visibility layer over a network segment:

- Detect network segments
- Discover active nodes
- Capture network traffic
- Classify communication flows
- Analyze local/inbound/outbound behavior
- Generate security-oriented reports

Main idea:

"Understand what exists inside a network before analyzing attacks."

---

# 2. Current Architecture

                     UserInterface
                           |
                           |
                           v
                     NetworkSegment
                           |
           --------------------------------
           |                              |
           v                              v
     InterfaceScanner              ScapyCollector
                                      |
                                      v
                                 TrafficFlow
                                      |
                                      v
                            NetworkAnalyzer
                                      |
                                      v
                                 Report

Interfaces:
- CLI: `interface/user_interface.py`
- GUI: `interface/pyqt_interface.py` (PyQt6, hacker-style theme)

---

# 3. Project Structure

```
main.py

interface/
    user_interface.py
    pyqt_interface.py

collectors/
    scapy_collector.py
    interface_scanner.py

models/
    segment.py
    node.py
    traffic.py

tools/
    analyzer.py

docs/
    Pmap.md
```

---

# 4. Component Responsibilities

## main.py

Application entry point.

- Default mode: PyQt6 GUI
- CLI mode: `sudo python3 main.py --cli`
- Checks root privileges before launching GUI or CLI
- Does not contain analysis logic, packet processing, or network discovery

Flow:

main.py
  ↓
UserInterface (CLI or GUI)

---

## interface/user_interface.py

CLI interface.

Responsibilities:
- Terminal menu system
- Segment selection and creation
- Interface selection for capture
- Display analysis reports
- Developer info, repository link, architecture map

---

## interface/pyqt_interface.py

PyQt6 graphical interface.

Responsibilities:
- Segment management sidebar
- Live statistics cards (Nodes, Flows, Local, Outbound, Inbound, External)
- Overview tab with segment info, nodes table, traffic table
- Capture tab with interface selection, ARP discovery, live capture, terminal log
- Nodes tab with detailed node table
- Traffic tab with detailed traffic flows
- Reports tab with export to CSV/TXT
- Hacker-style dark theme with color-coded traffic classification

Key classes:
- `MainWindow` — main application window
- `StatCard` — live statistics card
- `TerminalLog` — styled terminal output widget
- `CaptureThread` — background packet capture thread
- `DiscoverThread` — background ARP discovery thread
- `NewSegmentDialog` — segment creation dialog
- `HackerPalette` — theme color constants

---

## collectors/interface_scanner.py

Network interface discovery.

Responsibilities:
- Enumerate all network interfaces using `psutil`
- Extract IPv4 address, netmask, and broadcast for each interface
- Return structured interface list for GUI/CLI selection

---

## collectors/scapy_collector.py

Active network interaction.

Responsibilities:
- ARP discovery using Scapy `srp()`
- Live traffic capture using Scapy `sniff()`
- Convert packets to `TrafficFlow` objects
- Provide callback-based API for GUI integration
- Stop flag support for graceful capture termination

Key behaviors:
- Blocks ARP discovery for networks larger than 256 addresses to prevent excessive broadcast
- Uses 1-second sniff timeout loops to enable responsive stop/cancel
- Emits per-flow callbacks for real-time GUI updates

---

## models/segment.py

Network segment data model.

Fields:
- name
- cidr
- nodes
- traffic
- access
- netmask
- network
- broadcast
- hosts

Methods:
- `add_node(node)`
- `add_traffic(traffic)`
- `add_access(access)`
- `load_traffic(flows)`
- `get_traffic_count()`

---

## models/node.py

Network node data model.

Fields:
- ip
- hostname
- status
- mac
- vendor
- services
- last_seen

---

## models/traffic.py

Traffic flow data model.

Fields:
- source
- destination
- protocol
- size

---

## tools/analyzer.py

Network analysis engine.

Responsibilities:
- Traffic classification: LOCAL, OUTBOUND, INBOUND, EXTERNAL
- Passive node discovery from captured traffic
- Node details extraction
- Traffic classification aggregation
- Full segment analysis report generation

Key methods:
- `classify_traffic(segment, flow)` — classify single flow
- `discover_nodes(segment)` — discover nodes from traffic
- `analyze_nodes(segment)` — extract node details
- `analyze_traffic(segment)` — aggregate traffic classification
- `segment_analyze(segment)` — full analysis result

---

# 5. Traffic Classification

Categories:

LOCAL
Source and destination inside segment.

OUTBOUND
Internal host communicating outside.

INBOUND
External source communicating with internal host.

EXTERNAL
Neither side belongs to segment.

---

# 6. Node Discovery

Two sources:

1. ARP discovery — active, via `ScapyCollector.discover_nodes()`
2. Traffic observation — passive, via `NetworkAnalyzer.discover_nodes()`

Duplicate prevention:
- GUI checks for existing IPs before adding nodes
- Analyzer only adds IPs not already in segment.nodes

---

# 7. Current Workflow

## GUI Workflow

1. User creates segment via dialog
   - Selects interface
   - Auto-fills CIDR, network, broadcast, available hosts
2. Segment appears in sidebar
3. User clicks segment to view overview
4. User starts capture or ARP discovery
5. Live traffic flows appear in terminal log and tables
6. Statistics update in real time
7. User exports nodes/traffic/report to CSV/TXT

## CLI Workflow

1. User selects "Analyze Network Segment"
2. System shows available networks
3. User selects network
4. System creates NetworkSegment
5. ScapyCollector performs ARP discovery
6. Analyzer generates initial report
7. User selects "Capture Traffic"
8. System captures traffic until keyboard interrupt
9. Analyzer discovers additional nodes from traffic
10. Final report displayed

---

# 8. Current Problems / TODO

## Resolved

- [x] Node discovery duplication — GUI and analyzer now deduplicate
- [x] Segment analysis order — segment created first, then discovery/capture
- [x] Better report — GUI provides tables and export; CLI shows classification
- [x] Large subnet ARP — blocked for networks >256 addresses
- [x] Capture stop mechanism — timeout-based loop for responsive stop
- [x] GUI stats sync — live statistics update during capture
- [x] Logging consistency — all logs use TerminalLog with color coding

## Future Improvements

- Hostname and vendor lookup
- Service detection
- Port scanning
- Communication graph generation
- Network topology visualization
- Risk analysis and alerts
- IDS rules integration
- Plugin system
- Persistent storage for segments and traffic

---

# 9. Security Analysis Roadmap

## Phase 1 (Completed)

Network Visibility

Done:
- [x] Interface detection
- [x] CIDR calculation
- [x] Segment detection
- [x] ARP discovery
- [x] Packet capture
- [x] Traffic classification
- [x] Node discovery
- [x] Basic reporting
- [x] CLI interface
- [x] PyQt6 GUI interface
- [x] Exportable reports

## Phase 2

Node Intelligence

Add:
- Hostname lookup
- MAC vendor lookup (OUI database)
- Service detection via banner grabbing
- Port scanning
- OS fingerprinting
- Passive asset discovery

## Phase 3

Behavior Analysis

Add:
- Suspicious communication detection
- Unusual outbound traffic alerts
- Unknown device detection
- Abnormal port usage detection
- DGA/DNS tunneling detection
- NTP amplification detection
- Port scan detection
- Risk scoring engine

## Phase 4

Security Engine

Add:
- IDS rule integration
- Attack pattern detection
- TLS/JA3 fingerprinting
- Credential extraction from cleartext protocols
- Pattern-based data leakage detection
- Alert system
- GeoIP lookup
- Threat intelligence integration

## Phase 5

Advanced Analysis

Add:
- PCAP save/load with full metadata
- Capture filters (BPF)
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
- JSON/XML/Excel export

---

# 10. Complete Sniffing Feature Set

## Capture Features
- Live packet capture
- PCAP file save/load
- Capture filters (BPF syntax)
- Multi-interface simultaneous capture
- Rolling capture buffers
- High-performance packet ingestion

## Protocol Support
- Ethernet / 802.11
- IPv4 / IPv6
- TCP / UDP / ICMP
- DHCP / DHCPv6
- DNS / DNSSEC
- HTTP / HTTPS
- TLS 1.0–1.3
- QUIC / HTTP3 / gRPC
- FTP / SFTP / FTPS
- SSH
- SIP / VoIP
- NTP / SNMP
- SMTP / IMAP / POP3
- ARP
- 802.1Q VLAN
- GRE / VXLAN / Geneve

## Traffic Analysis
- Deep packet inspection (L2–L7)
- Flow reconstruction
- Conversation tracking
- Protocol distribution
- Top talkers
- Bandwidth monitoring
- Packet timeline
- TCP stream reassembly
- UDP stream analysis
- Fragmentation detection
- Checksum validation

## Node Intelligence
- Hostname lookup
- MAC vendor lookup
- Service detection
- Port scanning
- OS fingerprinting
- Passive discovery

## Security Features
- Anomaly detection
- Suspicious traffic detection
- Port scan detection
- DGA detection
- Risk scoring
- Alerting
- JA3/JA4 fingerprinting
- TLS certificate inspection
- Credential extraction
- Pattern-based leakage detection

## Forensics
- PCAP offline analysis
- File extraction
- Email extraction
- Certificate extraction
- Keyword search
- Packet carving
- GeoIP lookup

## Visualization
- Network topology
- Traffic graphs
- Protocol hierarchy
- Conversation maps

## System Features
- Persistent storage
- Plugin system
- REST API
- Multi-format export
- Alert system
- Automated reports

---

# 10. Design Principles

- Do not put everything inside UserInterface
- Keep separation:
  - Interface: user interaction
  - Collector: network interaction
  - Model: data storage
  - Analyzer: logic
  - Report: output

---

# 11. Known Working Configuration

Interface:
wlp8s0

Network:
172.20.10.0/28

ARP Result:
172.20.10.1

Traffic Capture:
1235 flows

Classification:
OUTBOUND: 492
INBOUND: 743
LOCAL: 0
EXTERNAL: 0

---

# 12. Next Development Session

1. Add hostname lookup for discovered nodes
2. Add vendor lookup using MAC OUI database
3. Implement service detection via banner grabbing
4. Add port scanning module
5. Design communication graph data structure
6. Add persistent storage for segments and traffic

---

# Current Project State

Status:
Ready for first GitHub release

Goal achieved:
A working network visibility analyzer with:
- segment detection
- ARP discovery
- packet capture
- node discovery
- traffic classification
- CLI report
- PyQt6 GUI interface
- Exportable reports

Next phase:
Node intelligence and behavior analysis

END OF MAP
