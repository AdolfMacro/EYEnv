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
AI-powered behavior analysis and intrusion detection

---

# 13. AI Infrastructure Roadmap

## Overview

Transform EYE Network Vision into an intelligent network security platform that:
- Learns normal behavior patterns
- Detects anomalies and intrusions
- Inspects suspicious payloads
- Generates actionable alerts

## Phase 1 — Foundation: Feature Engineering & Storage

### 1.1 Feature Extractor
**Location:** `features/extractor.py`  
**Input:** `TrafficFlow` objects  
**Output:** Numerical feature vectors

Features to extract:
- `packet_size` — total bytes
- `protocol` — IP protocol number
- `src_port` / `dst_port` — transport layer ports
- `duration` — flow duration (if available)
- `byte_rate` — bytes per second
- `packet_count` — number of packets in flow
- `payload_entropy` — randomness of payload
- `is_encrypted` — TLS/SSL detection
- `tls_version` — if applicable
- `ja3_hash` — TLS fingerprint
- `dns_query_length` — for DNS flows
- `http_method` — for HTTP flows
- `has_credentials` — regex match for passwords/tokens

Output format:
```python
{
    "flow_id": str,
    "timestamp": str,
    "features": [64, 6, 52341, 443, 0.05, 1280, 1, 4.2, ...],
    "feature_names": ["packet_size", "protocol", ...],
    "metadata": {"src_ip": "...", "dst_ip": "..."}
}
```

### 1.2 Data Store
**Location:** `tools/storage.py`  
**Backend:** SQLite (start) → TimescaleDB (future)

Tables:
- `flows` — raw captured flows
- `features` — extracted feature vectors
- `alerts` — generated alerts
- `profiles` — behavioral baselines per host
- `labels` — user feedback (true/false positive)

Schema:
```sql
CREATE TABLE flows (
    id INTEGER PRIMARY KEY,
    segment_id TEXT,
    source TEXT,
    destination TEXT,
    protocol INTEGER,
    size INTEGER,
    timestamp TEXT,
    classification TEXT
);

CREATE TABLE features (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER,
    features TEXT,  -- JSON array
    feature_names TEXT,  -- JSON array
    timestamp TEXT
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    severity TEXT,  -- LOW/MEDIUM/HIGH/CRITICAL
    category TEXT,  -- anomaly/payload/behavior
    description TEXT,
    flow_id INTEGER,
    score REAL,
    timestamp TEXT,
    acknowledged BOOLEAN DEFAULT FALSE
);

CREATE TABLE profiles (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE,
    baseline TEXT,  -- JSON: {mean_packet_size, std_packet_size, ...}
    last_seen TEXT,
    flow_count INTEGER
);

CREATE TABLE labels (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER,
    label TEXT,  -- normal/anomalous
    feedback TEXT,
    timestamp TEXT
);
```

### 1.3 API Layer
**Location:** `api/`  
**Framework:** FastAPI

Endpoints (v0.1):
- `GET /health` — health check
- `POST /api/v1/flows` — ingest new flow
- `POST /api/v1/flows/batch` — batch ingest
- `GET /api/v1/flows` — query flows with filters
- `GET /api/v1/features/{flow_id}` — get features for a flow
- `GET /api/v1/alerts` — get recent alerts
- `POST /api/v1/alerts/{alert_id}/ack` — acknowledge alert
- `GET /api/v1/profiles` — get all behavioral profiles
- `POST /api/v1/profiles/{ip}/rebuild` — rebuild profile for host

## Phase 2 — Behavioral Profiling & Anomaly Detection

### 2.1 Behavioral Profiler
**Location:** `ai/profiler.py`

Per-host baseline:
- `mean_packet_size`, `std_packet_size`
- `common_ports` — top 10 ports
- `common_protocols` — protocol distribution
- `active_hours` — histogram of activity by hour
- `frequent_partners` — top 10 communicating IPs
- `avg_byte_rate` — average bytes per second
- `connection_patterns` — inbound/outbound ratio

Update strategy:
- Initial baseline after 100 flows
- Exponential moving average for updates
- Rebuild on significant change detection

### 2.2 Anomaly Detector
**Location:** `ai/anomaly.py`

Models:
1. **Statistical Detector**
   - Z-score for packet size, byte rate, port count
   - Threshold: 3σ default
   - Output: anomaly score (0-1)

2. **Isolation Forest**
   - Scikit-learn implementation
   - Features: packet_size, protocol, ports, entropy
   - Contamination: 0.1 (10% expected anomalies)
   - Retrain: every 1000 new flows

3. **Rule-based Detector**
   - Port scan detection: >10 unique ports in 60s
   - DNS tunneling: high DNS query entropy + large responses
   - Unusual port: well-known port used unexpectedly
   - Off-hours activity: outside normal business hours

Output:
```python
{
    "flow_id": str,
    "anomaly_score": 0.85,  # 0-1
    "detectors": {
        "statistical": {"score": 0.9, "triggered": True},
        "isolation_forest": {"score": 0.7, "triggered": True},
        "rule_based": {"score": 1.0, "triggered": True}
    },
    "is_anomaly": True,
    "reasons": ["Unusual port", "Off-hours activity"]
}
```

## Phase 3 — Deep Packet Inspection & Alerting

### 3.1 Payload Inspector
**Location:** `ai/inspector.py`

Capabilities:
- TLS/JA3 fingerprint extraction
- DNS query analysis (length, entropy, TTL)
- HTTP header inspection (user-agent, methods)
- Credential pattern detection (regex for passwords, tokens)
- Payload entropy calculation
- Suspicious string matching

### 3.2 Alert Engine
**Location:** `ai/alerts.py`

Severity levels:
- **LOW** — minor deviation, informational
- **MEDIUM** — suspicious pattern, needs review
- **HIGH** — likely malicious, immediate attention
- **CRITICAL** — confirmed attack, action required

Scoring:
- Each detector contributes points
- Correlation: multiple medium alerts → HIGH
- Time decay: old alerts lose severity

### 3.3 GUI Integration
**Location:** `interface/pyqt_interface.py`

New tabs/widgets:
- `AlertsTab` — list of active alerts with severity colors
- `AlertDetailDialog` — drill-down into alert details
- `PayloadViewer` — hex/ASCII view of suspicious packet
- `ProfileViewer` — behavioral baseline for selected host

Real-time updates:
- New alerts appear in sidebar
- Sound notification for HIGH/CRITICAL
- Auto-scroll to latest alert

## Phase 4 — Advanced ML & Feedback

### 4.1 Model Management
**Location:** `ai/models/`

- MLflow integration for model versioning
- A/B testing framework
- Model performance metrics (precision, recall, F1)
- Auto-retraining pipeline (daily/weekly)

### 4.2 Feedback Loop
**Location:** `interface/pyqt_interface.py` + `ai/feedback.py`

UI:
- Right-click alert → "Mark as False Positive"
- Right-click alert → "Mark as True Positive"
- Bulk labeling for training data

Backend:
- Store labels in `labels` table
- Retrain model when enough new labels
- Track model improvement over time

### 4.3 REST API Complete
**Location:** `api/`

- WebSocket for real-time alerts
- Authentication (JWT)
- Rate limiting
- OpenAPI documentation

## Implementation Order

1. **Feature Extractor** (`features/extractor.py`) — 2 days
2. **Data Store** (`tools/storage.py`) — 1 day
3. **API Layer** (`api/main.py`) — 1 day
4. **Behavioral Profiler** (`ai/profiler.py`) — 2 days
5. **Anomaly Detector** (`ai/anomaly.py`) — 2 days
6. **Payload Inspector** (`ai/inspector.py`) — 1 day
7. **Alert Engine** (`ai/alerts.py`) — 1 day
8. **GUI Integration** (alerts tab) — 2 days
9. **Model Management** (optional) — 3 days
10. **Feedback Loop** (optional) — 2 days

**Total estimated:** 14-17 days for core AI infrastructure

---

# 14. Technical Decisions

## ML Framework
- **Scikit-learn** — Isolation Forest, Random Forest, statistical methods
- **No deep learning initially** — too complex, need labeled data
- **Future:** TensorFlow/PyTorch for LSTM/Transformer

## Database
- **Start:** SQLite — simple, no extra infrastructure
- **Scale:** TimescaleDB — time-series optimized, PostgreSQL compatible

## API
- **FastAPI** — async, auto-documentation, type hints
- **Uvicorn** — ASGI server
- **WebSocket** — real-time alerts

## Deployment
- Docker container for AI services
- Separate from capture GUI for scalability
- Optional: Kubernetes for production

---

# 15. Success Metrics

- **False Positive Rate:** < 20% after 1 week of learning
- **Detection Rate:** > 80% for known attack patterns
- **Latency:** < 1s from packet capture to alert
- **Usability:** Analyst can triage alerts in < 5 minutes

---

END OF MAP
