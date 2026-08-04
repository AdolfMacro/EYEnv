# EYE Network Vision
## Project Map & Development Handoff

Last Update:
2026-08-04

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

    ScapyCollector              NetworkAnalyzer


          |                              |

          v                              v

     TrafficFlow                  Analysis Report

          |
          |
          v

       NetworkNode



---

# 3. Project Structure


EYEmpr/

│
├── main.py
│
├── interface/
│   └── user_interface.py
│
├── collectors/
│   ├── scapy_collector.py
│   └── interface_scanner.py
│
├── models/
│   ├── segment.py
│   ├── node.py
│   └── traffic.py
│
├── tools/
│   └── analyzer.py
│
└── docs/
    └── PROJECT_MAP.md



---

# 4. Component Responsibilities


## main.py

Only application entry point.

Should not contain:

- analysis logic
- packet processing
- network discovery


Flow:

main.py

↓

UserInterface

---

# 5. Models


## NetworkSegment


Responsible for storing selected network information.


Current data:

- name
- cidr
- network
- broadcast
- netmask
- hosts
- nodes
- traffic
- access



Example:

172.20.10.0/28



---

## NetworkNode


Represents discovered devices.


Current structure:


class NetworkNode:

    ip

    hostname

    status

    mac

    vendor

    services

    last_seen



Node sources:

1. ARP discovery
2. Traffic observation


---

## TrafficFlow


Represents captured communication.


Current fields:

- source
- destination
- protocol
- size



---

# 6. Collectors


## ScapyCollector


Responsible for active network interaction.


Current responsibilities:


## 1. ARP Discovery


Uses:

Scapy srp()

Purpose:

Discover alive devices before traffic capture.


Example:


172.20.10.1

MAC:

a2:fb:c5:96:7b:64



## 2. Traffic Capture


Uses:

Scapy sniff()


Converts packets into:


TrafficFlow


Current captured data:

- IP source
- IP destination
- protocol
- packet size



---

# 7. Analyzer


File:

tools/analyzer.py



Responsibilities:


## Traffic Classification


Categories:


LOCAL

Source and destination inside segment.



OUTBOUND

Internal host communicating outside.



INBOUND

External source communicating with internal host.



EXTERNAL

Neither side belongs to segment.






## Node Discovery From Traffic


Function:

discover_nodes(segment)



Purpose:

Find nodes even if ARP discovery missed them.



Logic:


Traffic Flow

↓

Check source/destination

↓

Is IP inside segment?

↓

Create NetworkNode if new



Important:

This works even when:

- ARP discovery finds nothing
- passive traffic exists later



---

# 8. Current Workflow


## Step 1

User selects:

Analyze Network Segment



Example:

wlp8s0

CIDR:

172.20.10.0/28



---

## Step 2

Create:

NetworkSegment



---

## Step 3

ScapyCollector performs:

ARP discovery



Example result:


172.20.10.1

MAC: xx:xx:xx



---

## Step 4

Analyzer generates initial report.



Example:


Nodes:

1


Traffic:

0



---

## Step 5

User captures traffic.



Example:


1235 flows


LOCAL:

0

OUTBOUND:

492

INBOUND:

743

EXTERNAL:

0



---

## Step 6

Analyzer discovers additional nodes from traffic.



---

# 9. Current Problems / TODO


## High Priority


### 1. Node Discovery Duplication

Currently nodes can come from:

- ARP
- Traffic


Need one unified method:


merge_nodes()



Purpose:

Avoid duplicate IP entries.



---

### 2. Segment Analysis Order


Current:


ARP Discovery

↓

Traffic Capture

↓

Traffic Node Discovery



Future:


Create Segment

↓

Discover Nodes

↓

Capture Traffic

↓

Update Nodes

↓

Analyze



---

### 3. Better Report


Current report:

- nodes count
- traffic classification



Need:


Node table:

IP
MAC
Status
Vendor


Traffic table:

Source
Destination
Protocol
Type



---

# 10. Security Analysis Roadmap


## Phase 1 (Current)

Network Visibility


Done:

[x] Interface detection

[x] CIDR calculation

[x] ARP discovery

[x] Packet capture

[x] Traffic classification

[x] Basic reporting



---

## Phase 2


Node Intelligence


Add:


- hostname lookup
- vendor lookup
- service detection
- port analysis



---

## Phase 3


Behavior Analysis


Add:


- suspicious communication detection

- unusual outbound traffic

- unknown devices

- abnormal ports



---

## Phase 4


Security Engine


Possible modules:


- IDS rules

- attack pattern detection

- risk scoring

- alerts



---

# 11. Design Principles


IMPORTANT:


Do not put everything inside UserInterface.



Keep separation:


Interface:

User interaction


Collector:

Network interaction


Model:

Data storage


Analyzer:

Logic


Report:

Output



---

# 12. Current Known Working Test


Interface:

wlp8s0


Network:

172.20.10.0/28



ARP Result:

172.20.10.1



Traffic Capture:

1235 flows



Classification:


OUTBOUND:

492


INBOUND:

743


LOCAL:

0


EXTERNAL:

0



---

# 13. Next Development Session


First tasks:


1. Review current files:

- node.py
- segment.py
- traffic.py
- scapy_collector.py
- analyzer.py


2. Fix node merging system.


3. Improve report output.


4. Prepare first GitHub version.


5. Add README explaining architecture.



---

# Current Project State

Status:

Prototype / MVP


Goal for first GitHub release:

A working network visibility analyzer with:

- segment detection
- ARP discovery
- packet capture
- node discovery
- traffic classification
- CLI report


در نسخه بعدی EYE Network Vision، ابزار از حالت منوی ساده خارج شده و یک رابط CLI واقعی دریافت می‌کند؛ به شکلی که کاربر بتواند با دستورها عملیات مختلف را اجرا کند. تمام ترافیک‌های Capture شده باید ذخیره‌سازی شوند تا بعداً بدون نیاز به Capture مجدد داخل CLI قابل بررسی، فیلتر و تحلیل باشند و امکان Export گزارش‌ها و داده‌ها نیز فراهم شود. ساختار پروژه باید به سمت یک Network Visibility Platform کوچک حرکت کند؛ به طوری که هر Segment شناسایی‌شده دارای اطلاعات کامل شبکه، Broadcast، Host Range، Nodeهای فعال و وضعیت آن‌ها باشد. هر Node باید قابلیت بررسی جداگانه داشته باشد و اطلاعاتی مانند IP، MAC، Vendor، سرویس‌های مشاهده‌شده، آخرین زمان مشاهده و Traffic مربوط به آن ذخیره شود. همچنین تمام Segmentها و Nodeها باید قابلیت Query و تحلیل مستقل داشته باشند تا کاربر بتواند وضعیت شبکه، ارتباطات، Flowها و رفتارهای مشاهده‌شده را در هر زمان از طریق CLI بررسی کند.

END OF MAP