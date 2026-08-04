# EYE Network Vision

A modular network visibility and security analysis tool built with Python.

Rather than focusing only on packet capture, EYE Network Vision aims to understand the structure and behavior of a network by discovering devices, classifying traffic, mapping communication, and providing meaningful security insights.

---

## Project Goals

* Discover available network interfaces
* Detect local network segments automatically
* Capture live network traffic
* Build structured traffic models
* Distinguish local and external communication
* Discover active hosts
* Analyze communication relationships
* Generate security-oriented reports

---

## Current Features

* Modular architecture
* Automatic network interface discovery
* Automatic network segment detection
* Live packet capture using Scapy
* TrafficFlow data model
* NetworkSegment data model
* Basic network analysis engine
* Command Line Interface (CLI)

---

## Project Structure

```
main.py

interface/
    user_interface.py

collectors/
    interface_scanner.py
    network_discovery.py
    scapy_collector.py

models/
    node.py
    traffic.py
    segment.py

tools/
    analyzer.py
    traffic_classifier.py

docs/
```

---

## Architecture

```
User
  |
  v
User Interface
  |
  v
Network Discovery
  |
  v
NetworkSegment
  |
  +---------------------------+
  |                           |
  v                           v
Interface Scanner       Scapy Collector
                              |
                              v
                         TrafficFlow
                              |
                              v
                     Traffic Classifier
                              |
                              v
                      Network Analyzer
                              |
                              v
                           Report
```

---

## Technology Stack

* Python 3
* Scapy
* ipaddress
* Standard Library

---

## Roadmap

### Completed

* Project architecture
* CLI interface
* Interface detection
* Segment model
* Traffic model
* Live traffic capture
* Basic analyzer

### In Progress

* Local / External traffic classification
* Automatic host discovery
* Communication graph generation

### Planned

* Port scanning
* Service detection
* Network topology visualization
* Risk analysis
* Exportable reports
* Plugin system

---

## Why This Project?

Most packet capture tools stop at collecting packets.

The goal of EYE Network Vision is different.

Instead of only displaying raw traffic, the project is designed to understand the network itself:

* Who is communicating?
* Which devices belong to the local segment?
* Which connections leave the network?
* How are hosts related?
* What does the traffic reveal about the environment?

Each module is developed independently following the **Separation of Responsibilities** principle, making the project easier to maintain and extend.

---

## Running

Run the application with administrator/root privileges.

```bash
sudo python3 main.py
```

---

## License

This project is released under the MIT License.
