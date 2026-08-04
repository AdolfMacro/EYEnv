import os

from models.segment import NetworkSegment
from collectors.scapy_collector import ScapyCollector
from collectors.interface_scanner import InterfaceScanner
from tools.analyzer import NetworkAnalyzer
import ipaddress

class UserInterface:

    def __init__(self):

        self.collector = None
        self.scanner = InterfaceScanner()
        self.analyzer = NetworkAnalyzer()
        self.segment = None

    def detect_segments(self, interfaces):

        segments = []

        for interface in interfaces:

            if not interface["ip"]:
                continue

            if not interface["netmask"]:
                continue

            try:

                network = ipaddress.ip_network(
                    f"{interface['ip']}/{interface['netmask']}",
                    strict=False
                )

                segments.append({

                    "name": interface["name"],

                    "ip": interface["ip"],

                    "cidr": str(network),

                    "netmask": interface["netmask"],

                    "network": str(network.network_address),

                    "broadcast": str(network.broadcast_address),

                    "available_hosts": network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2

                })


            except ValueError:

                continue


        return segments
    def start(self):

        while True:

            self.clear_terminal()

            self.show_banner()

            choice = input("\nSelect option: ")


            if choice == "1":

                self.analyze_segment()


            elif choice == "2":

                self.capture_traffic()


            elif choice == "3":

                self.developer_info()


            elif choice == "4":

                self.repository()


            elif choice == "5":

                self.architecture()


            elif choice == "0":

                self.clear_terminal()

                print(
                    "\nExiting EYE Network Vision..."
                )

                break


            else:

                print(
                    "\nInvalid option!"
                )


            input(
                "\nPress Enter to return to menu..."
            )


    def clear_terminal(self):

        os.system(
            "cls" if os.name == "nt" else "clear"
        )

    def show_banner(self):

        print("""
========================================
          EYE Network Vision
========================================

        Network Security Analyzer

----------------------------------------

1. Analyze Network Segment
2. Capture Traffic
3. Developer Info
4. Repository
5. Architecture Map
0. Exit

========================================
        """)


    def show_networks(self, networks):

        print("""
========================================
        Available Networks
========================================
        """)


        for index, network in enumerate(
            networks,
            start=1
        ):

            print(f"""
{index}. {network['name']}

   IP:
   {network['ip']}

   Netmask:
   {network['netmask']}

   Network:
   {network['cidr']}

    Broadcast:
    {network['broadcast']}

    Available Hosts:
    {network['available_hosts']}
            """)


        print("""
========================================
        """)



    def show_interfaces(self, interfaces):

        print("""
========================================
        Available Interfaces
========================================
        """)


        for index, interface in enumerate(
            interfaces,
            start=1
        ):

            print(
                f"{index}. {interface['name']} - {interface['ip']}"
            )


        print("""
========================================
        """)

    def analyze_segment(self):

            print("""
        [+] Segment Analyzer
        """)


            if self.segment is None:

                interfaces = self.scanner.get_interfaces()


                networks = self.detect_segments(
                    interfaces
                )


                self.show_networks(
                    networks
                )


                choice = int(
                    input("Select network: ")
                )


                selected = networks[choice - 1]


                self.segment = NetworkSegment(
                    selected["name"],
                    selected["cidr"]
                )


                self.segment.netmask = selected["netmask"]
                self.segment.network = selected["network"]
                self.segment.broadcast = selected["broadcast"]
                self.segment.hosts = selected["available_hosts"]


                self.collector = ScapyCollector(
                    selected["name"]
                )


                nodes = self.collector.discover_nodes(
                    self.segment
                )


                self.segment.nodes.extend(
                    nodes
                )


                print(
                    "\nSegment created successfully!"
                )


            result = self.analyzer.segment_analyze(
                self.segment
            )


            self.show_result(result)


    def show_result(self, result):

        classification = result["traffic"]["classification"]

        print(f"""
========================================
        Analysis Report
========================================

Segment:
{result['segment']}

CIDR:
{result['cidr']}


Nodes:
{result['nodes']['total']}


Traffic Flows:
{result['traffic']['total_flows']}


Traffic Classification:

LOCAL:
{classification['LOCAL']}

OUTBOUND:
{classification['OUTBOUND']}

INBOUND:
{classification['INBOUND']}

EXTERNAL:
{classification['EXTERNAL']}


Access Connections:
{len(result['access']['connections'])}


========================================
        """)


    def capture_traffic(self):

        print("""
[+] Traffic Collector
""")


        if self.segment is None:

            print(
                "\nCreate a segment first!"
            )

            return



        interfaces = self.scanner.get_interfaces()


        self.show_interfaces(interfaces)


        choice = int(
            input(
                "Select interface: "
            )
        )


        selected = interfaces[choice - 1]


        print(
            f"\nSelected: {selected['name']}"
        )
        self.collector = ScapyCollector(
        selected["name"]
        )


        try:

            flows = self.collector.capture()


        except KeyboardInterrupt:

            print(
                "\n\nCapture stopped by user."
            )

            return

        self.segment.load_traffic(
            flows
        )


        # Discover nodes from captured traffic
        self.analyzer.discover_nodes(
            self.segment
        )


        print(
            f"\nCaptured flows: {len(flows)}"
        )


    def developer_info(self):

        print("""
========================================
Developer Information
========================================

Name:
Mani Kamran

Role:
- Cybersecurity Enthusiast
- Python Developer
- Linux Explorer

Project:
EYE Network Vision

========================================
""")


    def repository(self):

        print("""
========================================
Repository
========================================

GitHub:
https://github.com/AdolfMacro

========================================
""")


    def architecture(self):

        print("""
========================================
Architecture Map
========================================

User Interface
       |
       v
Models
       |
       v
Collectors
       |
       v
Analyzer
       |
       v
Report

========================================
""")