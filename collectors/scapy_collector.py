from scapy.all import sniff, IP, ARP, Ether, srp

from models.traffic import TrafficFlow
from models.node import NetworkNode

import ipaddress



class ScapyCollector:


    def __init__(self, interface=None):

        self.interface = interface



    def discover_nodes(self, segment):

        nodes = []


        network = ipaddress.ip_network(
            segment.cidr
        )


        print("""
========================================
        Network Discovery
========================================
""")


        arp_request = Ether(
            dst="ff:ff:ff:ff:ff:ff"
        ) / ARP(
            pdst=[
                str(host)
                for host in network.hosts()
            ]
        )


        answered, _ = srp(

            arp_request,

            iface=self.interface,

            timeout=3,

            verbose=False

        )


        for _, response in answered:


            node = NetworkNode(

                ip=response.psrc,

                status="alive"

            )


            node.mac = response.hwsrc


            nodes.append(node)


            print(
                f"{node.ip} | MAC: {node.mac}"
            )


        print("""
========================================
""")


        return nodes




    def capture(self):

        flows = []


        print("""
========================================
        Live Traffic Capture
========================================

CTRL + C to stop

========================================
""")


        try:

            sniff(

                iface=self.interface,

                prn=lambda packet:
                    self.process_packet(
                        packet,
                        flows
                    ),

                store=False

            )


        except KeyboardInterrupt:

            print(
                "\nCapture stopped."
            )


        return flows




    def process_packet(self, packet, flows):

        flow = self.packet_to_flow(packet)


        if flow:

            flows.append(flow)


            print(

                f"{flow.source} --> "
                f"{flow.destination} | "
                f"Protocol: {flow.protocol} | "
                f"Size: {flow.size}"

            )



    def packet_to_flow(self, packet):


        if IP in packet:


            return TrafficFlow(

                source=packet[IP].src,

                destination=packet[IP].dst,

                protocol=packet[IP].proto,

                size=len(packet)

            )


        return None