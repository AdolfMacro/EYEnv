from scapy.all import sniff, IP, ARP, Ether, srp, Raw

from models.traffic import TrafficFlow
from models.node import NetworkNode

import ipaddress



class ScapyCollector:


    def __init__(self, interface=None):

        self.interface = interface



    def discover_nodes(self, segment, on_node=None):

        nodes = []


        network = ipaddress.ip_network(
            segment.cidr
        )


        if network.num_addresses > 256:

            raise ValueError(
                f"Network {segment.cidr} is too large for ARP discovery. "
                f"Use a smaller subnet."
            )


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


            if on_node:

                on_node(node)


        return nodes




    def capture(self, on_flow=None, stop_flag=None):

        flows = []

        active = True

        if stop_flag is not None:

            active = stop_flag()


        def packet_callback(packet):

            flow = self.packet_to_flow(packet)


            if flow:

                flows.append(flow)

                if on_flow:

                    on_flow(flow)



        try:

            while active:

                sniff(

                    iface=self.interface,

                    prn=packet_callback,

                    store=False,

                    timeout=1,

                    stop_filter=(lambda p: not active) if stop_flag else None

                )


                if stop_flag is not None:

                    active = stop_flag()


        except KeyboardInterrupt:

            print(
                "\nCapture stopped."
            )


        return flows

    def packet_to_flow(self, packet):
        if IP in packet:
            payload = b""
            if Raw in packet:
                payload = bytes(packet[Raw].load)
            return TrafficFlow(
                source=packet[IP].src,
                destination=packet[IP].dst,
                protocol=packet[IP].proto,
                size=len(packet),
                payload=payload,
            )
        return None