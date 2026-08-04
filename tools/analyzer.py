import ipaddress

from models.node import NetworkNode


class NetworkAnalyzer:


    def classify_traffic(self, segment, flow):

        network = ipaddress.ip_network(
            segment.cidr
        )

        source = ipaddress.ip_address(
            flow.source
        )

        destination = ipaddress.ip_address(
            flow.destination
        )


        if source in network and destination in network:

            return "LOCAL"


        if source in network:

            return "OUTBOUND"


        if destination in network:

            return "INBOUND"


        return "EXTERNAL"



    def discover_nodes(self, segment):

        """
        Passive Node Discovery
        Discover nodes from captured traffic
        """

        if not segment.traffic:

            return


        network = ipaddress.ip_network(
            segment.cidr
        )


        discovered_ips = set()


        for flow in segment.traffic:


            source = ipaddress.ip_address(
                flow.source
            )


            destination = ipaddress.ip_address(
                flow.destination
            )


            if source in network:

                discovered_ips.add(
                    flow.source
                )


            if destination in network:

                discovered_ips.add(
                    flow.destination
                )



        existing_ips = {

            node.ip

            for node in segment.nodes

        }



        for ip in discovered_ips:


            if ip not in existing_ips:


                node = NetworkNode(

                    ip=ip,

                    hostname=None,

                    status="observed"

                )


                node.discovery_method = "TRAFFIC"


                segment.nodes.append(
                    node
                )



    def analyze_nodes(self, segment):

        nodes = []


        for node in segment.nodes:


            nodes.append({

                "ip": node.ip,

                "hostname": node.hostname,

                "status": node.status,

                "mac": node.mac,

                "vendor": node.vendor,

                "services": node.services,

                "last_seen": node.last_seen,

                "discovery_method": getattr(
                    node,
                    "discovery_method",
                    "UNKNOWN"
                )

            })


        return nodes



    def analyze_traffic(self, segment):

        classification = {

            "LOCAL": 0,

            "OUTBOUND": 0,

            "INBOUND": 0,

            "EXTERNAL": 0

        }


        for flow in segment.traffic:


            category = self.classify_traffic(
                segment,
                flow
            )


            classification[category] += 1



        return classification



    def segment_analyze(self, segment):


        # Passive discovery from traffic
        self.discover_nodes(
            segment
        )


        result = {


            "segment": segment.name,


            "cidr": segment.cidr,


            "network": getattr(
                segment,
                "network",
                None
            ),


            "broadcast": getattr(
                segment,
                "broadcast",
                None
            ),


            "nodes": {

                "total": len(segment.nodes),

                "details": self.analyze_nodes(
                    segment
                )

            },


            "traffic": {

                "total_flows": len(segment.traffic),

                "classification": self.analyze_traffic(
                    segment
                )

            },


            "access": {

                "connections": segment.access

            }

        }


        return result