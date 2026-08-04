class NetworkSegment:

    def __init__(self, name, cidr):
        self.name = name
        self.cidr = cidr
        self.nodes = []
        self.traffic = []
        self.access = []


    def add_node(self, node):
        self.nodes.append(node)


    def add_traffic(self, traffic):
        self.traffic.append(traffic)


    def add_access(self, access):
        self.access.append(access)


    def load_traffic(self, flows):

        for flow in flows:
            self.add_traffic(flow)


    def get_traffic_count(self):

        return len(self.traffic)