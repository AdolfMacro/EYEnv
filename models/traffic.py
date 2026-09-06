class TrafficFlow:

    def __init__(self, source, destination, protocol, size, payload=None):
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.size = size
        self.payload = payload