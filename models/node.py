class NetworkNode:

    def __init__(
        self,
        ip,
        hostname=None,
        status="unknown"
    ):

        self.ip = ip

        self.hostname = hostname

        self.status = status

        self.mac = None

        self.vendor = None

        self.services = []

        self.last_seen = None