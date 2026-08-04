import socket
import psutil


class InterfaceScanner:

    def get_interfaces(self):

        interfaces = []

        addresses = psutil.net_if_addrs()


        for name, addr_list in addresses.items():

            interface = {
                "name": name,
                "ip": None,
                "netmask": None,
                "broadcast": None
            }


            for addr in addr_list:

                if addr.family == socket.AF_INET:

                    interface["ip"] = addr.address
                    interface["netmask"] = addr.netmask
                    interface["broadcast"] = addr.broadcast


            interfaces.append(interface)


        return interfaces


    def show_interfaces(self):

        interfaces = self.get_interfaces()


        print("""
========================================
     Available Network Interfaces
========================================
""")


        for index, interface in enumerate(
            interfaces,
            start=1
        ):

            print(f"{index}. {interface['name']}")
            print(f"   IP: {interface['ip']}")
            print(f"   Netmask: {interface['netmask']}")
            print(f"   Broadcast: {interface['broadcast']}")


        print("""
========================================
""")

        return interfaces