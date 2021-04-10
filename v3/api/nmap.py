from nmap3 import Nmap

class NmapScan():
    def __init__(self, host):
        # print("[+] Starting nmap scan...")
        self.host = host
        self.nmap = Nmap()

    def initialScan(self):
        return self.nmap.scan_top_ports(target=self.host, args="-T4 -A -sV --version-intensity 9 --script vuln -p-")

    def quickScan(self):
        return self.nmap.scan_top_ports(target=self.host)

    def enumPort(self, port, scripts):
        return self.nmap.scan_top_ports(target=self.host, args='-p {} --script={}'
                                        .format(port, ','.join(scripts).replace(' ', '')))

    def scan(self):
        return self.quickScan()