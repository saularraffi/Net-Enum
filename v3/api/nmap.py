from nmap3 import Nmap

class NmapScan():
    def __init__(self):
        print("Starting nmap scan...")
        nmap = Nmap()
        self.results = nmap.scan_top_ports(target="localhost")

    def scan(self):
        return self.results