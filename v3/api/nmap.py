from nmap3 import Nmap
from termcolor import colored

class NmapScan():
    def __init__(self, host, disablePing=False):
        # print("[+] Starting nmap scan...")
        self.host = host
        self.disablePing = disablePing
        self.nmap = Nmap()

    def fullScan(self):
        print(colored("[+] Starting nmap full scan...", 'green'))
        disablePing = '-Pn' if self.disablePing else ''
        return self.nmap.scan_top_ports(target=self.host, args="-T4 -A -sV --version-intensity 9 --script vuln -p- {}"
                                        .format(disablePing))

    def quickScan(self):
        print(colored("[+] Starting nmap quick scan...", 'green'))
        disablePing = '-Pn' if self.disablePing else ''
        return self.nmap.scan_top_ports(target=self.host, args='{}'.format(disablePing))

    def enumPort(self, port, scripts):
        print(colored("\t[+] Starting nmap scripts...", 'green'))
        disablePing = '-Pn' if self.disablePing else ''
        return self.nmap.scan_top_ports(target=self.host, args='-p {} --script={} {}'
                                        .format(port, ','.join(scripts).replace(' ', ''), disablePing))

    def scan(self):
        return self.quickScan()