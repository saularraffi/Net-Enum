from termcolor import colored
from api.nmap import NmapScan

class SmbScanner():
    def __init__(self, host='127.0.0.1', port=445, smbScripts=None, disablePing=False):
        print(colored("[+] Starting smb scanner...", 'green'))
        if smbScripts is None:
            self.nmapScripts = ['smb-os-discovery.nse', 'smb-vuln*']
        else:
            self.nmapScripts = smbScripts
        self.host = host
        self.port = port
        self.disablePing = disablePing

    def runNmapScripts(self):
        # TODO: NOT RETURNING SCRIPT RESULTS
        print(colored("\t[+] Running smb nmap scripts...", 'green'))
        nmap = NmapScan(host=self.host, disablePing=self.disablePing)
        scriptResults = nmap.enumPort(self.port, self.nmapScripts)[self.host]['ports'][0]['scripts']
        return {'nmapScripts': scriptResults}

    def scan(self):
        return self.runNmapScripts()