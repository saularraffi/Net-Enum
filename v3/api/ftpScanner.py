import socket
from ftplib import FTP
from termcolor import colored
from api.nmap import NmapScan
from jsonmerge import Merger

class FtpScanner():
    def __init__(self, host='127.0.0.1', port=21, ftpScripts=None):
        print(colored("[+] Starting ftp scanner...", 'green'))
        if ftpScripts is None:
            self.nmapScripts = ['ftp-anon.nse']
        else:
            self.nmapScripts = ftpScripts
        self.host = host
        self.port = port

    def bannerGrab(self):
        print(colored("\t[+] Grabbing ftp banner...", 'green'))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))
            response = s.recv(1024)
            s.close()
            return {'banner': response.decode('utf-8').strip()}

        except:
            print(colored('\t\t[-] Nework error with grabbing ftp banner', 'red'))
            return None

    def checkAnonymousLogin(self):
        print(colored("\t[+] Checking ftp anonymous login...", 'green'))

    def runNmapScripts(self):
        print(colored("\t[+] Running http nmap scripts...", 'green'))
        nmap = NmapScan(self.host)
        scriptResults = nmap.enumPort(self.port, self.nmapScripts)[self.host]['ports'][0]['scripts']
        return {'nmapScripts': scriptResults}

    def getFiles(self, username='anonymous', password=''):
        print(colored("\t[+] Retrieving files from ftp server...", 'green'))
        ftp = FTP(self.host)

        try:
            ftp.login(user=username, passwd=password)
            return {'files': ftp.nlst()}

        except:
            print(colored('\t\t[-] Error retrieving files from ftp server', 'red'))

    def scan(self):
        bannerGrabResults = self.bannerGrab()
        nmapScriptResults = self.runNmapScripts()
        fileListingResults = self.getFiles()

        schema = {'properties': {'items': {'type': 'objects'}}}

        merger = Merger(schema)

        results = None
        results = merger.merge(results, bannerGrabResults)
        results = merger.merge(results, nmapScriptResults)
        results = merger.merge(results, fileListingResults)

        return {self.port: results}