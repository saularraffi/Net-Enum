import requests
import time
from threading import Thread
from api.nmap import NmapScan

class WebEnum():
    def __init__(self, host, port=80, dirBrutewordlist='/usr/share/wordlists/dirb/common.txt'):
        self.host = host
        self.port = port
        self.dirBrutewordlist = dirBrutewordlist
        self.directories = {}

    def _dirBrute(self, dir):
        url = "http://{}:{}/{}".format(self.host, self.port, dir)
        res = requests.get(url)
        if res.status_code != 404:
            self.directories['/' + dir.strip()] = res.status_code

    def dirBrute(self):
        dirs = open(self.dirBrutewordlist, 'r')

        for dir in dirs:
            dir = dir.strip()
            t = Thread(target=self._dirBrute, args=(dir,))
            t.daemon = True
            t.start()
            time.sleep(0.05)

        return self.directories

    def nmapEnum(self):
        nmap = NmapScan(self.host)
        return nmap.enumPort(self.port, ['http-enum.nse'])

    def scan(self):
        # return self.dirBrute()
        return self.nmapEnum()