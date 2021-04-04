import requests
import time
from threading import Thread
from api.nmap import NmapScan
import socket
import jsonmerge
import json
from jsonmerge import Merger

class WebEnum():
    def __init__(self, host, port=80, nmapScripts=None, dirBrutewordlist='/usr/share/wordlists/dirb/common.txt'):
        if nmapScripts is None:
            self.nmapScripts = ['http-enum.nse, http-methods.nse']
        else:
            self.nmapScripts = nmapScripts
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
            time.sleep(0.01)

        return {'directories': self.directories}

    def runNmapScripts(self):
        nmap = NmapScan(self.host)
        scriptResults = nmap.enumPort(self.port, self.nmapScripts)[self.host]['ports'][0]['scripts']
        return {'nmapScripts': scriptResults}

    def spider(self, depth=1):
        print("Spidering website")

    def bannerGrab(self):
        s = socket.socket()
        s.connect((self.host, self.port))
        s.send(b'GET /\n\n')
        banner = s.recv(10000).decode('utf-8')
        return {'banner': banner}

    def scan(self):
        # bruteResuts = self.dirBrute()
        # nmapScriptResults = self.runNmapScripts()
        # bannerGrabResults = self.bannerGrab()

        schema = {
            'properties': {
                'items': {
                    'type': 'objects'
                }
            }
        }

        merger = Merger(schema)

        bruteResuts = {'bla1': 'bla1'}
        nmapScriptResults = {'bla2': 'bla2'}
        bannerGrabResults = {'bla3': 'bla3'}

        results = None
        results = merger.merge(results, bruteResuts)
        results = merger.merge(results, nmapScriptResults)
        results = merger.merge(results, bannerGrabResults)

        return {self.port, json.dumps(results)}