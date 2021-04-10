from threading import Thread
from api.nmap import NmapScan
from jsonmerge import Merger
from termcolor import colored
from lxml import html, etree
import socket
import jsonmerge
import json
import requests
import time
from bs4 import BeautifulSoup, Comment


class WebScanner():
    def __init__(self, host='127.0.0.1', port=80, nmapScripts=None,
                 dirBrutewordlist='/usr/share/wordlists/dirb/common.txt', disablePing=False, spiderDepth=2):
        print(colored("[+] Starting web scanner...", 'green'))
        if nmapScripts is None:
            self.nmapScripts = ['http-enum.nse', 'http-methods.nse']
        else:
            self.nmapScripts = nmapScripts
        self.host = host
        self.port = port
        self.dirBrutewordlist = dirBrutewordlist
        self.directories = {}
        self.disablePing = disablePing
        self.spiderDepth = spiderDepth

    def _dirBrute(self, dir):
        url = "http://{}:{}/{}".format(self.host, self.port, dir)
        res = requests.get(url)
        if res.status_code != 404:
            self.directories['/' + dir.strip()] = res.status_code

    def dirBrute(self):
        print(colored("\t[+] Brute forcing web directories...", 'green'))
        dirs = open(self.dirBrutewordlist, 'r')

        for dir in dirs:
            dir = dir.strip()
            t = Thread(target=self._dirBrute, args=(dir,))
            t.daemon = True
            t.start()
            time.sleep(0.01)

        return {'directories': self.directories}

    def runNmapScripts(self):
        print(colored("\t[+] Running http nmap scripts...", 'green'))
        nmap = NmapScan(host=self.host, disablePing=self.disablePing)
        scriptResults = nmap.enumPort(self.port, self.nmapScripts)[self.host]['ports'][0]['scripts']
        return {'nmapScripts': scriptResults}

    def spider(self):
        print(colored("\t[+] Spidering website...", 'green'))

        depth = 0
        links = ['/']

        while depth < self.spiderDepth:
            for link in links:
                url = 'http://{}:{}/{}'.format(self.host, self.port, link)
                res = requests.get(url)
                webpage = html.fromstring(res.content.decode('utf-8'))
                newLinks = webpage.xpath('//a/@href')
                links.extend(newLinks)
                links = list(dict.fromkeys(links))
            depth = depth + 1

        return {'spider': links}

    def getHtmlComments(self):
        print(colored("\t[+] Extracting html comments...", 'green'))
        comments = []
        url = 'http://{}:{}'.format(self.host, self.port)
        res = requests.get(url)
        soup = BeautifulSoup(res.content.decode('utf-8'), 'lxml')

        for comment in soup.findAll(text=lambda text: isinstance(text, Comment)):
            comments.append(comment)

        return {'html_comments': comments}

    def bannerGrab(self):
        print(colored("\t[+] Grabbing http banner...", 'green'))
        try:
            s = socket.socket()
            s.connect((self.host, self.port))
            s.send(b'GET /\n\n')
            banner = s.recv(10000).decode('utf-8')
            return {'banner': banner}
        except:
            print('\t\t[-] Nework error with grabbing http banner', 'red')
            return None

    def scan(self):
        bruteResults = self.dirBrute()
        nmapScriptResults = self.runNmapScripts()
        bannerGrabResults = self.bannerGrab()
        spiderResults = self.spider()
        htmlCommentResults = self.getHtmlComments()

        schema = {'properties': {'items': {'type': 'objects'}}}

        merger = Merger(schema)

        results = None
        results = merger.merge(results, bruteResults)
        results = merger.merge(results, nmapScriptResults)
        results = merger.merge(results, bannerGrabResults)
        results = merger.merge(results, spiderResults)
        results = merger.merge(results, htmlCommentResults)

        return {self.port: results}