import requests
from nm import Nmap

class WebScanner:
	def __init__(self, target, port=80):
		self.target = target
		self.port = port
		self.nmap = Nmap(target, str(self.port))

	def nmapScripts(self, scriptList=['http-enum.nse', 'http-title.nse']):
		return self.nmap.scripts(self.port, scriptList)

	def directoryButeForce(self, wordlist='/usr/share/wordlists/dirb/common.txt'):
		validPages = {}
		dirWordList = open(wordlist, 'r')

		for directory in dirWordList:
			url = 'http://' + self.target + ':' + str(self.port) + '/' + directory.strip()
			
			try:
				page = requests.get(url)
			
				if page.status_code != 404:
					validPages['/' + directory.strip()] = page.status_code

			except:
				return False

		return validPages

	def spider(self):
		print('spidering website')