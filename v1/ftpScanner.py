from nm import Nmap
from ftplib import FTP
import socket
from termcolor import colored

class FtpScanner:
	def __init__(self, target, port=21):
		self.target = target
		self.port = port
		self.nmap = Nmap(target, str(self.port))

	def nmapScripts(self, scriptList=['ftp-anon.nse', 'ftp-syst.nse', 'tftp-enum.nse']):
		print(self.nmap.scripts(self.port, scriptList))
		return self.nmap.scripts(self.port, scriptList)

	def checkAnonymousLogin(self):
		scanResult = self.nmap.customCommand('--script=ftp-anon.nse -p ' + str(self.port))
		return scanResult['scan'][self.target]['tcp'][self.port]['script']['ftp-anon']

	def getFiles(self, username='anonymous', password=''):
		ftp = FTP(self.target)
		
		try:
			ftp.login(user=username, passwd = password)
			print('Login successful')
			files = ftp.nlst()

			for file in files:
				print(file)
		except:
			print('Login failed')

	def getBanner(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((self.target, self.port))
			response = s.recv(1024)
			s.close()
			return response

		except:
			print(colored('\n[-] Nework error with grabbing FTP banner\n', 'red'))
			return None