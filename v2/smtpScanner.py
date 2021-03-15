from nm import Nmap
import socket
from termcolor import colored

class SmtpScanner():
	def __init__(self, target, port=25):
		self.target = target
		self.port = port
		self.nmap = Nmap(target, str(self.port))

	def nmapScripts(self, scriptList=['smtp-enum-users.nse', 'smtp-brute.nse']):
		return self.nmap.scripts(self.port, scriptList)

	def userVrfyBruteForce(self, wordlist='/usr/share/wordlists/metasploit/unix_users.txt'):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((self.target, self.port))
			s.recv(1024)

			validUsers = []

			userWordlist = open(wordlist, 'r')

			counter = 0

			for user in userWordlist:
				s.send('VRFY ' + user.strip() + '\n')
				response = s.recv(1024)

				if response.split(' ')[0] != '550':
					validUsers.append(user)

				counter = counter + 1
				if counter%20 == 0:
					s.close()
					s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					s.connect((self.target, self.port))
					s.recv(1024)

			s.close()

			return validUsers

		except:
			print(colored('\n[-] Network error connecting to SMTP server\n', 'red'))
			return None

	def getBanner(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.target, self.port))
		response = s.recv(1024)
		s.close()
		return response