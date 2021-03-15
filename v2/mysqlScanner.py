from nm import Nmap
from termcolor import colored
import subprocess

class MysqlScanner():
	def __init__(self, target, port=3306):
		self.target = target
		self.port = port
		self.nmap = Nmap(target, str(self.port))

	def nmapScripts(self, scriptList=['mysql-audit.nse','mysql-databases.nse','mysql-dump-hashes.nse',
		'mysql-empty-password.nse','mysql-enum.nse','mysql-info.nse','mysql-query.nse',
		'mysql-users.nse','mysql-variables.nse']):
		return self.nmap.scripts(self.port, scriptList)

	def getBanner(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.target, self.port))
		response = s.recv(1024)
		s.close()
		return response

	def runCommand(self, username='', password='', command=''):
		if command[-1:] != ';':
			command = command + ';'

		if password == '':
			cmd = 'mysql --user={} --host={} --execute="{}"'.format(username, self.target, command)
		else:
			cmd = 'mysql --user={} --password={} --host={} --execute="{}"'.format(username, password, self.target, command)

		result = subprocess.Popen(cmd,stdout=subprocess.PIPE,stdin=subprocess.PIPE,shell=True).communicate()
		return result[0]