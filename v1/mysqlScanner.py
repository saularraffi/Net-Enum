from nm import Nmap
from termcolor import colored

class MysqlScanner():
	def __init__(self, target, port=3306):
		self.target = target
		self.port = port
		self.nmap = Nmap(target, str(self.port))

	def nmapScripts(self, scriptList=['mysql-audit.nse','mysql-databases.nse','mysql-dump-hashes.nse',
		'mysql-empty-password.nse','mysql-enum.nse','mysql-info.nse','mysql-query.nse',
		'mysql-users.nse','mysql-variables.nse']):
		return self.nmap.scripts(self.port, scriptList)