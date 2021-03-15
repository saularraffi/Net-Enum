from nm import Nmap
from smb.SMBConnection import SMBConnection
from termcolor import colored
import os

class SmbScanner():
	def __init__(self, target, port=139):

		# consider implementing multiple port numbers (ex. 139,445)

		self.target = target
		self.port = port
		self.nmap = Nmap(self.target, str(self.port))

	def nmapScripts(self, scriptList=['smb-enum-users']):
		return self.nmap.scripts(self.port, scriptList)

	def checkAnonymousLogin(self):
		smbConnect = SMBConnection('', '', '', '', use_ntlm_v2 = True)
		return smbConnect.connect(str(self.target), self.port)

	def listShares(self, username='', password=''):
		smbConnect = SMBConnection(username, password, '', '', use_ntlm_v2 = True)
		smbConnect.connect(str(self.target), self.port)
		shareObjs = smbConnect.listShares()
		shares = {}

		for share in shareObjs:
			if self.listFiles(share.name):
				shares[share.name] = True
			else:
				shares[share.name] = False

		return shares

	def listFiles(self, share, username='', password=''):
		try:
			smbConnect = SMBConnection(username, password, '', '', use_ntlm_v2=True)
			smbConnect.connect(str(self.target), self.port)
			sharedFiles = smbConnect.listPath(share,'/')

			files = {}

			for file in sharedFiles:
				if file.isDirectory:
					files[str(file.filename)] = 'd'
				else:
					files[str(file.filename)] = 'f'

			files.pop('.', None)
			files.pop('..', None)

			return {share: files}

		except:
			print(colored('\n[-] Network error connecting to SMB share: {}\n'.format(share), 'red'))
			return None

	def mountShare(self, share, username='', password='', smbVers='1.0'):
		if username == '' and password == '':
			if not os.path.isdir('mounts/smb'):
				os.system('mkdir mounts/smb')

			if os.path.isdir('mounts/smb/{}'.format(share)):
				os.system('umount -l mounts/smb/{}'.format(share))
			else:	
				os.system('mkdir mounts/smb/{}'.format(share))

			mountCommand = 'mount -t cifs //{}/{}/ mounts/smb/{} -o guest,vers={}'.format(self.target, share, share, smbVers)
			os.system(mountCommand)

		else:
			print(colored('\n[-] Cannot mount SMB share ({}), anonymous login not permitted\n'.format(share), 'red'))

	def unmountShare(self, share):
		if os.path.isdir('mounts/smb/{}'.format(share)):
			os.system('umount -l mounts/smb/{}'.format(share))
