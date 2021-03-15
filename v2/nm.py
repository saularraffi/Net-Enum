import nmap
from termcolor import colored

class Nmap:
	def __init__(self, target, portRange='1-1024'):
		self.target = target
		self.portRange = portRange
		self.scanner = nmap.PortScanner()

	# only run after running tcpVersionScan()
	def getOpenTcpPorts(self):
		openTcpPorts = self.scanner[self.target]['tcp'].keys()
		openTcpPorts.sort()
		return openTcpPorts

	def tcpVersionScan(self):
		self.scanner.scan(self.target, self.portRange, arguments='-sV --version-intensity 9')
		serviceDict = {}

		for port in self.getOpenTcpPorts():
			service = self.scanner[self.target]['tcp'][port]
			serviceDict[port] = service

		return serviceDict

	def getOs(self):
		return self.scanner.scan(self.target, arguments='-O')['scan'][self.target]['osmatch'][0]['name']

	def vulnScan(self, portList=[]):
		if len(portList) == 0:
			scanResult = self.scanner.scan(self.target, arguments='--script vuln')
		else:
			portList = [str(int) for int in portList]
			ports = ','.join(portList)
			scanResult = self.scanner.scan(self.target, arguments='--script vuln -p {}'.format(ports))

		serviceResults = scanResult['scan'][self.target]['tcp']

		vulnScanDict = {}
		scriptDict = {}

		for port in serviceResults:
			scripts = scanResult['scan'][self.target]['tcp'][port]['script']

			for script in scripts:
				if 'ERROR:' not in scripts[script]:
					scriptDict[script] = scripts[script].strip()

			if bool(scriptDict):
				vulnScanDict[port] = scriptDict
			
			scriptDict = {}

		return vulnScanDict

	def scripts(self, port, scriptList):
		scripts = ','.join(scriptList)
		scanResult = self.customCommand('--script=' + scripts + ' -p ' + str(port))
		
		try:
			scriptResults = scanResult['scan'][self.target]['tcp'][port]['script']

			for title, result in scriptResults.items():
				if 'ERROR:' in result:
					scriptResults.pop(title)

			return scriptResults
		except:
			return None

	def customCommand(self, command):
		return self.scanner.scan(self.target, arguments=command)