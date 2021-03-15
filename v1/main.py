from webScanner import WebScanner
from ftpScanner import FtpScanner
from smbScanner import SmbScanner
from termcolor import colored
from nm import Nmap
import argparse
import sys

# ============================== functions ==============================

def printBanner(color='yellow'):
	print(colored('\n  ////////////////////////////////////////////////////////////////////////////////', color))
	print(colored(' //                             Enumeration Scanner                            //', color))
	print(colored('////////////////////////////////////////////////////////////////////////////////\n', color))

def printHeader(header, color='yellow'):
	print(colored('\n' + '*'*60, color))
	print(colored(int((60 - len(header))/2) * ' ' + header, color))
	print(colored('*'*60 + '\n', color))

def printSubHeader(header, color='white'):
	print(colored('------------ ' + header + ' ------------\n', color))

def printErrorMessage(message, color='red'):
	print(colored('\n[-] ' + message, color) + '\n')

printBanner()

# ============================== argument parsing ==============================

parser = argparse.ArgumentParser(description='Automated enumeration and information gathering tool.')
parser.add_argument('-t', '--target', type=str, help='specify the target IP address', required=True)
parser.add_argument('-p', '--ports', type=str, help='specify port range')

args = parser.parse_args()
target = args.target
portRange = args.ports if args.ports != None else '1-1024'

print('Target: ' + target)
print('Ports: ' + portRange)

# ============================== setup nmap ==============================

nmap = Nmap(target, portRange)

services = nmap.tcpVersionScan()

# ============================== service scan ==============================

printHeader('Service Scan')

httpPorts = []

print('  Port       State    Service, Product, Version')
print('  ------------------------------------')

for port in nmap.getOpenTcpPorts():
	serviceName = services[port]['name']
	serviceProduct = services[port]['product']

	if serviceName == 'http':
		httpPorts.append(port)

	serviceVersion = services[port]['version']
	state = services[port]['state']
	print('  ' + str(port) + '/tcp: ' + '   ' + state + '     ' + serviceName.rstrip(',') + 
		', ' + serviceProduct + ', ' + serviceVersion)

# ============================== os scan ==============================

printHeader('Operating System Scan')

print('  OS: ' + nmap.getOs())

# ============================== web scan ==============================

printHeader('Web Scan')

for port in httpPorts:
	webscan = WebScanner(target, port)
	printSubHeader('http title, port ' + str(port))
	print('  ' + webscan.getHttpTitle() + '\n')
	printSubHeader('nmap http enum, port ' + str(port))
	print(webscan.nmapHttpEnum())
	printSubHeader('directory brute force, port ' + str(port))

	directories = webscan.directoryButeForce()

	if directories:
		for directory in webscan.directoryButeForce():
			print('  ' + directory + ' - ' + str(directories[directory]))
	else:
		printErrorMessage('Unable to brute force directories on port ' + str(port))

	print('\n')

# ============================== ftp scan ==============================

printHeader('FTP Scan')

ftpscan = FtpScanner(target)

printSubHeader('check anonymous login')
print('  ' + ftpscan.checkAnonymousLogin())

# ============================== smb scan ==============================

printHeader('SMB Scan')

smbscan = SmbScanner(target)

printSubHeader('check anonymous login')

anonymousLogin = smbscan.checkAnonymousLogin()

if anonymousLogin:
	print('  Login successful\n')

	printSubHeader('list shares')

	shares = smbscan.listShares('', '')

	for share in shares:
		print('  ' + share)
	print('\n')

	printSubHeader('list files')

	for share in shares:
		smbFiles = smbscan.listFiles(share)

		if smbFiles:

			print('  share: /' + share + '\n')

			for file in smbFiles:
				print('      ' + file)
	print('\n')

else:
	print('  Login failed\n')

