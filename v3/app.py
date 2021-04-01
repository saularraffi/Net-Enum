from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON
from termcolor import colored
from datetime import datetime
from nm import Nmap
from webScanner import WebScanner
from ftpScanner import FtpScanner
from smtpScanner import SmtpScanner
from smbScanner import SmbScanner
from mysqlScanner import MysqlScanner

#################################################################################
# NOTE: Disable cache in your browser to fix linking issues with javascript files 
#################################################################################

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///enumscan.db'
db = SQLAlchemy(app)

'''
from app import db
db.create_all()
'''

#################################################################################
#									Classes									#
#################################################################################

######################## db schema ########################

class Report(db.Model):
	__tablename__ = 'reports'
	ip = db.Column(db.String(15), nullable=False, primary_key=True)
	date_created = db.Column(db.DateTime, default=datetime.utcnow)
	ports = db.Column(JSON)
	services = db.Column(JSON)
	os = db.Column(db.String(50))
	webScanResults = db.Column(JSON)
	ftpScanResults = db.Column(JSON)
	smtpScanResults = db.Column(JSON)
	smbScanResults = db.Column(JSON)
	vulnScanResults = db.Column(JSON)
	mysqlScanResults = db.Column(JSON)

db.create_all()

######################## options ########################

# class Options(db.Model):
# 	__tablename__ = 'options'
# 	ip = db.Column(db.String(15), nullable=False, primary_key=True)
# 	mysqlLogin = db.Column(JSON)

# class Options():
# 	def __init__(self, mysqlLogin={}):
# 		self.mysqlLogin = mysqlLogin

#################################################################################
#								Options Dictionary								#
#################################################################################

options = {
	'mysql-login': {},
	'nmap-vuln-scan': False
}

#################################################################################
#									Functions									#
#################################################################################

def printerr(string):
	print(colored('\n' + str(string) + '\n', 'red'))

def initialNmapScan(ip, ports='1-1024'):
	nmap = Nmap(ip, ports)
	serviceScan = nmap.tcpVersionScan()
	openPorts = {'tcp': nmap.getOpenTcpPorts()}
	os = nmap.getOs()

	services = {}
	ports = []

	for port in openPorts['tcp']:
		ports.append(port)
		serviceName = serviceScan[port]['name']
		serviceProduct = serviceScan[port]['product']
		serviceVersion = serviceScan[port]['version']
		state = serviceScan[port]['state']

		services[port] = {'name': serviceName, 'product': serviceProduct, 'version': serviceVersion, 'state': state}

	scanResults = {'ports': ports, 'services': services, 'os': os}
	return scanResults

def webScan(ip):
	webscan = WebScanner(ip, 80)
	directories = webscan.directoryButeForce()
	nmapScripts = webscan.nmapScripts()

	scanResults = {'dirs': directories, 'nmap-scripts': nmapScripts}
	return scanResults

def ftpScan(ip):
	ftpscan = FtpScanner(ip)
	banner = ftpscan.getBanner()
	nmapScripts = ftpscan.nmapScripts()
	scanResults = {'banner': banner, 'nmap-scripts': nmapScripts}
	return scanResults

def smtpScan(ip):
	smtpscan = SmtpScanner(ip)
	banner = smtpscan.getBanner()
	usersFound = smtpscan.userVrfyBruteForce()
	scanResults = {'banner': banner, 'users-found': usersFound}
	return scanResults

def smbScan(ip):
	smbscan = SmbScanner(ip)
	anonLogin = smbscan.checkAnonymousLogin()

	shares = {}
	sharedFiles = {}

	if anonLogin:
		shares = smbscan.listShares('', '')

		for share in shares:
			files = smbscan.listFiles(share)
			if files is not None:
				sharedFiles[share] = files[share]

	scanResults = {'anon-login': anonLogin, 'shares': shares, 'files': sharedFiles}
	return scanResults

def mysqlScan(ip):
	mysqlscan = MysqlScanner(ip)
	nmapScripts = mysqlscan.nmapScripts()
	scanResults = {'nmap-scripts': nmapScripts}
	return scanResults

def nmapVulnScan(ip, ports='1-1024'):
	nmap = Nmap(ip)
	scanResults = {'vuln-scan': nmap.vulnScan(ports)}
	return scanResults

#################################################################################
#									Routes										#
#################################################################################

######################## index route ########################

@app.route('/', methods=['GET', 'POST'])
def index():
	global options

	if request.method == 'POST':
		ip = request.form['target-ip']
		portRange = request.form['port-range']

		initialScan = initialNmapScan(ip, portRange)
		ports = initialScan['ports']
		services = initialScan['services']
		os = initialScan['os']

		webscan = ftpscan = smtpscan = vulnscan = smbscan = mysqlscan = None

		if 80 in initialScan['ports']:
			webscan = webScan(ip)
		if 21 in initialScan['ports']:
			ftpscan = ftpScan(ip)
		if 25 in initialScan['ports']:
			smtpscan = smtpScan(ip)
		if 139 in initialScan['ports'] or 25 in initialScan['ports']:
			smbscan = smbScan(ip)
		if 3306 in initialScan['ports']:
			mysqlscan = mysqlScan(ip)

		if options['nmap-vuln-scan'] == True:
			vulnscan = nmapVulnScan(ip, initialScan['ports'])

		report = Report(ip=ip, ports=ports, services=services, os=os, webScanResults=webscan, 
			ftpScanResults=ftpscan, smtpScanResults=smtpscan, smbScanResults=smbscan, 
			vulnScanResults=vulnscan, mysqlScanResults=mysqlscan)

		try:
			db.session.add(report)
			db.session.commit()
			return render_template('index.html')

		except:
			return 'There was a problem adding to the database'

	else:
		return render_template('index.html')

######################## all reports route ########################

@app.route('/reports')
def getReports():
	reports = Report.query.order_by(Report.ip).all()
	return render_template('reports.html', reports=reports)

######################## report route ########################

@app.route('/report/<string:ip>')
def getReport(ip):
	report = Report.query.get_or_404(ip)
	return render_template('report.html', report=report)

######################## port report route ########################

@app.route('/report/<string:ip>/<int:port>')
def getPortReport(ip, port):
	global options
	report = Report.query.get_or_404(ip)
	return render_template('portReport.html', report=report, port=port, options=options)

######################## report delete route ########################

@app.route('/delete/<string:ip>')
def deleteReport(ip):
	report = Report.query.get_or_404(ip)

	try:
		db.session.delete(report)
		db.session.commit()
		return redirect('/reports')

	except:
		return 'There was a problem deleting that task'

######################## vuln scan route ########################

@app.route('/report/<string:ip>/vulns')
def getVulnScanResults(ip):
	report = Report.query.get_or_404(ip)
	return render_template('vulnScan.html', report=report)

######################## advanced options route ########################

@app.route('/options', methods=['GET', 'POST'])
def advancedOptions():
	global optionDict

	if request.method == 'POST':
		mysqlUser = request.form['mysql-user']
		mysqlPass = request.form['mysql-pass']

		options['mysql-login'] = {'user': mysqlUser, 'pass': mysqlPass}

		return render_template('index.html')

	else:
		return render_template('advancedOptions.html')

#################################################################################
#									Main										#
#################################################################################

if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, threaded=True)