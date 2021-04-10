from api.nmap import NmapScan
from api.webScanner import WebScanner
from api.ftpScanner import FtpScanner
import json
import jsonmerge

host = "10.10.10.5"

# nmap = NmapScan(host=host)
# nmapResult = nmap.scan()
# print(json.dumps(nmapResult, indent=4))

# webResults = WebScanner(host=host, port=80)
# print(json.dumps(webResults.scan(), indent=4))

ftpResults = FtpScanner(host=host, port=21)
print(json.dumps(ftpResults.scan(), indent=4))