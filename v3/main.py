from api.webEnum import WebEnum
from api.nmap import NmapScan
import json

webResults = WebEnum()
nmap = NmapScan()

nmapResult = nmap.scan()
print(json.dumps(nmapResult, indent=4))