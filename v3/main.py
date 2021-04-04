from api.webEnum import WebEnum
from api.nmap import NmapScan
import json
import jsonmerge

host = "10.10.10.233"

# nmap = NmapScan(host=host)
# nmapResult = nmap.scan()
# print(json.dumps(nmapResult, indent=4))

webResults = WebEnum(host=host, port=80)
print(json.dumps(webResults.scan(), indent=4))
# print(webResults.scan())