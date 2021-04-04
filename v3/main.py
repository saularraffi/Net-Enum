from api.webEnum import WebEnum
from api.nmap import NmapScan
import json
import jsonmerge

host = "10.10.71.51"

nmap = NmapScan(host=host)
# nmapResult = nmap.scan()
# print(json.dumps(nmapResult, indent=4))

webResults = WebEnum(host=host, port=3333)
print(json.dumps(webResults.scan(), indent=4))