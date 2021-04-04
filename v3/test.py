import _thread
import time
from threading import Thread
import requests

host = "10.10.71.51"

dirs = open('/usr/share/wordlists/dirb/common.txt', 'r').readlines()

def checkStatus(dir):
    url = "http://{}:3333/{}".format(host,dir)
    res = requests.get(url)
    # print(url)
    if res.status_code != 404:
        print(dir, res.status_code)

for dir in dirs:
    dir = dir.strip()
    t = Thread(target=checkStatus, args=(dir,))
    t.daemon = True
    t.start()
    time.sleep(0.05)
