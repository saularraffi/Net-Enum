import _thread
import time
from threading import Thread
import requests
import jsonmerge
from jsonmerge import Merger
import json

host = "10.10.71.51"

j = {'key': 'val'}
j = json.dumps(j)
new_j = json.loads(j)
print(json.dumps(j, indent=4))
