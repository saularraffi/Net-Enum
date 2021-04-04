import _thread
import time
from threading import Thread
import requests
import jsonmerge
from jsonmerge import Merger

host = "10.10.71.51"

schema = {
    'properties': {
        'items': {
            'type': 'objects'
        }
    }
}

merger = Merger(schema)

j1 = {'bla1': 'bla1'}
j2 = {'bla2': 'bla2'}
j3 = {'bla3': 'bla3'}

base = None
base = merger.merge(base, j1)
base = merger.merge(base, j2)
base = merger.merge(base, j3)

print(base)

