#!/usr/bin/python3

import json
from haralyzer import HarParser, HarPage
from haralyzer.compat import iteritems

with open('arc.har','r') as f:
    data = HarParser(json.loads(f.read()))
    for page in data.pages:
        print(page)
        for entry in page.entries:
            print(entry['request']['cookies'])
            print(' ')
            print(' ')
            print(' ')
            print(' ')
            print(entry['response']['cookies'])
            print("===========================")
