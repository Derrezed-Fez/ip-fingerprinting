import json, os
from haralyzer import HarParser, HarPage

for dir in os.listdir('www.6-pence.com'):
    for entry in os.listdir('www.6-pence.com\\' +  dir):
        if '.har' in entry:
            with open('www.6-pence.com\\' +  dir + '\\' + entry, 'r') as f:
                har_parser = HarParser(json.loads(f.read()))
                for page in har_parser.pages:
                    for entry in page.entries:
                        if har_parser.match_request_type(entry, 'GET'):
                            print(entry)