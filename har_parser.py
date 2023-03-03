import json, os
from haralyzer import HarParser, HarPage

LOG_FILEPATH = 'D:\\IP Domain Fingerprinting\\New Data Collection'

def convert_ip_to_int(ip:str):
    octets = ip.split('.')
    return (int(octets[0]) * (256**3)) + (int(octets[1]) * (256**2)) + (int(octets[2]) * 256) + int(octets[3])

def calculate_basic_domain_based_fingerprint(dir:str, domain:str):
    browser = ''
    fingerprint = domain + ';'
    for file in os.listdir(dir):
        if '.json' in file:
            if 'edge' in file:
                browser = 'edge'
            elif 'chrome' in file:
                browser = 'chrome'
            elif 'firefox' in file:
                browser = 'firefox'
        if '.har' in file:
            with open(os.path.join(dir, file), 'r', encoding='utf-8') as f:
                har_parser = HarParser(json.loads(f.read()))
                for page in har_parser.pages:
                    for entry in page.entries:
                        if har_parser.match_request_type(entry, 'GET'):
                            # if entry.url == domain
                            print(entry)
                        if har_parser.match_request_type(entry, 'POST'):
                            print(entry)
        return browser, fingerprint

if __name__ == '__main__':
    chrome_basic_ip_fingerprints, firefox_basic_ip_fingerprints, edge_basic_ip_fingerprints = open(os.path.join(LOG_FILEPATH, 'chrome_basic_ip_fingerprints'), 'wb'), \
        open(os.path.join(LOG_FILEPATH, 'firefox_basic_ip_fingerprints'), 'wb'), open(os.path.join(LOG_FILEPATH, 'edge_basic_ip_fingerprints'), 'wb')
    for dir in os.listdir(LOG_FILEPATH):
        if '.log' not in dir and 'fingerprints' not in dir:
            for inner_dir in os.listdir(os.path.join(LOG_FILEPATH, dir)):
                browser, fingerprint = calculate_basic_domain_based_fingerprint(os.path.join(LOG_FILEPATH, dir, inner_dir), dir)
                if 'chrome' in browser:
                    chrome_basic_ip_fingerprints.write()
    chrome_basic_ip_fingerprints.close()
    firefox_basic_ip_fingerprints.close()
    edge_basic_ip_fingerprints.close()
