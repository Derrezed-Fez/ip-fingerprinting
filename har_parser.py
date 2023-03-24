import json, os
from haralyzer import HarParser

LOG_FILEPATH = 'C:\\Users\\hacki\\ip-fingerprinting\\data\\input\\New Data Collection'

def convert_ip_to_int(ip:str):
    octets = ip.split('.')
    return (int(octets[0]) * (256**3)) + (int(octets[1]) * (256**2)) + (int(octets[2]) * 256) + int(octets[3])

def compile_fingerprints_and_traces(dir:str, domain:str):
    connections = list()
    browser = ''
    network_trace_filepath = os.path.join(LOG_FILEPATH, 'Network Traces')
    if not os.path.isdir(network_trace_filepath):
        os.mkdir(network_trace_filepath)
    domain_placed = False
    fingerprint = domain.replace('www.', '') + ';'
    secondary_reqs = list()
    for file in os.listdir(dir):
        if '.json' in file:
            if 'edge' in file:
                browser = 'edge'
            elif 'chrome' in file:
                browser = 'chrome'
            elif 'firefox' in file:
                browser = 'firefox'
            elif 'brave' in file:
                browser = 'brave'
            elif 'safari' in file:
                browser = 'safari'
        if '.har' in file:
            with open(os.path.join(dir, file), 'r', encoding='utf-8') as f:
                har_parser = HarParser(json.loads(f.read()))
                for page in har_parser.pages:
                    for entry in page.entries:
                        if har_parser.match_request_type(entry, 'GET') or har_parser.match_request_type(entry, 'POST'):
                            try:
                                if entry.url == 'https://' + domain + '/' and not domain_placed:
                                    fingerprint += (str([convert_ip_to_int(entry.serverAddress)]) + ';')
                                    domain_placed = True
                                else: 
                                    if convert_ip_to_int(entry.serverAddress) not in secondary_reqs:
                                        secondary_reqs.append(convert_ip_to_int(entry.serverAddress))
                            except:
                                pass
                        try:
                            if (har_parser.match_request_type(entry, 'GET') or har_parser.match_request_type(entry, 'POST')) and len(entry.timings.keys()) > 0:
                                connections.append((entry.timings['receive'], convert_ip_to_int(entry.serverAddress)))
                        except:
                            pass
                        # INSERT DOMAIN-Based Fingerprints HERE
    with open(os.path.join(network_trace_filepath, browser + '_' + domain + '.txt'), 'w') as f:
        f.write(str(connections) + '\n')
    if len(secondary_reqs) > 0:
        fingerprint += str(secondary_reqs)
    else:
        fingerprint = None
    return browser, fingerprint

if __name__ == '__main__':
    chrome_basic_ip_fingerprints, firefox_basic_ip_fingerprints, edge_basic_ip_fingerprints = open(os.path.join(LOG_FILEPATH, 'chrome_basic_ip_fingerprints'), 'w'), \
        open(os.path.join(LOG_FILEPATH, 'firefox_basic_ip_fingerprints'), 'w'), open(os.path.join(LOG_FILEPATH, 'edge_basic_ip_fingerprints'), 'w')
    for dir in os.listdir(LOG_FILEPATH):
        if '.log' not in dir and 'fingerprints' not in dir and 'Network' not in dir:
            for inner_dir in os.listdir(os.path.join(LOG_FILEPATH, dir)):
                browser, fingerprint = compile_fingerprints_and_traces(os.path.join(LOG_FILEPATH, dir, inner_dir), dir)
                if fingerprint is not None:
                    if 'chrome' in browser:
                        chrome_basic_ip_fingerprints.write(fingerprint + '\n')
                    if 'firefox' in browser:
                        firefox_basic_ip_fingerprints.write(fingerprint + '\n')
                    if 'edge' in browser:
                        edge_basic_ip_fingerprints.write(fingerprint + '\n')
    chrome_basic_ip_fingerprints.close()
    firefox_basic_ip_fingerprints.close()
    edge_basic_ip_fingerprints.close()