import json, os
from haralyzer import HarParser
import math
from collections import Counter

LOG_FILEPATH = 'C:\\Users\\hacki\\ip-fingerprinting\\data\\input\\New Data Collection'

def convert_ip_to_int(ip:str):
    octets = ip.split('.')
    if ip == '':
        return ''
    return (int(octets[0]) * (256**3)) + (int(octets[1]) * (256**2)) + (int(octets[2]) * 256) + int(octets[3])

def sort_connections(conn):
    return conn[0]

def information_entropy(visited_domains):
    # Count the frequency of each unique domain in the visited_domains list
    domain_freq = Counter(visited_domains)

    # Calculate the total number of visited domains
    total_domains = len(visited_domains)

    # Calculate the information entropy for each domain
    entropy_dict = {}

    for domain, count in domain_freq.items():

        probability = count / total_domains

        entropy = -math.log2(probability)

        entropy_dict[domain] = entropy

    return entropy_dict

def compile_fingerprints_and_traces(dir:str, domain:str):
    connections = list()
    browser = ''
    network_trace_filepath = os.path.join(LOG_FILEPATH, 'Network Traces')
    if not os.path.isdir(network_trace_filepath):
        os.mkdir(network_trace_filepath)
    domain_placed = False
    ip_fingerprint, enhanced_ip_fingerprint = domain.replace('www.', '') + ';', domain.replace('www.', '') + ';'
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
                # Basic Fingerprinting
                for page in har_parser.pages:
                    for entry in page.entries:
                        if har_parser.match_request_type(entry, 'GET') or har_parser.match_request_type(entry, 'POST'):
                            try:
                                if entry.url == 'https://' + domain + '/' and not domain_placed:
                                    ip_fingerprint += (str([convert_ip_to_int(entry.serverAddress)]) + ';')
                                    domain_placed = True
                                else: 
                                    if convert_ip_to_int(entry.serverAddress) not in secondary_reqs:
                                        secondary_reqs.append(convert_ip_to_int(entry.serverAddress))
                            except:
                                pass
                # Enhanced Fingerprinting
                dom_loading, dom_content_loaded, dom_content_complete = list(), list(), list()
                for entry in har_parser.har_data['entries']:
                    if 'receive' in entry['timings'].keys() and 'serverIPAddress' in entry.keys():
                        connections.append((entry['timings']['receive'], convert_ip_to_int(entry['serverIPAddress'])))
                    if '_priority' in entry.keys() and 'serverIPAddress' in entry.keys():
                        if entry['_priority'] == 'VeryHigh' or entry['_priority'] == 'High':
                            dom_loading.append(convert_ip_to_int(entry['serverIPAddress']))
                        elif entry['_priority'] == 'Medium':
                            dom_content_loaded.append(convert_ip_to_int(entry['serverIPAddress']))
                        elif entry['_priority'] == 'Low':
                            dom_content_complete.append(convert_ip_to_int(entry['serverIPAddress']))
                enhanced_ip_fingerprint += str(dom_loading) + ';' + str(dom_content_loaded) + ';' + str(dom_content_complete)
                # INSERT DOMAIN-Based Fingerprints HERE
    with open(os.path.join(network_trace_filepath, browser + '_' + domain + '.txt'), 'w') as f:
        f.write(str(connections.sort(key=sort_connections)) + '\n')
        if len(ip_fingerprint.split('[')) > 1:
            f.write(str({0: ip_fingerprint.split('[')[1].replace(']', '').replace(';',''), 1: str(secondary_reqs)}) + '\n')
            f.write(str({0: ip_fingerprint.split('[')[1].replace(']', '').replace(';',''), 1 : enhanced_ip_fingerprint.split(';')[0], \
                        2: enhanced_ip_fingerprint.split(';')[1], 3: enhanced_ip_fingerprint.split(';')[2]}))
        else:
            f.write(str({0: [], 1: []}) + '\n')
            f.write(str({0: [], 1: [], 2: [], 3: []}))
    if len(secondary_reqs) > 0:
        ip_fingerprint += str(secondary_reqs)
    else:
        ip_fingerprint = None
    return browser, ip_fingerprint, enhanced_ip_fingerprint

if __name__ == '__main__':
    chrome_basic_ip_fingerprints, firefox_basic_ip_fingerprints, edge_basic_ip_fingerprints = open(os.path.join(LOG_FILEPATH, 'chrome_basic_ip_fingerprints'), 'w'), \
        open(os.path.join(LOG_FILEPATH, 'firefox_basic_ip_fingerprints'), 'w'), open(os.path.join(LOG_FILEPATH, 'edge_basic_ip_fingerprints'), 'w')
    chrome_enhanced_ip_fingerprints, firefox_enhanced_ip_fingerprints, edge_enhanced_ip_fingerprints = \
        open(os.path.join(LOG_FILEPATH, 'chrome_enhanced_ip_fingerprints'), 'w'), open(os.path.join(LOG_FILEPATH, 'firefox_enhanced_ip_fingerprints'), 'w'), \
        open(os.path.join(LOG_FILEPATH, 'edge_enhanced_ip_fingerprints'), 'w')
    for dir in os.listdir(LOG_FILEPATH):
        if '.log' not in dir and 'fingerprints' not in dir and 'Network' not in dir:
            for inner_dir in os.listdir(os.path.join(LOG_FILEPATH, dir)):
                browser, ip_fingerprint, enhanced_ip_fingerprint = compile_fingerprints_and_traces(os.path.join(LOG_FILEPATH, dir, inner_dir), dir)
                if ip_fingerprint is not None:
                    if 'chrome' in browser:
                        chrome_basic_ip_fingerprints.write(ip_fingerprint + '\n')
                        chrome_enhanced_ip_fingerprints.write(enhanced_ip_fingerprint + '\n')
                    if 'firefox' in browser:
                        firefox_basic_ip_fingerprints.write(ip_fingerprint + '\n')
                        firefox_enhanced_ip_fingerprints.write(enhanced_ip_fingerprint + '\n')
                    if 'edge' in browser:
                        edge_basic_ip_fingerprints.write(ip_fingerprint + '\n')
                        edge_enhanced_ip_fingerprints.write(enhanced_ip_fingerprint + '\n')
    chrome_basic_ip_fingerprints.close()
    firefox_basic_ip_fingerprints.close()
    edge_basic_ip_fingerprints.close()