import json, os
from haralyzer import HarParser

LOG_FILEPATH = 'F:\\IP Domain Fingerprinting\\New Data\\COMPILED\\First Run'

def convert_ip_to_int(ip:str):
    octets = ip.split('.')
    if ip == '':
        return ''
    return (int(octets[0]) * (256**3)) + (int(octets[1]) * (256**2)) + (int(octets[2]) * 256) + int(octets[3])

def sort_connections(conn):
    return conn[0]

def compile_fingerprints_and_traces(dir:str, domain:str):
    domain_connections = list()
    ip_connections = list()
    browser = ''
    network_trace_filepath = os.path.join(LOG_FILEPATH, 'Network Traces')
    
    if not os.path.isdir(network_trace_filepath):
        os.mkdir(network_trace_filepath)
    
    domain_placed = False

    domain_fingerprint, enhanced_domain_fingerprint = domain.replace('www.', '') + ';', domain.replace('www.', '') + ';'
    ip_fingerprint, enhanced_ip_fingerprint = domain.replace('www.', '') + ';', domain.replace('www.', '') + ';'
 
    domain_secondary_reqs = list()
    ip_secondary_reqs = list()
   
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
                                    domain_fingerprint += (str([entry.url]) + ';')
                                    ip_fingerprint += (str([convert_ip_to_int(entry.serverAddress)]) + ';')
                                    domain_placed = True
                                else: 
                                    if convert_ip_to_int(entry.serverAddress) not in ip_secondary_reqs:
                                        domain_secondary_reqs.append(entry.url)
                                        ip_secondary_reqs.append(convert_ip_to_int(entry.serverAddress))
                            except:
                                pass
                # Enhanced Fingerprinting
                domain_dom_loading, domain_dom_content_loaded, domain_dom_content_complete = list(), list(), list()
                ip_dom_loading, ip_dom_content_loaded, ip_dom_content_complete = list(), list(), list()
                for entry in har_parser.har_data['entries']:
                    if 'receive' in entry['timings'].keys() and 'serverIPAddress' in entry.keys():
                        domain_connections.append((entry['timings']['receive'], entry['request']['url']))
                        ip_connections.append((entry['timings']['receive'], convert_ip_to_int(entry['serverIPAddress'])))
                    if '_priority' in entry.keys() and 'serverIPAddress' in entry.keys():
                        if entry['_priority'] == 'VeryHigh' or entry['_priority'] == 'High':
                            domain_dom_loading.append(entry['request']['url'])
                            ip_dom_loading.append(convert_ip_to_int(entry['serverIPAddress']))
                        elif entry['_priority'] == 'Medium':
                            domain_dom_content_loaded.append(entry['request']['url'])
                            ip_dom_content_loaded.append(convert_ip_to_int(entry['serverIPAddress']))
                        elif entry['_priority'] == 'Low':
                            domain_dom_content_complete.append(entry['request']['url'])
                            ip_dom_content_complete.append(convert_ip_to_int(entry['serverIPAddress']))
 
                enhanced_domain_fingerprint += str(domain_dom_loading) + ';' + str(domain_dom_content_loaded) + ';' + str(domain_dom_content_complete)
                enhanced_ip_fingerprint += str(ip_dom_loading) + ';' + str(ip_dom_content_loaded) + ';' + str(ip_dom_content_complete)
    if not os.path.exists(os.path.join(LOG_FILEPATH, 'Domain Based Fingerprints')):
        os.mkdir(os.path.join(LOG_FILEPATH, 'Domain Based Fingerprints'))
    with open(os.path.join(LOG_FILEPATH, 'Domain Based Fingerprints' , 'domain_based_' + browser + '_' + domain + '.txt'), 'w') as f1:
        f1.write(str(domain_connections) + '\n')
        if len(domain_fingerprint.split('[')) > 1:
            f1.write(str({0: domain_fingerprint.split('[')[1].replace(']', '').replace(';',''), 1: str(domain_secondary_reqs)}) + '\n')
            f1.write(str({0: domain_fingerprint.split('[')[1].replace(']', '').replace(';',''), 1 : enhanced_domain_fingerprint.split(';')[0], \
                        2: enhanced_domain_fingerprint.split(';')[1], 3: enhanced_domain_fingerprint.split(';')[2]}))
        else:
            f1.write(str({0: [], 1: []}) + '\n')
            f1.write(str({0: [], 1: [], 2: [], 3: []}))
    if len(domain_secondary_reqs) > 0:
        domain_fingerprint += str(domain_secondary_reqs)
    else:
        domain_fingerprint = None
            
    with open(os.path.join(network_trace_filepath, 'ip_based_' + browser + '_' + domain + '.txt'), 'w') as f:
        f.write(str(ip_connections) + '\n')
        if len(ip_fingerprint.split('[')) > 1:
            f.write(str({0: ip_fingerprint.split('[')[1].replace(']', '').replace(';',''), 1: str(ip_secondary_reqs)}) + '\n')
            f.write(str({0: ip_fingerprint.split('[')[1].replace(']', '').replace(';',''), 1 : enhanced_ip_fingerprint.split(';')[0], \
                        2: enhanced_ip_fingerprint.split(';')[1], 3: enhanced_ip_fingerprint.split(';')[2]}))
        else:
            f.write(str({0: [], 1: []}) + '\n')
            f.write(str({0: [], 1: [], 2: [], 3: []}))
    if len(ip_secondary_reqs) > 0:
        ip_fingerprint += str(ip_secondary_reqs)
    else:
        ip_fingerprint = None
    return browser, ip_fingerprint, enhanced_ip_fingerprint

if __name__ == '__main__':

    #chrome_domain_fingerprints, firefox_domain_fingerprints, edge_domain_fingerprints, brave_domain_fingerprints = open(os.path.join(LOG_FILEPATH, 'chrome_domain_fingerprints'), 'w'), \
    #    open(os.path.join(LOG_FILEPATH, 'firefox_domain_fingerprints'), 'w'), open(os.path.join(LOG_FILEPATH, 'edge_domain_fingerprints'), 'w'), \ 
    #    open(os.path.join(LOG_FILEPATH, 'brave_domain_fingerprints'), 'w')

    chrome_basic_ip_fingerprints, firefox_basic_ip_fingerprints, edge_basic_ip_fingerprints = open(os.path.join(LOG_FILEPATH, 'chrome_basic_ip_fingerprints'), 'w'), \
        open(os.path.join(LOG_FILEPATH, 'firefox_basic_ip_fingerprints'), 'w'), open(os.path.join(LOG_FILEPATH, 'edge_basic_ip_fingerprints'), 'w')
    chrome_enhanced_ip_fingerprints, firefox_enhanced_ip_fingerprints, edge_enhanced_ip_fingerprints = \
        open(os.path.join(LOG_FILEPATH, 'chrome_enhanced_ip_fingerprints'), 'w'), open(os.path.join(LOG_FILEPATH, 'firefox_enhanced_ip_fingerprints'), 'w'), \
        open(os.path.join(LOG_FILEPATH, 'edge_enhanced_ip_fingerprints'), 'w')
    for dir in os.listdir(LOG_FILEPATH):
        if '.log' not in dir and 'fingerprints' not in dir and 'Network' not in dir and 'Domain Based Fingerprints' not in dir:
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