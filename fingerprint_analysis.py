import os, json
from har_parser import information_entropy
import matplotlib.pyplot as plt

INPUT_DIR = 'F:\\IP Domain Fingerprinting\\New Data\\COMPILED\\First Run'
ANALYSIS_OUTPUT_DIR = 'F:\\IP Domain Fingerprinting\\New Data\\Comparative Analysis'
DOMAIN_FINGERPRINTS = 'F:\\IP Domain Fingerprinting\\New Data\\COMPILED\\Second Run\\Domain Based Fingerprints'
SINGLE_RESOURCE_DOMAINS, SINGLE_RESOURCE_IPS = dict(), dict()
BASIC_IP_FINGERPRINTS, ENHANCED_IP_FINGERPRINTS = dict(), dict()
UNLABELED_BASIC_IP_FINGERPRINTS, UNLABELED_ENHANCED_IP_FINGERPRINTS = dict(), dict()
ENTROPY_MAP = dict()

def extract_domain_info(domains, browser):
    # Check for single resource domains
    stripped_domain_list = list()
    for domain in domains:
        stripped_domain_list.append(domain.replace('https://', '').split('/')[0])
    if len(set(stripped_domain_list)) == 1:
        if browser not in SINGLE_RESOURCE_DOMAINS.keys():
            SINGLE_RESOURCE_DOMAINS[browser] = list()
        SINGLE_RESOURCE_DOMAINS[browser].append(next(iter(set(stripped_domain_list))))

def extract_IP_info(IPs, browser, type):
    if type == 'basic':
        domain, primary, secondary = IPs.split(';')[0], IPs.split(';')[1].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(','), IPs.split(';')[2].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(',') if len(IPs.split(';')) > 2 else None
        if len(set(primary)) == 1:
            if browser not in SINGLE_RESOURCE_IPS.keys():
                SINGLE_RESOURCE_IPS[browser] = list()
            SINGLE_RESOURCE_IPS[browser].append(next(iter(set(primary))))
        if browser not in ENTROPY_MAP.keys():
            ENTROPY_MAP[browser] = dict()
        for ip in set(primary):
            if ip not in ENTROPY_MAP[browser].keys():
                ENTROPY_MAP[browser][ip] = 1
            else:
                ENTROPY_MAP[browser][ip] += 1
        if secondary is not None:
            for ip in set(secondary):
                if ip not in ENTROPY_MAP[browser].keys():
                    ENTROPY_MAP[browser][ip] = 1
                else:
                    ENTROPY_MAP[browser][ip] += 1
        return ENTROPY_MAP
    else:
        domain, dom_loading, dom_content_loaded, dom_content_complete = IPs.split(';')[0], IPs.split(';')[1].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(','), IPs.split(';')[2].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(',') if len(IPs.split(';')) > 2 else None, IPs.split(';')[3].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(',') if len(IPs.split(';')) > 3 else None
        if len(set(dom_loading)) == 1 and len(set(dom_content_loaded)) == 1 and len(set(dom_content_loaded)) == 1 and (set(dom_loading) == set(dom_content_loaded) and set(dom_content_loaded) == set(dom_content_complete)):
            if browser not in SINGLE_RESOURCE_IPS.keys():
                SINGLE_RESOURCE_IPS[browser] = list()
            SINGLE_RESOURCE_IPS[browser].append(next(iter(set(dom_loading))))
        if browser not in ENTROPY_MAP.keys():
            ENTROPY_MAP[browser] = dict()
        if dom_loading is not None:
            for ip in set(dom_loading):
                if ip not in ENTROPY_MAP[browser].keys():
                    ENTROPY_MAP[browser][ip] = 1
                else:
                    ENTROPY_MAP[browser][ip] += 1
        if dom_content_loaded is not None:
            for ip in set(dom_content_loaded):
                if ip not in ENTROPY_MAP[browser].keys():
                    ENTROPY_MAP[browser][ip] = 1
                else:
                    ENTROPY_MAP[browser][ip] += 1
        if dom_content_complete is not None:
            for ip in set(dom_content_complete):
                if ip not in ENTROPY_MAP[browser].keys():
                    ENTROPY_MAP[browser][ip] = 1
                else:
                    ENTROPY_MAP[browser][ip] += 1
        return ENTROPY_MAP

def determine_single_hosted_domains(domain_fingerprint_dir:str):
    for file in os.listdir(domain_fingerprint_dir):
        if 'brave' in file:
            browser = 'brave'
        elif 'chrome' in file:
            browser = 'chrome'
        elif 'firefox' in file:
            browser = 'firefox'
        elif 'edge' in file:
            browser = 'edge'
        elif 'safari' in file:
            browser = 'safari'
        else:
            browser = 'unclassified'
        domains = list()
        with open(os.path.join(DOMAIN_FINGERPRINTS, file), 'r') as f:
            lines = f.readlines()
            for domain in lines[0].strip('][').split(', '):
                if not '(' in domain:
                    domains.append(domain.strip("')").strip())
        extract_domain_info(domains=domains, browser=browser)
    with open(os.path.join(ANALYSIS_OUTPUT_DIR, 'single_resource_hosted_domains.json'), 'w') as f:
        json.dump(SINGLE_RESOURCE_DOMAINS, f)

def correct_empty_network_traces(browser, trace_file, type):
    if type == 'basic':
        with open(os.path.join(INPUT_DIR, browser + '_basic_ip_fingerprints'), 'r') as f:
            for line in f.readlines():
                if trace_file.replace('ip_based_', '').replace('.txt', '').split('_')[1] in line and len(line.split(';')) > 1:
                    with open(os.path.join(INPUT_DIR, 'Network Traces', trace_file), 'r') as trace:
                        segments = trace.readlines()
                    primary, secondary = line.split(';')[1].replace('\n', '') if len(line.split(';')) == 2 else '[]', line.split(';')[2].replace('\n', '') if len(line.split(';')) == 3 else '[]'
                    segments[1] = '{0: \'' + primary + '\', 1: \'' + secondary + '\'}\n'
                    with open(os.path.join(INPUT_DIR, 'Network Traces', trace_file), 'w') as trace:
                        for segment in segments:
                            trace.write(segment)
    else:
        with open(os.path.join(INPUT_DIR, browser + '_enhanced_ip_fingerprints'), 'r') as f:
            for line in f.readlines():
                if trace_file.replace('ip_based_', '').replace('.txt', '').split('_')[1] in line and len(line.split(';')) > 1:
                    with open(os.path.join(INPUT_DIR, 'Network Traces', trace_file), 'r') as trace:
                        segments = trace.readlines()
                    dom_loading, dom_content_loaded, dom_content_complete = line.split(';')[1], line.split(';')[2], line.split(';')[3]
                    try:
                        primary_ips = segments[1].split("{0: '")[1].split("', 1:")[0]
                        segments[2] = "{0: '" + primary_ips + "', 1: '" + dom_loading if not dom_loading == '' else '[]' + "', 2: '" + dom_content_loaded if not dom_content_loaded == '' else '[]' + "', 3: '" + dom_content_complete if not dom_content_complete == '' else '[]' + "'"
                        with open(os.path.join(INPUT_DIR, 'Network Traces', trace_file), 'w') as trace:
                            for segment in segments:
                                trace.write(segment)
                    except:
                        pass

def check_ip_against_single_host_domains(browser, domain):
    if not 'www.' in domain:
        domain = 'www.' + domain
    with open(os.path.join(ANALYSIS_OUTPUT_DIR, 'single_resource_hosted_domains.json'), 'r') as excluded_domains:
        domains = json.load(excluded_domains)
        if domain in domains[browser]:
            return True
        else:
            return False
        
def get_highest_entropy_score(entropy_map):
    top = None
    for key, value in entropy_map.items():
        if top is None:
            top = [key, value]
        else:
            if value > top[1]:
                top = [key, value]
    return top[0]

def print_fingerprint_accuracy(domain_counter, fingerprint_counter):
    browser, percentages = list(), list()
    for key in domain_counter.keys():
        browser.append(key)
        percentages.append((fingerprint_counter[key] / domain_counter[key]))
    #Plot accuracty per browser
    colors = ['green', 'blue', 'purple', 'red']
    plt.bar(browser, percentages, color=colors)
    plt.title('Enhanced Fingerprint Accuracy', fontsize=14)
    plt.xlabel('Browser', fontsize=14)
    plt.ylabel('Accuracy %', fontsize=14)
    plt.show()

def determine_basic_fingerprint_accuracy():
    fingerprint_accuracy_counter = {'brave': 0, 'chrome': 0, 'edge': 0, 'firefox': 0}
    domain_counter = {'brave': 0, 'chrome': 0, 'edge': 0, 'firefox': 0}
    domain_maxes = {'brave': 10000, 'chrome': 10000, 'edge': 10000, 'firefox': 10000}

    for browser in ['brave', 'chrome', 'edge', 'firefox']:
        with open(os.path.join(INPUT_DIR, browser + '_basic_ip_fingerprints'), 'r') as f:
            for line in f.readlines():
                extract_IP_info(line, browser, 'basic')
    entropy_scores = information_entropy(ENTROPY_MAP, 10000)
    # sorted(entropy_scores['brave'].items(), key=lambda x:x[1], reverse=True)
    # get each Network Trace to check against entropy score for candidacy
    # REMEMBER TO ADD FINGERPRINTS TO NETWORK TRACE IN PARSING STEP IF THEY ARE NOT IN NETWORK TRACE FILE
    for file in os.listdir(os.path.join(INPUT_DIR, 'Network Traces')):
        candidates = dict()
        browser, domain = file.replace('ip_based_', '').replace('.txt', '').split('_')[0], file.replace('ip_based_', '').replace('.txt', '').replace('www.', '').split('_')[1]
        if domain_counter[browser] <= domain_maxes[browser]:
            domain_counter[browser] += 1
            if not check_ip_against_single_host_domains(browser, domain):
                with open(os.path.join(INPUT_DIR, 'Network Traces', file), 'r') as f:
                    lines = f.readlines()
                if lines[1] == '{0: [], 1: []}\n':
                    correct_empty_network_traces(browser, file, 'basic')
                with open(os.path.join(INPUT_DIR, 'Network Traces', file), 'r') as f:
                    lines = f.readlines()
                    with open(os.path.join(INPUT_DIR, browser + '_basic_ip_fingerprints'), 'r') as fingerprints:
                        for fingerprint in fingerprints.readlines():
                            primary, secondary = fingerprint.split(';')[1].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').replace('\'', '').split(','), fingerprint.split(';')[2].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(',') if len(fingerprint.split(';')) > 2 else None
                            # Here we determine whether ip0 is in the primary IP, and what subset of secondary ips exist within the network trace that match each ip fingerprint (domain label removed here)
                            if all(x in primary for x in lines[1].split('{0: ')[1].split(', 1: \'[')[0].replace('\'', '').replace('[', '').replace(']', '').replace(' ', '').replace('\'', '').split(',')[:-1]):
                                if secondary is None and '[]' in lines[1].split('1:')[1]:
                                    candidates[fingerprint.split(';')[0]] = 0
                                elif secondary is not None and len(lines[1].split('1: ')[1].split(',')) > 1:
                                    for secondary_domain in secondary:
                                        if secondary_domain in lines[1].split('1: ')[1].replace(' ', '').replace('[', '').replace(']', '').replace('\n', '').replace('}', '').replace('\'', '').split(','):
                                            candidates[fingerprint.split(';')[0]] = secondary_domain
                                elif secondary is not None and '[]' not in lines[1].split('1: ')[1]:
                                    candidates[fingerprint.split(';')[0]] = 0
                                    for secondary_domain in secondary:
                                        if secondary_domain in lines[1].split('1: ')[1]:
                                            candidates[fingerprint.split(';')[0]] += entropy_scores[browser][secondary_domain]
            if check_ip_against_single_host_domains(browser, domain):
                fingerprint_accuracy_counter[browser] += 1
            else:
                if len(candidates.keys()) > 0:
                    top_pick = get_highest_entropy_score(candidates)
                    if top_pick == domain:
                        fingerprint_accuracy_counter[browser] += 1
                else:
                    fingerprint_accuracy_counter[browser] += 1
            print(browser + ' ' + str(fingerprint_accuracy_counter[browser]/domain_counter[browser]))
    print(str(domain_counter))
    print(str(fingerprint_accuracy_counter))
    print_fingerprint_accuracy(domain_counter, fingerprint_accuracy_counter)

def create_primary_ip_map(browser):
    ip_map = dict()
    with open(os.path.join(INPUT_DIR, browser + '_basic_ip_fingerprints'), 'r') as f:
        for line in f.readlines():
            domain, primary_ips = line.split(';')[0], line.split(';')[1].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').replace('\'', '').split(',')
            ip_map[domain] = primary_ips
    return ip_map

def determine_enhanced_fingerprint_accuracy():
    fingerprint_accuracy_counter = {'brave': 0, 'chrome': 0, 'edge': 0, 'firefox': 0}
    domain_counter = {'brave': 0, 'chrome': 0, 'edge': 0, 'firefox': 0}
    domain_maxes = {'brave': 1000, 'chrome': 1000, 'edge': 1000, 'firefox': 1000}
    ip_map = dict()

    for browser in ['firefox']:
        with open(os.path.join(INPUT_DIR, browser + '_enhanced_ip_fingerprints'), 'r') as f:
            for line in f.readlines():
                extract_IP_info(line, browser, 'enhanced')
        ip_map[browser] = create_primary_ip_map(browser)
    entropy_scores = information_entropy(ENTROPY_MAP, 10000)
    # get each Network Trace to check against entropy score for candidacy
    # REMEMBER TO ADD FINGERPRINTS TO NETWORK TRACE IN PARSING STEP IF THEY ARE NOT IN NETWORK TRACE FILE
    for file in os.listdir(os.path.join(INPUT_DIR, 'Network Traces')):
        candidates = dict()
        browser, domain = file.replace('ip_based_', '').replace('.txt', '').split('_')[0], file.replace('ip_based_', '').replace('.txt', '').split('_')[1]
        if domain_counter[browser] <= domain_maxes[browser] and browser != 'brave' and browser != 'chrome' and browser != 'edge':
            domain_counter[browser] += 1
            if not check_ip_against_single_host_domains(browser, domain):
                with open(os.path.join(INPUT_DIR, 'Network Traces', file), 'r') as f:
                    lines = f.readlines()
                if lines[2] == '{0: [], 1: [], 2: [], 3: []}':
                    correct_empty_network_traces(browser, file, 'enhanced')
                with open(os.path.join(INPUT_DIR, 'Network Traces', file), 'r') as f:
                    lines = f.readlines()
                    with open(os.path.join(INPUT_DIR, browser + '_enhanced_ip_fingerprints'), 'r') as fingerprints:
                        for fingerprint in fingerprints.readlines():
                            try:
                                if all(x in ip_map[browser][domain] for x in lines[1].split('{0: ')[1].split(', 1: \'[')[0].replace('\'', '').replace('[', '').replace(']', '').replace(' ', '').replace('\'', '').split(',')[:-1]):
                                    dom_loading, dom_content_loaded, dom_content_complete = fingerprint.split(';')[1].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(','), fingerprint.split(';')[2].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(','), fingerprint.split(';')[3].replace('[', '').replace(']', '').replace('\n', '').replace(' ', '').split(',')
                                    # Here we determine whether ips are in each render bucket
                                    candidates[fingerprint.split(';')[0]] = 0 
                                    if dom_loading is not '':
                                        for ip in dom_loading:
                                            if ip in lines[2].split('1: ')[1].replace(' ', '').replace('[', '').replace(']', '').replace('\n', '').replace('}', '').replace('\'', '').split(','):
                                                candidates[fingerprint.split(';')[0]] += entropy_scores[browser][ip]
                                    if dom_content_loaded is not '' and len(lines[2].split('2: ')) > 1:
                                        for ip in dom_content_loaded:
                                            if ip in lines[2].split('2: ')[1].replace(' ', '').replace('[', '').replace(']', '').replace('\n', '').replace('}', '').replace('\'', '').split(','):
                                                candidates[fingerprint.split(';')[0]] += entropy_scores[browser][ip]
                                    if dom_content_complete is not '' and len(lines[2].split('3: ')) > 1:
                                        for ip in dom_content_complete:
                                            if ip in lines[2].split('3: ')[1].replace(' ', '').replace('[', '').replace(']', '').replace('\n', '').replace('}', '').replace('\'', '').split(','):
                                                candidates[fingerprint.split(';')[0]] += entropy_scores[browser][ip]
                            except:
                                pass
            if check_ip_against_single_host_domains(browser, domain):
                fingerprint_accuracy_counter[browser] += 1
            else:
                if len(candidates.keys()) > 0:
                    top_pick = get_highest_entropy_score(candidates)
                    if top_pick == domain:
                        fingerprint_accuracy_counter[browser] += 1
                else:
                    fingerprint_accuracy_counter[browser] += 1
            print(browser + ' ' + str(fingerprint_accuracy_counter[browser]/domain_counter[browser]))
    print(str(domain_counter))
    print(str(fingerprint_accuracy_counter))
    print_fingerprint_accuracy(domain_counter, fingerprint_accuracy_counter)

if __name__ == '__main__':
    # determine_enhanced_fingerprint_accuracy()
    print_fingerprint_accuracy({'brave': 1000, 'chrome': 1000, 'edge': 1000, 'firefox': 1000}, {'brave': 790, 'chrome': 780, 'edge': 730, 'firefox': 940})