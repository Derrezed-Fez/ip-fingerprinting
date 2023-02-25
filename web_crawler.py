import os
import datetime
import dns.resolver
import csv
import config_file as config

class WebCrawler():
    def __init__(self, domains:list):
        self.domains = domains
        current_time = str(datetime.datetime.now())
        self.output_directory_domain_based = os.path.join('data', 'output', current_time, 'domain_based')
        self.output_directory_ip_based = os.path.join('data', 'output', current_time, 'ip_based')

    def crawl_domains(self):
        for domain in self.domains:
            self.__capture_domain_fingerprint(domain)

    def __capture_domain_fingerprint(self, domain:str):
        resolver = dns.resolver.Resolver()
        resolver.query(domain, "A")

with open(config.COMPILED_DOMAINS_FILE_PATH, 'r') as f:
    reader = csv.reader(f)
    domains = [row[0] for row in csv.reader(f)]
    crawler = WebCrawler(domains)
    crawler.crawl_domains()