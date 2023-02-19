import os
import datetime

class WebCrawler():
    def __init__(self, domains:list):
        self.domains = domains
        self.output_directory = os.path.join('data', 'output', str(datetime.datetime.now()))

    def crawl_domains(self):
        