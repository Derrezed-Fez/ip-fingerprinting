import config_file as config
from helpers import compare_top_domain_lists
from web_crawler import WebCrawler

'''

Main Module
Takes command-line arguments to specify what action to perform and with which options.
Option values described in help menu print block.

'''
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if '--help' or '-h' or '-H' in sys.argv[1]:
            print('''
                ip-fingerprinting - Data collection module
                [1]
                DEFAULT\tCollects IP Fingerprints using default techniques (i.e. without any obfuscation methods such as VPN, proxy, onion routing, etc.)
                DARK-WEB\tCollects Fingerprints using methods designed for use with Onion-Routing and obfuscation for the Dark Web
                BRAVE\tCollects IP Fingerprints using Brave Search Engine.
                VPN\tCollects IP Fingerprints while using a VPN
                [2]
                --config <config-file-path>\tSpecifies a configuration filepath for performing the crawling.
                CONFIG-FILE-FORMAT (config_file.py):

                TRANCO_FILE_PATH = <filepath_to_tranco_ip_list>
                ALEXA_FILE_PATH = <filepath_to_alex_ip_list>
            ''')
        elif 'DEFAULT' in sys.argv[1]:
            crawler = WebCrawler(config.COMPILED_DOMAINS_FILE_PATH)
    else:
        print('ERROR: Must supply an argument to execute data colleciton. Add --help for details of which options are supported')