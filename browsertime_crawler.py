import subprocess, sys, csv
from threading import Thread

def crawl_firefox(url):
    p = subprocess.Popen(["powershell.exe", "C:\\Users\\Zane\\ip-fingerprinting\\crawl_firefox.ps1", 'https://www.' + url], stdout=sys.stdout)
    p.communicate()

def crawl_chrome(url):
    p = subprocess.Popen(["powershell.exe", "C:\\Users\\Zane\\ip-fingerprinting\\crawl_chrome.ps1", 'https://www.' + url], stdout=sys.stdout)
    p.communicate()

with open('data\input\combined_top_domains.csv', newline='\n') as f:
    reader = csv.reader(f)
    for row in reader:
        chrome_thread = Thread(target=crawl_chrome, args=[row[0]])
        firefox_thread = Thread(target=crawl_firefox, args=[row[0]])
        chrome_thread.run()
        firefox_thread.run()
