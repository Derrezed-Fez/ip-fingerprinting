import subprocess, csv, datetime, os
logfile_name = 'data\\output\\' + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + '_logfile.log'
logfile = open(logfile_name, 'w+')
def crawl_firefox(url):
    p = subprocess.Popen(["powershell.exe", "C:\\Users\\psych\\ip-fingerprinting\\crawl_firefox.ps1", 'https://www.' + url, url, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")], stdout=logfile, stderr=logfile)
    p.communicate()

def crawl_chrome(url):
    p = subprocess.Popen(["powershell.exe", "C:\\Users\\psych\\ip-fingerprinting\\crawl_chrome.ps1", 'https://www.' + url, url, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")], stdout=logfile, stderr=logfile)
    p.communicate()

def crawl_edge(url):
    p = subprocess.Popen(["powershell.exe", "C:\\Users\\psych\\ip-fingerprinting\\crawl_edge.ps1", 'https://www.' + url, url, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")], stdout=logfile, stderr=logfile)
    p.communicate()

def crawl_safari(url):
    p = subprocess.Popen(["browsertime", 'https://www.' + url, '-b', 'safari'], stdout=logfile, stderr=logfile)
    p.communicate()

def crawl_domains(domains:str, is_macos:bool=False):
    with open(domains, newline='\n') as f:
        reader = csv.reader(f)
        for row in reader:
            if is_macos:
                crawl_safari
            else:
                crawl_chrome(row[0])
                crawl_firefox(row[0])
                crawl_edge(row[0])
            # procs = [multiprocessing.Process(target=crawl_firefox, args=(row[0], )), \
            #          multiprocessing.Process(target=crawl_chrome, args=(row[0], )), \
            #         multiprocessing.Process(target=crawl_edge, args=(row[0], ))]
            # for proc in procs:
            #     proc.start()
            # for proc in procs:
            #     proc.join()

if __name__ == '__main__':
    # procs = [multiprocessing.Process(target=crawl_domains, args=('data\input\domains_1-2500.csv', )), multiprocessing.Process(target=crawl_domains, args=('data\input\domains_2501-5000.csv', )), \
    #             multiprocessing.Process(target=crawl_domains, args=('data\input\domains_5001-7500.csv', )), multiprocessing.Process(target=crawl_domains, args=('data\input\domains_7501-10000.csv', ))]
    # for proc in procs:
    #     proc.start()
    # for proc in procs:
    #     proc.join()
    crawl_domains('data\\input\\combined_top_domains.csv')
