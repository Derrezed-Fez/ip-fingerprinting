import os
import glob
import shutil
import csv
import pandas as pd
from pathlib import Path

def get_immediate_subdirectories(a_dir):
    return [subdir for subdir in os.listdir(a_dir)]

try:

    fp_dir = "C:\\Fingerprinting"

    domains = get_immediate_subdirectories(fp_dir)
    
    browsers = ['Brave', 'Chrome', 'Edge', 'Firefox']

    runs = []
    harfile_json_run1_dirs = []
    harfile_json_run2_dirs = []

    with open('RUNs.csv', 'w', newline="") as out_file:

        writer = csv.writer(out_file)
        writer.writerow(['File_Path', 'Run1', 'Run2'])

    for domain in domains:
    
        for browser in browsers:

            run_dir = fp_dir + "\\" + domain + "\\" + browser
            try:
                runs = get_immediate_subdirectories(run_dir)
            except:
                print("Browser_Directory does not exist: " + run_dir)
            
            with open('RUNs.csv', 'a', newline="") as out_file:
                writer = csv.writer(out_file)
                if(len(runs) == 2):
                    writer.writerow([run_dir, runs[0], runs[1]])
                    harfile_json_run1_dirs.append((run_dir + "\\" + runs[0]))
                    harfile_json_run2_dirs.append((run_dir + "\\" + runs[1]))                    
                elif(len(runs) == 1):
                    print(run_dir)
                    writer.writerow([run_dir, runs[0]])
                    harfile_json_run1_dirs.append((run_dir + "\\" + runs[0]))            
    
    
    with open('browsertime_output_run1.csv', 'w' , newline="") as out_file1:
        writer = csv.writer(out_file1)
        writer.writerow(['File_Path', 'JSON File Exist?', 'HAR File Exist?'])

    
        for directory in harfile_json_run1_dirs:
            x = directory.split("\\")
            brwsr = x[3]
            my_json_file = Path(directory + "\\" + brwsr.lower() + "_results.json")
            my_har_file = Path(directory + "\\" + "browsertime.har")
            
        
            writer.writerow([directory, str(my_json_file.is_file()), str(my_har_file.is_file())])
              
        
    with open('browsertime_output_run2.csv', 'w' , newline="") as out_file2:
        writer = csv.writer(out_file2)
        writer.writerow(['File_Path', 'JSON File Exist?', 'HAR File Exist?'])

        
        for directory in harfile_json_run2_dirs:
        
            x = directory.split("\\")
            brwsr = x[3]
            my_json_file = Path(directory + "\\" + brwsr.lower() + "_results.json")
            my_har_file = Path(directory + "\\" + "browsertime.har")
        
            writer.writerow([directory, str(my_json_file.is_file()), str(my_har_file.is_file())])

    
    #with open('RUNS.csv', 'r') as out_file:
    
    #    run_df = pd.read_csv("C:\\Users\\17862\\Desktop\\RUNS.csv")
    
    #for index, row in run_df.iterrows():
    #    my_filepath = row['File_Path']
    #    run2 = row['Run2']
    #    file_path = str(my_filepath) + "\\" + str(run2)
    #    if run2 is not None:
    #       for f in glob.glob(file_path):
    #           shutil.rmtree(f)
    
except Exception as e:
        print(e)