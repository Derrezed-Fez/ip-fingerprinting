import os
import shutil

DIR_PATH = 'H:\\'
OUTPUT_DIR = 'H:\\'

# def format_brower_directories():

def format_safari():
    safari_path = 'F:\\IP Domain Fingerprinting\\New Data\\Safari\\First Run\\browsertime-results'
    output_path = 'F:\\IP Domain Fingerprinting\\New Data\\Safari_modified\\First Run\\'
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    for dir in os.listdir(safari_path):
        for inner_dir in os.listdir(os.path.join(safari_path, dir)):
            for file in os.listdir(os.path.join(safari_path, dir, inner_dir)):
                if '.json' in file:
                    if not os.path.exists(os.path.join(output_path, dir)):
                        os.mkdir(os.path.join(output_path, dir))
                    if not os.path.exists(os.path.join(output_path, dir, inner_dir)):
                        os.mkdir(os.path.join(output_path, dir, inner_dir))
                    shutil.copyfile(os.path.join(safari_path, dir, inner_dir, file), (os.path.join(output_path, dir, inner_dir, 'safari_' + file)))

def combine_owens_pulls():
    # CFE_DIR = 'F:\\IP Domain Fingerprinting\\New Data\\Owen 1st Pull\\browsertime-results'
    # BRAVE_DIR = 'F:\\IP Domain Fingerprinting\\New Data\\Owen 1st Pull (Brave)'
    # for brave in os.listdir(BRAVE_DIR):
    #     for brave_time_dir in os.listdir(os.path.join(BRAVE_DIR, brave, 'Brave')):
    #         if not os.path.exists(os.path.join(CFE_DIR, 'www.' + brave, brave_time_dir)):
    #             try:
    #                 os.mkdir(os.path.join(CFE_DIR, 'www.' + brave, brave_time_dir))
    #             except:
    #                 pass
    #         for file in os.listdir(os.path.join(BRAVE_DIR, brave, 'Brave', brave_time_dir)):
    #             try:
    #                 shutil.copy(os.path.join(BRAVE_DIR, brave, 'Brave', brave_time_dir, file), os.path.join(CFE_DIR, 'www.' + brave, brave_time_dir, file))
    #             except:
    #                 pass
    CFE_DIR = 'F:\\IP Domain Fingerprinting\\New Data\\crawler-second-run'
    BRAVE_DIR = 'F:\\IP Domain Fingerprinting\\New Data\\Brave Second Run'
    for brave in os.listdir(BRAVE_DIR):
        if '.log' not in brave:
            for brave_time_dir in os.listdir(os.path.join(BRAVE_DIR, brave, 'Brave')):
                if not os.path.exists(os.path.join(CFE_DIR, brave, brave_time_dir)):
                    try:
                        os.mkdir(os.path.join(CFE_DIR, brave, brave_time_dir))
                    except:
                        pass
                for file in os.listdir(os.path.join(BRAVE_DIR, brave, 'Brave', brave_time_dir)):
                    try:
                        shutil.copy(os.path.join(BRAVE_DIR, brave, 'Brave', brave_time_dir, file), os.path.join(CFE_DIR, brave, brave_time_dir, file))
                    except:
                        pass

def process_jons_pulls():
    RUN_DIR = 'F:\\IP Domain Fingerprinting\\New Data\Jon\'s Pulls\\Run 2'
    OUT_DIR = 'F:\\IP Domain Fingerprinting\\New Data\\jon_1_modified'
    for folder in os.listdir(RUN_DIR):
        os.mkdir(os.path.join(OUT_DIR, 'www.' + folder))
        for inner_folder in os.listdir(os.path.join(RUN_DIR, folder)):
            for inner_inner_folder in os.listdir(os.path.join(RUN_DIR, folder, inner_folder)):
                os.mkdir(os.path.join(OUT_DIR, 'www.' + folder, inner_inner_folder))
                for file in os.listdir(os.path.join(RUN_DIR, folder, inner_folder, inner_inner_folder)):
                    try:
                        shutil.copy(os.path.join(RUN_DIR, folder, inner_folder, inner_inner_folder, file), os.path.join(OUT_DIR, 'www.' + folder, inner_inner_folder, file))
                    except:
                        pass
                


# for dir in os.listdir(DIR_PATH):
#     if 'Jon' in DIR_PATH:
#         format_brower_directories()

if __name__ == '__main__':
    combine_owens_pulls()