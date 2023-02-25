import csv
import config_file as config

def compare_top_domain_lists(list1:str, list2:str, max_domain_num:int, output_file_path:str='data/combined_top_domains.csv'):
    with open(list1, newline='') as f:
        print('Processing ' + list1)
        data1 = [row[1] for row in csv.reader(f)]
    print('Done processing ' + list1)

    with open(list2, newline='') as f:
        print('Processing ' + list2)
        data2 = [row[1] for row in csv.reader(f)]
        print('Done processing ' + list2)

    common_list = set(data1).intersection(data2)
    with open(output_file_path, 'w', newline='') as f:
        writer = csv.writer(f,)
        writer.writerows([[item] for item in list(common_list)[:max_domain_num]])

