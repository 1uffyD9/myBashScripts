#!/usr/bin/env python3

from pathlib import Path
import pandas as pd
import zipfile
import json
import csv
import sys
import re
import io
import os

# filename prefix ; note the order of the files
source_files_prefix = ['security', 'source']
# primary keys which use to join 2nd file into the 1st file mentioned above
primary_key = ["Component id", "Version id", "Origin id"]
# key which contains the file_path info
source_feilds = ["Archive Context and Path"]
# bd content to common vulnerability content
selective_feilds = {
    'title': ["Vulnerability id", "Component name", "Component origin id"],
    'cve': 'Vulnerability id',
    'vulnerability_id': "Vulnerability id",
    'severity': "Security Risk",
    'description': 'Description',
    'references': 'URL',
    'component_name': "Component origin id",
    'component_version': "Component origin version name",
    'component_type': "Component origin name",
    'file_path': "Archive Context and Path"
}

# comments feilds
comments_feilds = [
    "[note] WSO2 Resolution_1", "[note] Use Case_1", 
    "[note] Vulnerability Influence_1", "[note] Resolution_1"
]

class BDParser:

    def __init__(self) -> None:
        self.blackduck_content = dict()


    def get_zip_file(self, zip_file: str) -> dict:
        
        tmp_dict = dict()
        
        with zipfile.ZipFile(zip_file, mode="r") as archive:
            # filtering out unwanted files, MacOS resource forks, etc.
            for file_path in archive.namelist():
                if not file_path.startswith('__') and bool([i for i in source_files_prefix if i in file_path.split("/")[-1]]):
                    with io.TextIOWrapper(archive.open(file_path)) as file:
                        csvReader = csv.DictReader(file)
                        tmp_dict[file_path.split("/")[-1].split("_")[0]] = [row for row in csvReader]

        return tmp_dict


    def pretty_print(self, json_obj: dict) -> None: 
        print(json.dumps(json_obj, indent=4, sort_keys=True))


    def pri_key_validator(self, dict_a: dict, dict_b: dict) -> bool:
        """This will return True if the given 2 dictonaries have matching key:value pairs of a given list of keys"""
        
        count = 0
        for i in primary_key:
            if dict_a[i] == dict_b[i]:
                count += 1

        return True if count == len(primary_key) else False


    def json_join(self, bd_content: dict) -> dict:
        """Join given two json objects into the first object based on the given list of primary keys"""

        for security_item in bd_content[source_files_prefix[0]]:

            tmp_dict = {key : [] for key in source_feilds}
            for source_item in bd_content[source_files_prefix[1]]:
                if self.pri_key_validator(security_item,source_item):
                    for key in source_feilds:
                        tmp_dict[key].append(source_item[key])

            # adding the selected values in 2nd dictionary to the objects in 1st dictonary
            for key in tmp_dict.keys():
                security_item[key] = tmp_dict[key]

        return bd_content


    def set_format(self, vuln_list: list) -> list:
        """Set the final fomatting of the blackduck findings"""

        tmp_list = []

        for finding in vuln_list:
            tmp_dict = dict()
            for key, value in selective_feilds.items():

                cve_regex = re.compile(r"CVE-\d{4}-\d{4,9}", re.IGNORECASE)

                # setting the title
                if key == 'title':
                    tmp_dict[key] = ' '.join([finding[i] for i in selective_feilds[key]])
                # setting the CVE if exists
                elif key == 'cve':
                    cve = cve_regex.search(finding[selective_feilds[key]])
                    tmp_dict[key] = cve.group(0) if cve else ''
                # setting the vuln ID if exists
                elif key == 'vulnerability_id':
                    tmp_dict[key] = cve_regex.sub('', finding[selective_feilds[key]]).strip().strip('(').rstrip(')')
                # setting the component name without version
                elif key == 'component_name':
                    tmp_dict[key] = finding[selective_feilds[key]].rsplit(':', 1)[0]
                else:
                    tmp_dict[key] = finding[selective_feilds[key]]
            
            tmp_list.append(tmp_dict)
        
        return tmp_list


    def main(self) -> None:
        bd_pd_content = ''
        dst_file = ''
        yes = {'yes','y', 'ye', ''}
        bd_content = dict()

        zip_file = Path(input("[>] Path to ZIP file : ")).expanduser()

        if zipfile.is_zipfile(zip_file):
            # get blackduck content
            bd_content = self.get_zip_file(zip_file)

            # join selected CSV content based on given primary keys
            try: 
                bd_content = self.json_join(bd_content)
            except KeyError:
                sys.exit("[!] Keys mismatch found! Please check the blackduck configs and retry!")

            # setting up the final formatting
            bd_content = self.set_format(bd_content[source_files_prefix[0]])

            pds = pd.json_normalize(bd_content)
            # adding cols to add analysis comments
            bd_pd_content = pds.reindex(columns = pds.columns.tolist() + comments_feilds)

        else:
            sys.exit("[!] Given ZIP filepath is invalid! Please check the path / file content and try again.")

        user_choice = input("[>] Do you want to write to current working directory [y/Y] ?").lower()

        if user_choice in yes:
            dst_file = "{}/{}.csv".format(os.getcwd(), zip_file.stem)
            bd_pd_content.to_csv(r'{}'.format(dst_file), index = None)
            print("[!] File written to : {}".format(dst_file))
        else:
            csv_dst_dir = Path(input("[>] Enter destination direcotry : ")).expanduser()

            if csv_dst_dir.is_dir():
                dst_file = "{}/{}.csv".format(csv_dst_dir, zip_file.stem)
                bd_pd_content.to_csv(r'{}'.format(dst_file), index = None)
                print("[!] File written to : {}".format(dst_file))
            else:
                sys.exit("[!] Directory does not exist : {}".format(csv_dst_dir))


if __name__ == '__main__':
    try:
        jp = BDParser()
        jp.main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Keyboard Interrupt occured! Exiting.. ")
