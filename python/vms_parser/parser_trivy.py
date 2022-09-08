#!/usr/bin/env python3

from pathlib import Path
from select import select
from typing import Union
import pandas as pd
import json
import sys
import os

# object which contains the results
results_key = "Results"

# object which contains the vulnerabilities of each category
vulnerabilities = 'Vulnerabilities'

# trivy content general info
general_feilds = {
    # contains image version, os info
    'general_info': ['ArtifactName', 'Metadata.OS'],
    'component_type': 'Type',
    'target': 'Target'
}

# trivy content specific to vuln
# you can use the information in general_feilds here
selective_feilds = {
    'title': ['VulnerabilityID', 'PkgName', 'InstalledVersion'],
    'cve': 'VulnerabilityID',
    'vulnerability_id': '',
    'cwe': 'CweIDs',
    'severity': 'Severity',
    'description': 'Description',
    'references': 'References',
    'component_name': 'PkgName',
    'component_type': general_feilds['component_type'],
    'component_version': 'InstalledVersion',
    'file_path': ['PkgPath', 'target']
}

# comments feilds
comments_feilds = [
    "[note] WSO2 Resolution_1", "[note] Use Case_1", 
    "[note] Vulnerability Influence_1", "[note] Resolution_1"
]


class Utils:
    
    # ref multiple return types: https://peps.python.org/pep-0483/
    def get_json_file(self, filename: str) -> Union[dict, None]:
        """Returns a json"""

        try:
            with open(filename) as f:
                return json.load(f)
        except ValueError as e:
            return


    def pretty_print(self, json_obj: dict) -> None:
        """Print JSON object with indentations"""

        print(json.dumps(json_obj, indent=4, sort_keys=True))


    def find_nested_element(self, element_path: str, json_obj: json) -> Union[dict, None]:
        """Find the value of a element given by its key path seperated by a period mark"""

        keys = element_path.split('.')
        current_obj = json_obj

        try:
            for key in keys:
                current_obj = current_obj[int(key) if key.isnumeric() else key]

            return current_obj
        except KeyError as e:
            return None



class TrivyParser:

    def __init__(self, json_content: dict) -> None:
        self.utils = Utils()
        self.json_content = json_content


    def set_trivy_format(self) -> list:

        fin_content = []

        if results_key in self.json_content.keys():

            # iterate through the each component category
            for vuln_type in self.json_content[results_key]:
                
                # setting up general feilds
                tmp_dict_gen = dict()

                for key in general_feilds.keys():
                    
                    if key == 'general_info':
                        tmp_val = ''
                        
                        for item in general_feilds[key]:
                            tmp_val_i = self.utils.find_nested_element(item, self.json_content)

                            if isinstance(tmp_val_i, dict):
                                # get the keys and join
                                tmp_val_i = ':'.join(tmp_val_i.values())

                            tmp_val += f"\n{item}: {tmp_val_i}"
                            
                        tmp_dict_gen[key] = tmp_val

                    else:
                        tmp_val = self.utils.find_nested_element(general_feilds[key], vuln_type)
                        tmp_dict_gen[key] = tmp_val if not isinstance(tmp_val, type(None)) else ''

                # exclude all categories which does not have vulnerabilities (this may be infomational findings)
                if vulnerabilities in vuln_type.keys():

                    # iterate through each vulns
                    for vuln in vuln_type[vulnerabilities]:

                        # set vuln specific selective feilds
                        tmp_dict_vuln = selective_feilds
                        for key in selective_feilds.keys():

                            if key == 'title':
                                tmp_dict = []
                                for item in selective_feilds[key]:
                                    tmp_val = self.utils.find_nested_element(item, vuln)
                                    if not isinstance(tmp_val, type(None)) or not tmp_val:
                                        tmp_dict.append(tmp_val)

                                tmp_dict_vuln[key] = ' '.join(tmp_dict)

                            
                            elif key == 'description':
                                tmp_dict_vuln[key] = self.utils.find_nested_element(selective_feilds[key], vuln)
                                tmp_dict_vuln[key] += '\n' + self.utils.find_nested_element('general_info', tmp_dict_gen) if tmp_dict_gen['general_info'] else ''
                            
                            elif key == 'component_type':
                                tmp_val = self.utils.find_nested_element(selective_feilds[key], vuln)
                                if not isinstance(tmp_val, type(None)) or not tmp_val:
                                    tmp_val = self.utils.find_nested_element(key, tmp_dict_gen)

                                tmp_dict_vuln[key] = tmp_val if tmp_val else ''

                            elif key == 'file_path':

                                tmp_val = ''

                                for item in selective_feilds[key]:

                                    # self.utils.pretty_print(vuln)
                                    tmp_val = self.utils.find_nested_element(item, vuln)

                                    # if file path not exist in the vulnerability info, take the next value in the list
                                    tmp_val = self.utils.find_nested_element(item, tmp_dict_gen) if isinstance(tmp_val, type(None)) or tmp_val else ''

                                    # if value found, exist looking for options
                                    if tmp_val:
                                        break

                                tmp_dict_vuln[key] = tmp_val if tmp_val else ''

                            else:
                                # filter out empty items
                                if selective_feilds[key]:
                                    tmp_val = self.utils.find_nested_element(selective_feilds[key], vuln)

                                    if isinstance(tmp_val, list):
                                        tmp_val = '\n'.join(tmp_val)

                                    tmp_dict_vuln[key] = tmp_val
                else:
                    raise KeyError(f"{vulnerabilities}")

        else:
            raise KeyError(f"{results_key}")

        return fin_content
                

    def main(self) -> None:

        trivy_pd_content = ''
        dst_file = ''
        yes = {'yes','y', 'ye', ''}
        trivy_content = dict()

        input_file = Path(input("[>] Path to ZIP file : ")).expanduser()

        if input_file.is_file(input_file):
            # get blackduck content
            trivy_content = self.utils.get_json_file(input_file)

            # setting up the final formatting
            try: 
                trivy_content = self.set_trivy_format(trivy_content)
            except KeyError as e:
                sys.exit(f"[!] Keys mismatch found ({e})! Please check the trivy configs and retry!")


            pds = pd.json_normalize(trivy_content)

            # adding cols to add analysis comments
            trivy_pd_content = pds.reindex(columns = pds.columns.tolist() + comments_feilds)

        else:
            sys.exit("[!] Given report filepath is invalid! Please check the path / file content and try again.")

        user_choice = input("[>] Do you want to write to current working directory [y/Y] ?").lower()

        if user_choice in yes:
            dst_file = "{}/{}.csv".format(os.getcwd(), input_file.stem)
            trivy_pd_content.to_csv(r'{}'.format(dst_file), index = None)
            print("[!] File written to : {}".format(dst_file))
        else:
            csv_dst_dir = Path(input("[>] Enter destination direcotry : ")).expanduser()

            if csv_dst_dir.is_dir():
                dst_file = "{}/{}.csv".format(csv_dst_dir, input_file.stem)
                trivy_pd_content.to_csv(r'{}'.format(dst_file), index = None)
                print("[!] File written to : {}".format(dst_file))
            else:
                sys.exit("[!] Directory does not exist : {}".format(csv_dst_dir))



if __name__ == '__main__':
    try:
        triv = TrivyParser()
        triv.main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Keyboard Interrupt occured! Exiting.. ")
