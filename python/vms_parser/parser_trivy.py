#!/usr/bin/env python3.10

from datetime import datetime
from pathlib import Path
from typing import Union
import pandas as pd
import json
import sys
import os

C='\033'
RED=f"{C}[31m"
GREEN=f"{C}[32m"
YELW=f"{C}[33m"
BLUE=f"{C}[34m"
MGNT=f"{C}[35m" #Magenta
LG=f"{C}[37m" #LightGray
DG=f"{C}[90m" #DarkGray
NC=f"{C}[0m"
BOLD=f"{C}[1m"
UNDERLINED=f"{C}[5m"
ITALIC=f"{C}[3m"

# enable debug to find additional info
debug = True

yes = {'yes','y', 'ye', ''}
now = datetime.now()
dt_string = 'vulnerabilities' # now.strftime("%d-%m-%Y %H-%M-%S")

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
    "[note] wso2-resolution", "[note] usecase",
    "[note] justification",	"[note] resolution"
]


class Utils:
    
    # ref multiple return types: https://peps.python.org/pep-0483/
    def get_json_file(self, filename: str) -> Union[dict, None]:
        """Returns a json"""

        try:
            with open(filename) as f:
                return json.load(f)
        except ValueError:
            return
        except AttributeError:
            return


    def pretty_print(self, json_obj: dict) -> None:
        """Print JSON object with indentations"""

        print(json.dumps(json_obj, indent=4, sort_keys=True))


    def print_log(self, content: str = '', code: int = 0, end: str = '\n', exit: bool = False, prefix: str = '') -> None:
        """Print console logs based on the given code\n
            0 - Info (default)\n
            1 - Success\n
            2 - Error\n
            3 - Fail\n
            4 - Event
            5 - Debug
        """
        fin_content = prefix if prefix else ''

        if int(code) == 1:
            # success 
            fin_content += f"{GREEN}{BOLD}[+]{NC} {content} {NC}"
        elif int(code) == 2:
            # error 
            fin_content += f"{RED}{BOLD}[!]{NC} {content} {NC}"
        elif int(code) == 3:
            # fail 
            fin_content += f"{YELW}{BOLD}[-]{NC} {content} {NC}"
        elif int(code) == 4:
            # event 
            fin_content += f"{BLUE}{BOLD}[*]{NC} {content} {NC}"
        elif int(code) == 5:
            # debug 
            fin_content += f"{MGNT}{BOLD}[%]{NC} {content} {NC}"
        else:
            fin_content += f"{DG}{BOLD}[*]{NC} {content} {NC}"

        sys.exit(f'{fin_content}{end}') if exit else print(fin_content, end=end)


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


    def write_csv(self, pd_content: pd, file_name: str) -> None:
        
        user_choice = input(f"{YELW}[>]{NC} Do you want to write to current working directory [y/Y] ?").lower()

        if user_choice in yes:
            dst_file = "{}/{}.xlsx".format(os.getcwd(), file_name)
            pd_content.to_excel(r'{}'.format(dst_file), index = None, sheet_name=dt_string)
            self.print_log("File written to : {}".format(dst_file), code=4)
        else:
            csv_dst_dir = Path(input(f"{YELW}[>]{NC} Enter destination direcotry : ")).expanduser()

            if csv_dst_dir.is_dir():
                dst_file = "{}/{}.xlsx".format(csv_dst_dir, file_name)
                pd_content.to_excel(r'{}'.format(dst_file), index = None, sheet_name=dt_string)
                self.print_log("File written to : {}".format(dst_file), code=4)
            else:
                self.print_log("Directory does not exist : {}".format(csv_dst_dir), code=2, exit=True)



class TrivyParser:

    def __init__(self, json_file: str) -> None:
        self.utils = Utils()
        self.json_file = json_file
        self.trivy_content = dict()


    def set_trivy_format(self) -> list:

        fin_content = []

        if results_key in self.trivy_content.keys():

            # iterate through the each component category
            for vuln_type in self.trivy_content[results_key]:
                
                # setting up general feilds
                tmp_dict_gen = dict()

                for key in general_feilds.keys():

                    if key == 'general_info':
                        tmp_val = ''
                        
                        for item in general_feilds[key]:
                            tmp_val_i = self.utils.find_nested_element(item, self.trivy_content)

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

                        if debug and utils.find_nested_element('name', vuln):
                            utils.print_log(vuln['name'], code=5)  
                        
                        # set vuln specific selective feilds
                        tmp_dict_vuln = dict()
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
                                tmp_val = ''

                                if selective_feilds[key] in vuln.keys():
                                    tmp_val = vuln[selective_feilds[key]]
                                elif key in tmp_dict_gen.keys():
                                    tmp_val = tmp_dict_gen[key]
                                else:
                                    pass

                                tmp_dict_vuln[key] = tmp_val

                            elif key == 'file_path':

                                tmp_val = ''

                                for item in selective_feilds[key]:

                                    tmp_val = ''
                                    # first search the key inside vuln info obj
                                    if item in vuln.keys():
                                        tmp_val = vuln[item]
                                    # if file path not exist in the vulnerability info, take the next value in the list
                                    elif item in tmp_dict_gen.keys():
                                        tmp_val = tmp_dict_gen[item]
                                    else:
                                        pass

                                    # if value found, exist looking remaining items
                                    if tmp_val:
                                        break

                                tmp_dict_vuln[key] = tmp_val

                            else:
                                # filter out empty items
                                if selective_feilds[key]:
                                    tmp_val = self.utils.find_nested_element(selective_feilds[key], vuln)

                                    if isinstance(tmp_val, list):
                                        tmp_val = '\n'.join(tmp_val)

                                    tmp_dict_vuln[key] = tmp_val
                                else:
                                    tmp_dict_vuln[key] = ''

                        # adding formatted vuln info to the final list
                        fin_content.append(tmp_dict_vuln)

                else:
                    utils.print_log("Non-vulnerability issue category detected. Skipping!", code=4)

        else:
            raise KeyError(f"{results_key}")

        return fin_content
                

    def main(self) -> None:

        trivy_content = dict()

        # get the content of the json file
        self.trivy_content = self.utils.get_json_file(self.json_file)

        # check if None type or empty
        if not isinstance(self.trivy_content, type(None)) or self.trivy_content:

            try: 
                trivy_content = self.set_trivy_format()
            except KeyError as e:
                utils.print_log(f"Keys mismatch found ({e})! Please check the aqua configs and retry!", code=2, exit=True)

            pds = pd.json_normalize(trivy_content)

            # writing csv file
            self.utils.write_csv(pds.reindex(columns = pds.columns.tolist() + comments_feilds), self.json_file.stem)
        else:
            utils.print_log("[Error] Invalid file content! Please check the file format and try again.", code=2, exit=True)



if __name__ == '__main__':

    utils = Utils()

    try:
        input_file = Path(input(f"{YELW}[>]{NC} Path to the Scanner report : ").strip()).expanduser()
        if input_file.is_file():
            triv = TrivyParser(input_file)
            triv.main()
        else:
            utils.print_log("Given report filepath is invalid! Please check the path / file content and try again.", code=3, exit=True)
        
    except KeyboardInterrupt:
        utils.print_log("Keyboard Interrupt occured! Exiting.. ", code=2, exit=True, pref='\n')
