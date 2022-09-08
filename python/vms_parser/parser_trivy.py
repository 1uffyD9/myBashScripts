#!/usr/bin/env python3

from pathlib import Path
import pandas as pd
import json
import sys
import os

# object which contains the results
results_key = "Results"

# object which contains the vulnerabilities of each category
vulnerabilities = 'Vulnerabilities'

# trivy content to common vulnerability content
selective_feilds = {
    'title': 'Title',
    'cve': 'VulnerabilityID',
    'vulnerability_id': '',
    'cwe': 'CweIDs',
    'severity': 'Severity',
    'description': 'Description',
    'references': 'References',
    'component_name': 'PkgName',
    'component_version': 'InstalledVersion',
    'component_type': 'Type',                   # relative to element in Results object
    'file_path': ['PkgPath', 'Target'],
    'image_version': 'ArtifactName',            # add these to description
    'os_version': 'Metadata.OS'                 # add these to description
}

# comments feilds
comments_feilds = [
    "[note] WSO2 Resolution_1", "[note] Use Case_1", 
    "[note] Vulnerability Influence_1", "[note] Resolution_1"
]


class TrivyParser:

    def __init__(self) -> None:
        pass


def get_json_file(filename: str) -> dict:
    try:
        with open(filename) as f:
            return json.load(f)
    except ValueError as e:
        sys.exit("[!] Invalid JSON format in file : {}".format(filename))


def find_nested_element(element_path: str, json_obj: json):
    """Find the value of a element given by its key path seperated by a period mark"""

    keys = element_path.split('.')
    
    rv = json_obj

    try:
        for key in keys:
            rv = rv[int(key) if key.isnumeric() else key]

        return rv
    except KeyError as e:
        sys.exit(f"[!] [Error] {e} Key cannot be found! Please check the path ({element_path}) and try again.)")

def pretty_print(json_obj: dict) -> None: 
    print(json.dumps(json_obj, indent=4, sort_keys=True))

def set_format(vuln: str):
    pass



json_file = Path('./docker.wso2.com_wso2mi-dashboard_1.2.0.18.json').expanduser()

if json_file.is_file():
    json_content = get_json_file(json_file)


image_version = find_nested_element(selective_feilds['image_version'], json_content)
os_version = ':'.join(find_nested_element(selective_feilds['os_version'], json_content).values())


vulns = []

# Results obj contains all the vulnerabilities categorized by type
for vuln_type in json_content[results_key]:

    if selective_feilds['component_type'] in vuln_type.keys():
        component_type = vuln_type[selective_feilds['component_type']]
    else:
        component_type = ""
    
    target = vuln_type[selective_feilds['file_path'][1]]
    
    # filter out objects which does not have vuln (having issues like licensing, etc)
    if vulnerabilities in vuln_type.keys():
        for vuln in vuln_type[vulnerabilities]:
        
            tmp_vuln = dict()

            if selective_feilds['title'] in vuln.keys():
                tmp_vuln['title'] = vuln[selective_feilds['title']]
            else:
                tmp_vuln['title'] = ''

            # print(vuln[selective_feilds['cve']])
            tmp_vuln['cve'] = vuln[selective_feilds['cve']]
            tmp_vuln['vulnerability_id'] = ''
            tmp_vuln['severity'] = vuln[selective_feilds['severity']].capitalize()
            tmp_vuln['description'] = vuln[selective_feilds['description']]
            tmp_vuln['references'] = '\n'.join(vuln[selective_feilds['references']])
            tmp_vuln['component_name'] = vuln[selective_feilds['component_name']]
            tmp_vuln['component_version'] = vuln[selective_feilds['component_version']]
            tmp_vuln['component_type'] = component_type

            if selective_feilds['file_path'][0] in vuln.keys():
                tmp_vuln['file_path'] = vuln[selective_feilds['file_path'][0]]
            else:
                tmp_vuln['file_path'] = target

            tmp_vuln['image_version'] = image_version
            tmp_vuln['os_version'] = os_version

            # adding vuln elements to final list
            vulns.append(tmp_vuln)


dst_file = "{}/{}.csv".format(os.getcwd(), json_file.stem)

pds = pd.json_normalize(vulns)
# adding cols to add analysis comments
bd_pd_content = pds.reindex(columns = pds.columns.tolist() + comments_feilds)


bd_pd_content.to_csv(r'{}'.format(dst_file), index = None)
print("[!] File written to : {}".format(dst_file))
