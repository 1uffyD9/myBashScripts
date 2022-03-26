#!/usr/bin/env python3

import pandas as pd
from pathlib import Path
import os, sys
import json

def get_json_file(filename):
    try:
        with open(filename) as f:
            return json.load(f)
    except ValueError as e:
        sys.exit("[!] Invalid JSON format in file : {}".format(filename))

def main():
    json_content = ''
    dst_file = ''
    yes = {'yes','y', 'ye', ''}

    json_file = Path(input("[>] Path to JSON file : ")).expanduser()

    if json_file.is_file():
        # normalize the nested JSON objects 
        # https://pythonmana.com/2021/08/20210809143233849o.html
        json_content = pd.json_normalize(get_json_file(json_file), record_path=['cves'], 
            meta=[
                    'severity', 'component_id', 'summary', 'description', 'type',
                    ['versions', 'id'],
                    ['versions', 'vulnerable_versions'],
                    ['versions', 'fixed_versions'],
                    'package_type', 'provider', 'created', 'vulnerability_id', 'cvss_v2_score', 
                    'cvss_v2_base', 'cvss_v3_score',
                    'cvss_v3_base'
                ], errors="ignore").\
        rename(index=str, 
            columns={
                    'versions.id': 'package_id',
                    'versions.vulnerable_versions': 'vulnerable_versions',
                    'versions.fixed_versions': 'fixed_versions'
                })
            
        # re-arranging the columns
        json_content = json_content.loc[:, [
                        'cve', 'cwe', 'severity', 'component_id', 'summary', 'description', 'type',
                        'package_id', 'vulnerable_versions', 'fixed_versions', 'cvss_v2', 'cvss_v3',
                        'package_type', 'provider', 'created', 'vulnerability_id', 'cvss_v2_score', 
                        'cvss_v2_base', 'cvss_v3_score', 'cvss_v3_base'
                    ]]
        
    else:
        sys.exit("[!] JSON script was not found! Please check the path and try again.")

    user_choice = input("[>] Do you want to write to current working directory [y/Y] ?").lower()

    if user_choice in yes:
        dst_file = "{}/{}.csv".format(os.getcwd(), json_file.stem)
        json_content.to_csv (r'{}'.format(dst_file), index = None)
        print("[!] File written to : {}".format(dst_file))
    else:
        csv_dst_dir = Path(input("[>] Enter destination direcotry : ")).expanduser()

        if csv_dst_dir.is_dir():
            dst_file = "{}/{}.csv".format(csv_dst_dir, json_file.stem)
            json_content.to_csv (r'{}'.format(dst_file), index = None)
            print("[!] File written to : {}".format(dst_file))
        else:
            sys.exit("[!] Directory does not exist : {}".format(csv_dst_dir))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Keyboard Interrupt occured! Exiting.. ")