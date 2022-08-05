#!/usr/bin/env python3

import pandas as pd
from pathlib import Path
import os, sys
import json

class JFrogParser:
    def get_json_file(self, filename: str) -> dict:
        try:
            with open(filename) as f:
                return json.load(f)
        except ValueError as e:
            sys.exit("[!] Invalid JSON format in file : {}".format(filename))

    
    def group_by_component(self, content: json) -> pd.DataFrame:

        pd_content = pd.json_normalize(content, record_path=['cves'],
            meta=[
                'severity', 'component_id', 'summary', 'description', 'type',
                ['versions', 'id'], ['versions', 'vulnerable_versions'],
                ['versions', 'fixed_versions'],
                'package_type', 'provider', 'created', 'vulnerability_id', 'cvss_v2_score', 
                'cvss_v2_base', 'cvss_v3_score', 'cvss_v3_base'
            ],
            errors="ignore").\
            rename(index=str, 
                columns={
                    'versions.id': 'package_id',
                    'versions.vulnerable_versions': 'vulnerable_versions',
                    'versions.fixed_versions': 'fixed_versions'
                })
                
        # re-arranging the columns
        pd_content = pd_content.loc[:, [
            'cve', 'cwe', 'severity', 'component_id', 'summary', 'description', 'type',
            'package_id', 'vulnerable_versions', 'fixed_versions', 'cvss_v2', 'cvss_v3',
            'package_type', 'provider', 'created', 'vulnerability_id', 'cvss_v2_score', 
            'cvss_v2_base', 'cvss_v3_score', 'cvss_v3_base'
        ]]

        # adding cols to add analysis comments
        pd_content = pd_content.reindex(columns = pd_content.columns.tolist() + [
            "[note] WSO2 Resolution_1", "[note] Use Case_1", 
            "[note] Vulnerability Influence_1", "[note] Resolution_1"
        ])
        
        # print(pd_content.columns)
        # remove special characters and return
        return pd_content.replace('(\\r|\\n)','',regex=True)


    def group_by_cves_components(self, content: json) -> pd.DataFrame:
        
        image_name = ""
        if 'imageName' in content : image_name = content['imageName']

        if 'vulnerabilities' in content:
            print(f"[!] Processing {content['vulnerabilities']} vulnerabilities..")

        # normalize by components
        pd_content = pd.json_normalize(content['scanReport'], record_path=['components'], 
            meta=[
                'cves', 'severity', 'summary', 'description', 'references',
                'type', 'package_type', 'provider', '_id', 'ignored'
            ], errors="ignore")


        # print(json.dumps(json.loads(pd_content.to_json(orient='table')), indent=4))

        # normalize by cves
        pd_content = pd.json_normalize(json.loads(pd_content.to_json(orient='records')), record_path=['cves'],
            meta=[
                'severity', 'id', 'vulnerable_versions', 'fixed_versions', 'summary', 'description',
                'references', 'type', 'package_type', 'provider', '_id', 'ignored'
            ], errors="ignore").\
            rename(index=str, columns={
                '_id': 'xray_id',
                'id':'package_id'
                })

        # re-arranging the columns
        pd_content = pd_content.loc[:, [
                'cve', 'cwe', 'severity', 'summary', 'description', 'references',
                'package_id', 'vulnerable_versions', 'fixed_versions',
                'type', 'package_type', 'cvss_v2', 'cvss_v3', 'provider',
                'xray_id', 'ignored'
            ]]

        # adding cols to add analysis comments
        pd_content = pd_content.reindex(columns = pd_content.columns.tolist() + [
            'target_image_name', "[note] WSO2 Resolution_1", "[note] Use Case_1", 
            "[note] Vulnerability Influence_1", "[note] Resolution_1"
        ])

        # adding target image name to the column
        pd_content = pd_content.assign(target_image_name=image_name)

        # remove special characters and return
        return pd_content.replace('(\\r|\\n)','',regex=True)


    def main(self) -> None:
        json_content = ''
        dst_file = ''
        yes = {'yes','y', 'ye', ''}

        json_file = Path(input("[>] Path to JSON file : ")).expanduser()

        if json_file.is_file():
            json_content = self.get_json_file(json_file)

            # normalize the nested JSON objects 
            # https://pythonmana.com/2021/08/20210809143233849o.html
            if 'scanReport' in json_content:
                json_content = self.group_by_cves_components(json_content)
            else:
                json_content = self.group_by_component(json_content)

        else:
            sys.exit("[!] JSON script was not found! Please check the path and try again.")

        user_choice = input("[>] Do you want to write to current working directory [y/Y] ?").lower()

        if user_choice in yes:
            dst_file = "{}/{}.csv".format(os.getcwd(), json_file.stem)
            json_content.to_csv(r'{}'.format(dst_file), index = None)
            print("[!] File written to : {}".format(dst_file))
        else:
            csv_dst_dir = Path(input("[>] Enter destination direcotry : ")).expanduser()

            if csv_dst_dir.is_dir():
                dst_file = "{}/{}.csv".format(csv_dst_dir, json_file.stem)
                json_content.to_csv(r'{}'.format(dst_file), index = None)
                print("[!] File written to : {}".format(dst_file))
            else:
                sys.exit("[!] Directory does not exist : {}".format(csv_dst_dir))


if __name__ == '__main__':
    try:
        jp = JFrogParser()
        jp.main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Keyboard Interrupt occured! Exiting.. ")