#!/usr/bin/env python3

from defusedxml import ElementTree
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
dt_string = now.strftime("%d-%m-%Y %H-%M-%S")

# xml related
XML_NAMESPACE = {'x': 'https://www.veracode.com/schema/reports/export/1.0'}

# comments feilds
COMMENTS_FEILDS = [
    "[note] wso2-resolution", "[note] usecase",
    "[note] justification",	"[note] resolution"
]


class Utils:
    
    # ref multiple return types: https://peps.python.org/pep-0483/
    def get_xml_file(self, filename: str) -> Union[any, None]:
        """Returns a """

        try:
            return ElementTree.parse(filename).getroot()
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


class VeracodeParser:

    # source : https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/tools/veracode/xml_parser.py
    def __init__(self, input_file) -> None:
        self.report_xml = input_file
        self.vc_severity_mapping = {
            1: 'Info',
            2: 'Low',
            3: 'Medium',
            4: 'High',
            5: 'Critical'
        }

    def xml_flaw_to_severity(self, xml_node):
        return self.vc_severity_mapping.get(int(xml_node.attrib['severity']), 'Info')

    def xml_flaw_to_unique_id(self, app_id, xml_node):
        issue_id = xml_node.attrib['issueid']
        return 'app-' + app_id + '_issue-' + issue_id


    def xml_flaw_to_finding(self, app_id, xml_node, mitigation_text, test = ""):
        # Defaults
        finding = dict()
        finding['mitigation'] = mitigation_text
        finding['static_finding'] = True
        finding['dynamic_finding'] = False
        finding['unique_id_from_tool'] = self.xml_flaw_to_unique_id(app_id, xml_node)

        # Report values
        finding['severity'] = self.xml_flaw_to_severity(xml_node)
        finding['cwe'] = int(xml_node.attrib['cweid'])
        finding['title'] = xml_node.attrib['categoryname']
        # finding['impact'] = 'CIA Impact: ' + xml_node.attrib['cia_impact'].upper()

        # Note that DD's legacy dedupe hashing uses the description field,
        # so for compatibility, description field should contain very static info.
        _description = xml_node.attrib['description'].replace('. ', '.\n')
        finding['description'] = _description

        _references = 'None'
        if 'References:' in _description:
            _references = _description[_description.index(
                'References:') + 13:].replace(')  ', ')\n')
        finding['references'] = _references \
            + "\n\nVulnerable Module: " + xml_node.attrib['module'] \
            + "\nType: " + xml_node.attrib['type'] \
            + "\nVeracode issue ID: " + xml_node.attrib['issueid']

        _is_mitigated = False
        _mitigated_date = None
        if ('mitigation_status' in xml_node.attrib and
                xml_node.attrib["mitigation_status"].lower() == "accepted"):
            if ('remediation_status' in xml_node.attrib and
                    xml_node.attrib["remediation_status"].lower() == "fixed"):
                _is_mitigated = True
            else:
                # This happens if any mitigation (including 'Potential false positive')
                # was accepted in VC.
                for mitigation in xml_node.findall("x:mitigations/x:mitigation", namespaces=XML_NAMESPACE):
                    _is_mitigated = True
                    _mitigated_date = datetime.strptime(mitigation.attrib['date'], '%Y-%m-%d %H:%M:%S %Z')

        # Check if it's a FP in veracode.
        # Only check in case finding was mitigated, since DD doesn't allow
        # both `verified` and `false_p` to be true, while `verified` is implied on the import
        # level, not on the finding-level.
        _false_positive = False
        if _is_mitigated:
            _remediation_status = xml_node.attrib['remediation_status'].lower()
            if "false positive" in _remediation_status or "falsepositive" in _remediation_status:
                _false_positive = True
        finding['false_p'] = _false_positive

        return finding


    def xml_static_flaw_to_finding(self, app_id, xml_node, mitigation_text):
        finding = self.xml_flaw_to_finding(app_id, xml_node, mitigation_text)
        finding['static_finding'] = True
        finding['dynamic_finding'] = False

        _line_number = xml_node.attrib['line']
       # _functionrelativelocation = xml_node.attrib['functionrelativelocation']
        if (_line_number is not None and _line_number.isdigit()):
            finding['line_number'] = int(_line_number)
            # finding['sast_source_line'] = finding['line']

        _source_file = xml_node.attrib.get('sourcefile')
        _sourcefilepath = xml_node.attrib.get('sourcefilepath')
        finding['file_path'] = _sourcefilepath + _source_file
        # finding['sast_source_file_path'] = _sourcefilepath + _source_file

        _sast_source_obj = xml_node.attrib.get('functionprototype')
        finding['sast_source_object'] = _sast_source_obj if _sast_source_obj else None

        # finding['unsaved_tags'] = ["sast"]

        return finding

    def main(self) -> None:
        root = utils.get_xml_file(self.report_xml)

        app_id = root.attrib['app_id']
        report_date = datetime.strptime(root.attrib['last_update_time'], '%Y-%m-%d %H:%M:%S %Z')

        dupes = dict()

        # Get SAST findings
        # This assumes `<category/>` only exists within the `<severity/>` nodes.
        for category_node in root.findall('x:severity/x:category', namespaces=XML_NAMESPACE):

            # Mitigation text.
            mitigation_text = ''
            mitigation_text += category_node.find('x:recommendations/x:para', namespaces=XML_NAMESPACE).get('text') + "\n\n"
            # Bullet list of recommendations:
            mitigation_text += ''.join(list(map(
                lambda x: '    * ' + x.get('text') + '\n',
                category_node.findall('x:recommendations/x:para/x:bulletitem', namespaces=XML_NAMESPACE))))

            for flaw_node in category_node.findall('x:cwe/x:staticflaws/x:flaw', namespaces=XML_NAMESPACE):
                dupe_key = flaw_node.attrib['issueid']

                # Only process if we didn't do that before.
                if dupe_key not in dupes:
                    # Add to list.
                    dupes[dupe_key] = self.xml_static_flaw_to_finding(app_id, flaw_node, mitigation_text)

            for flaw_node in category_node.findall('x:cwe/x:dynamicflaws/x:flaw', namespaces=XML_NAMESPACE):
                dupe_key = flaw_node.attrib['issueid']

                if dupe_key not in dupes:
                    dupes[dupe_key] = self.__xml_dynamic_flaw_to_finding(app_id, flaw_node, mitigation_text)
        
        final_content = list()

        for key, value in dupes.items():
            value ['issue_id'] = int(key)
            final_content.append(value)

        # print(final_content)
        pd_content = pd.json_normalize(final_content)

        # re-arranging the columns
        pd_content = pd_content.loc[:, [
            'title', 'issue_id', 'cwe', 'severity', 'description', 'mitigation', 'references', 
            'file_path', 'line_number', 'sast_source_object', 'unique_id_from_tool'
        ]]

        # adding cols to add analysis comments
        pd_content = pd_content.reindex(columns = pd_content.columns.tolist() + COMMENTS_FEILDS)

        # remove special characters and write
        utils.write_csv(pd_content, self.report_xml.stem) 


if __name__ == '__main__':

    utils = Utils()

    try:
        input_file = Path(input(f"{YELW}[>]{NC} Path to the Scanner report : ").strip()).expanduser()

        if input_file.is_file():
            vara = VeracodeParser(input_file)
            vara.main()
        else:
            utils.print_log("Given report filepath is invalid! Please check the path / file content and try again.", code=3, exit=True)
        
    except KeyboardInterrupt:
        utils.print_log("Keyboard Interrupt occured! Exiting.. ", code=2, exit=True, pref='\n')
