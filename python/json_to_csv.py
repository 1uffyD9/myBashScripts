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
        json_content = pd.read_json(json.dumps(get_json_file(json_file)))
    else:
        sys.exit("[!] JSON script was not found! Please check the path and try again.")

    user_choice = input("Do you want to write to current working directory [y/Y] ?").lower()

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