#!/usr/bin/env python3

import sys

# https://gist.github.com/vratiu/9780109#file-bash_aliases
C='\033'
RED=f"{C}[31m"
GREEN=f"{C}[32m"
YELW=f"{C}[33m"
BLUE=f"{C}[34m"
CYN=f"{C}[36m"  # Cyan
MGNT=f"{C}[35m" # Magenta
LG=f"{C}[37m"   # LightGray
DG=f"{C}[90m"   # DarkGray
NC=f"{C}[0m"
BOLD=f"{C}[1m"
UNDERLINED=f"{C}[5m"
ITALIC=f"{C}[3m"


def print_log(content: str = '', code: int = 0, end: str = '\n', exit: bool = False, prefix: str = '') -> None:
    """Print console logs based on the given code\n
        0 - Info (default)\n
        1 - Success\n
        2 - Error\n
        3 - Fail\n
        4 - Event\n
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
        fin_content += f"{RED}[-]{NC} {content} {NC}"
    elif int(code) == 4:
        # event 
        fin_content += f"{BLUE}{BOLD}[*]{NC} {content} {NC}"
    elif int(code) == 5:
        # debug 
        fin_content += f"{YELW}{BOLD}[%]{NC} {content} {NC}"
    else:
        fin_content += f"{DG}{BOLD}[*]{NC} {content} {NC}"
    
    sys.exit(f'{fin_content}') if exit else print(fin_content, end=end)


print_log("This reprecents an Informational massage")
print_log("This reprecents a successful massage", 1)
print_log("This reprecents an error massage", 2)
print_log("This reprecents a fail massage", 3)
print_log("This reprecents an event massage and next massage will print in the same line", 4, end='')
print_log("This reprecents a debug massage", 5)
print_log("This reprecents an error massage with exit", 2, exit=True)
print_log("This will not be print")
