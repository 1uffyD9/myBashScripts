#!/usr/bin/env python3

from datetime import datetime
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
    """
    Prints console logs with formatted messages based on the given code.
    
    Log Codes:
        0 - Info (default): General informational messages.
        1 - Success: Indicates successful execution.
        2 - Error: Indicates an error occurred.
        3 - Fail: Indicates a failed process or task.
        4 - Event: Represents significant events in the workflow.
        5 - Debug: Debugging messages for development.

    :param content: The message to log.
    :param code: The type of log message (0: Info, 1: Success, 2: Error, 3: Fail, 4: Event, 5: Debug).
    :param end: The character to end the print statement with (default is newline).
    :param exit: If True, the program will exit after logging (default is False).
    :param prefix: An optional prefix to prepend to the log message.
    :return: None
    """
    
    # Prepare the log message with optional prefix
    fin_content = prefix if prefix else ''

    # Get current datetime formatted as 'YYYY-MM-DD HH:MM:SS AM/PM'
    now = datetime.now()
    current_datetime = now.strftime("%Y-%m-%d %I:%M:%S %p")

    # Define log format based on the code provided
    if int(code) == 1:
        # Success
        fin_content += f"{GREEN}{BOLD}[+]{NC} [ {DG}{current_datetime}{NC} ] {content} {NC}"
    elif int(code) == 2:
        # Error
        fin_content += f"{RED}{BOLD}[!]{NC} [ {DG}{current_datetime}{NC} ] {content} {NC}"
    elif int(code) == 3:
        # Fail
        fin_content += f"{RED}[-]{NC} [ {DG}{current_datetime}{NC} ] {content} {NC}"
    elif int(code) == 4:
        # Event
        fin_content += f"{BLUE}{BOLD}[*]{NC} [ {DG}{current_datetime}{NC} ] {content} {NC}"
    elif int(code) == 5:
        # Debug
        fin_content += f"{YELW}{BOLD}[%]{NC} [ {DG}{current_datetime}{NC} ] {content} {NC}"
    else:
        # Info (default)
        fin_content += f"{DG}{BOLD}[*]{NC} [ {DG}{current_datetime}{NC} ] {content} {NC}"

    # Exit the program if 'exit' is True, otherwise print the log
    if exit:
        sys.exit(f'{fin_content}')
    else:
        print(fin_content, end=end)


print_log("This reprecents an Informational massage")
print_log("This reprecents a successful massage", 1)
print_log("This reprecents an error massage", 2)
print_log("This reprecents a fail massage", 3)
print_log("This reprecents an event massage and next massage will print in the same line", 4, end='')
print_log("This reprecents a debug massage", 5)
print_log("This reprecents an error massage with exit", 2, exit=True)
print_log("This will not be print")
