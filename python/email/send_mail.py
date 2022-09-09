#!/usr/bin/env python3

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import smtplib
import ssl
import os


SCRIPT_ROOT = os.path.dirname(os.path.realpath(__file__))
load_dotenv(f"{SCRIPT_ROOT}/.env")
SERVER = os.getenv('SERVER')
PORT = os.getenv('PORT')
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
APP_PASS = os.getenv('APP_PASS')
RECVR_EMAIL = os.getenv('RECVR_EMAIL')

# ref : https://realpython.com/python-send-email/#sending-fancy-emails

message = MIMEMultipart('alternative')
message['From'] = SENDER_EMAIL
message['To'] = RECVR_EMAIL
message['Subject'] = "This Mail sent using a python script"

# Create the plain-text and HTML version of your message
text = "This will be getting override by html content"
html = ''
html_template = 'template.html'

# read from html file
with open(html_template, 'r') as template:
    html = template.read()

# Turn these into plain/html MIMEText objects
part1 = MIMEText(text, 'plain') # this will be getting override by the next content
part2 = MIMEText(html, 'html')

# Add HTML/plain-text parts to MIMEMultipart message
# The email client will try to render the last part first
message.attach(part1)
message.attach(part2)

# Create secure connection with server and send email
context = ssl.create_default_context()
with smtplib.SMTP_SSL(SERVER, PORT, context=context) as server:
    server.login(SENDER_EMAIL, APP_PASS)
    server.sendmail(
        SENDER_EMAIL, RECVR_EMAIL, message.as_string()
    )
