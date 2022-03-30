#!/usr/bin/env python3

import os
import smtplib, ssl
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


SCRIPT_ROOT = os.path.dirname(os.path.realpath(__file__))
load_dotenv(f"{SCRIPT_ROOT}/.env")
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
APP_PASS = os.getenv('APP_PASS')


# ref : https://realpython.com/python-send-email/#sending-fancy-emails

receiver_email = "test@example.com"

message = MIMEMultipart("alternative")
message["Subject"] = "multipart test"
message["From"] = SENDER_EMAIL
message["To"] = receiver_email

# Create the plain-text and HTML version of your message
text = "Plain text content here"

html = ""

with open("template.html", 'r') as template:
    html = template.read()

# Turn these into plain/html MIMEText objects
part1 = MIMEText(text, "plain")
part2 = MIMEText(html, "html")

# Add HTML/plain-text parts to MIMEMultipart message
# The email client will try to render the last part first
message.attach(part1)
message.attach(part2)

# Create secure connection with server and send email
context = ssl.create_default_context()
with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
    server.login(SENDER_EMAIL, APP_PASS)
    server.sendmail(
        SENDER_EMAIL, receiver_email, message.as_string()
    )

