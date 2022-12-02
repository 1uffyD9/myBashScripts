#!/bin/bash

C='\033'
NC="${C}[0m"
DG="${C}[90m" #DarkGray
RED="${C}[31m"

TOMCAT_ARC="apache-tomcat-8.5.84.tar.gz"
TOMCAT_HOME="/opt/tomcat"

if [[ ! -f "/tmp/$TOMCAT_ARC" ]]; then
	echo -e "[!] File not found!. Downloading! $DG"
	wget "https://dlcdn.apache.org/tomcat/tomcat-8/v8.5.84/bin/$TOMCAT_ARC" -O "/tmp/$TOMCAT_ARC"
fi

echo -e "$NC[*] Creating user and directory base"
# create tomcat installation directroy if not exist
sudo mkdir -p "$TOMCAT_HOME"

# Add user and set home directory
sudo useradd -s /bin/false -U -d "$TOMCAT_HOME" tomcat 2>/dev/null

echo "[*] Extracting tomcat"
# strip-components will extract the content in the subdirectories
# inside the archieve to the defined directory based on the given depth 
sudo tar xzf "/tmp/$TOMCAT_ARC" -C "$TOMCAT_HOME" --strip-components=1

# change default permissions
sudo chown -R tomcat:tomcat $TOMCAT_HOME/{webapps,work,temp,logs}/

# Give executable permissions
sudo sh -c "chmod u+x $TOMCAT_HOME/bin/*.sh"

# Follow the guideline : https://www.digitalocean.com/community/tutorials/how-to-install-apache-tomcat-10-on-ubuntu-20-04

