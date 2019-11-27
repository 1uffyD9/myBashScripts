#!/bin/bash
# Author : 1uffyD9

if [ $# -eq 0 ]; then
	echo "Usage: ./networkRecon.sh <IP>"
	exit 1
fi

# DELAY=( $(seq 1 3 ) ) random time

echo -e "PROGRESS\t\tPORT\tSTATUS"
for port in {1..65535}
do
	echo -ne "Checking $port"\\r
	op="$(hping3 -V -S -p $port -s 5050 -c 1 $1 2>&1)"
	if [[ $op == *"1 packets transmitted, 1 packets received"* ]]; then
		echo -e "              \t\t$port\topen"
	fi
	#sleep $[$RANDOM % ${#DELAY[@]}]
done

