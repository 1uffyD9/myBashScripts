#!/bin/bash 

COMMAND_TO_FILTER="ls"	# edit the variable to the name of the process you want to monitor
touch .session_topMonitor
declare -i SESSION_NO=0

if [[ -s ".session_topMonitor" ]]; then
	declare -i P_SESSION_NO=$(cat .session_topMonitor)
	SESSION_NO=$((P_SESSION_NO + 1))
	echo $SESSION_NO > .session_topMonitor
else
	echo $SESSION_NO > .session_topMonitor
fi

echo "SESSION: $SESSION_NO"
		
ORDER_BY="CPU"			# Options: MEM
PERIOD="3"			# Edit the time delay you want to add

COMMAND1="top -b -n 1 -o %$ORDER_BY"
declare -i REC_COUNT=0

while true
do
	((REC_COUNT=REC_COUNT+1))
	echo -e "\n# Record$SESSION_NO.$REC_COUNT #####################################################################" | tee -a main_file
	$COMMAND1 >> main_file
	echo -e "\n# Record$SESSION_NO.$REC_COUNT End #################################################################" >> main_file	
	

	declare -i RECORD_START=$(cat main_file | grep -n "Record$SESSION_NO.$REC_COUNT #" | cut -d ":" -f1)
	declare -i RECORD_ENDS=$(cat main_file | grep -n "Record$SESSION_NO.$REC_COUNT End #" | cut -d ":" -f1)

	
	COMMAND2=$(sed -n "$RECORD_START, $RECORD_ENDS p" main_file | grep $COMMAND_TO_FILTER$)
	if [[ $COMMAND2 ]]; then
		cat main_file | grep -A 7 "Record$SESSION_NO.$REC_COUNT #" >> top_$COMMAND_TO_FILTER
		echo $COMMAND2 >> top_$COMMAND_TO_FILTER
		echo -e "\n" >> top_$COMMAND_TO_FILTER
	else
		echo -e "\n# Record$SESSION_NO.$REC_COUNT #####################################################################" >> top_$COMMAND_TO_FILTER
		echo "Process related to '$COMMAND_TO_FILTER' not Found" >> top_$COMMAND_TO_FILTER

	fi
	sleep $PERIOD
done
