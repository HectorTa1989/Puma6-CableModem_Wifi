#!/bin/bash
pid_file="/var/run/tftp_log.pid"

if [ -f "$pid_file" ]; then
	daemon_exist="$(top -bn1 |grep "$(cat $pid_file)")"
	if [ "$daemon_exist" -le "2" ]; then
		exit
	else
		echo "$$" > "${pid_file}"
	fi
else
	echo "$$" > "${pid_file}"
fi

. /var/tmp/vars.temp
filelocation="/var/tmp/log_test"

ps | while read line; do
	echo "$line" >> ${filelocation}
done
free | while read line; do
	echo "$line" >> ${filelocation}
done

counter=1
while [ 1 ]
do
	if [ ${counter} = 10 ];
	then
		ps | while read line; do
			echo "$line" >> ${filelocation}
		done
		free | while read line; do
			echo "$line" >> ${filelocation}
		done
		counter=0
	fi

	if [ -f "/nvram/tftp_server" ]; then
		tftp_server="$(cat /nvram/tftp_server)"
        fi
        date=`(date +"%m%d%H%M%S")`
        fileName=$DeviceSerialNumber"_ARM_messages_"$date".txt"
        echo $filelocation
        echo $tftp_server
        echo $fileName
        tftp -l $filelocation -p $tftp_server -r $fileName
	tftp_res=$?
	echo "TFTP result = "$tftp_res
	if [ $tftp_res == 0 ]; then
		echo "Clear log..."
	        rm -rf /var/tmp/log_test
	fi

	counter=$((counter+1))
        sleep 30
done
