#/usr/bin/env bash

if [ $USER = "root" ] ;then 

	mkdir /opt/arp_guard

	cp ARP_Guard.py /opt/arp_guard/
	cp conf_file.json /opt/arp_guard/

	cp arpGuard.service /etc/systemd/system/

	systemctl enable arpGuard
	systemctl start arpGuard
	
	echo "finished installing .. "

else
	echo "This script needs root Permission .. run it as sudo user please .."
fi
exit 0



