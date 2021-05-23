# arp_Guard

_It works as a service in linux (as it built for debian) .. to guard ARP table against MITM (in the local LAN). _

* **install.sh** .. it's only rule is to copy the file in a unique dir to make it work as a service .. and enables it.

* **ARP_Guard.py** .. I find it well explained (by comments) from inside if you want to change something.

	* it keeps reading the arp table .. if something changed and unique it makes it static allowed in arptables .. else .. the app blacklist it.
	* if **familiar_macs** has values .. it will alert for strangers macs,ips .. anyway the app will warn about spoofing macs in the warning path. 
> Note: the default warning path is "/opt/arp_guard/arp_warnings" .. but you can change it by adding your paths in **my_paths** list.

* **arpGuard.service** .. service file to make the App works as a service in the background.
