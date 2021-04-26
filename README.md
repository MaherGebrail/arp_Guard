# arp_Guard

_It works as a service in linux (as it built for debian) .. to guard ARP table against MITM (in the local LAN). _

* **install.sh** .. it's only rule is to copy the file in a unique dir to make it work as a service .. and enables it.

* **ARP_Guard.py** .. The app which i find it well explained (by comments) from inside if you want to change somthing.

	* it keeps reading the arp table .. if something changed and unique it make it static .. else .. the app blacklisted it.

* **arpGuard.service** .. service file to make the App works as a service in the background.
