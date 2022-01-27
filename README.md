# arp_Guard

_It works as a service in linux (as it built for debian) .. to guard ARP table against MITM (in the local LAN). _

* **install.sh** .. it's only rule is to copy the file in a unique dir to make it work as a service .. and enables it.

* **ARP_Guard.py** .. I find it well explained (by comments) from inside if you want to change something, while the major functions are :

    * it keeps reading the arptables .. if something changed and unique it makes it static allowed in arptables, else the app will blacklist it.
    * **IF** **familiar_macs** has values -> it will alert for strangers macs,ips .. anyway the app will warn about spoofing macs in the warning path. 
      > Beside the warning files of [spoofing, strangers], There is another logging json file for actions taken to captured macs.
    * **force_static** is an option in the script, by default it's True, to reject (changing) in macs for ips, **BUT** You can set it to False -> to let the app be more flexible.
> **Note**
>  * The Default warning path is **_{app_path}/arp_warnings_** dir, you may change it by adding your paths in **my_paths** list.
>  * The Default current-process Logging path is **_{app_path}/Logging_** dir, you may change or disable it in **path_of_current_log** variable.

* **arpGuard.service** .. service file to make the App works as a service in the background.
