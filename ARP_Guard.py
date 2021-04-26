#!/usr/bin/python3
from datetime import datetime 
import os
import time


# dict to add your familiar macs if you are in closed lan and want alerts if any stranger appears on pc's arp_table:
	#ex: familiar_macs = {"my-pc": "aa:bb:cc:dd:ee:ff"} 
#else leave it empty to stop annoying you from(stranger warnings)
familiar_macs = {}

blackListed = []
state_list = []
strangers = []


def create_warning_path(paths_=None):
    """It Creates the files names for both files ( strangers and spoofing )"""

    if not paths_:
        if not os.path.isdir('/opt/arp_warnings/'):
            os.system('mkdir /opt/arp_guard/arp_warnings')
        paths_ = ['/opt/arp_guard/arp_warnings/'] # default warning dir

    spoofs_path = []
    strangers_paths = []
    date_path = str(datetime.now().year) + "_" + str(datetime.now().month) + "_" + str(datetime.now().day)

    for i in paths_:
        spoofs_path.append(i + "MacSpoof_warning_" + date_path)
        strangers_paths.append(i + "strangers_warning_" + date_path)
    return spoofs_path, strangers_paths


def write_warnings(message, paths_list):
    """This Function to write the warning messages into the files in the paths_list"""
    for path in paths_list:
        with open(path, 'a+') as f:
            f.write(message)


path_of_arp_table = "/proc/net/arp"  # only change it if the arp file path changed and this file hasn't updated !!

my_paths = []  # you can add here your paths for warning files ex:['/home/user1/Desktop/', '/home/user2/'] .. or let it be empty list.
list_of_warnings_paths, list_of_strangers_paths = create_warning_path(my_paths)


def get_mac_lists():
    """This Function returns tuple of (macs, ips) lists"""
    macs = []
    ips = []
    with open(path_of_arp_table, "r") as f:
        getArp = f.readlines()

    for a in getArp:
        a = a.replace("\t", " ").split(" ")

        for z in range(a.count(" ") + a.count('')):
            try:
                a.remove(" ")
            except ValueError:
                a.remove('')
        try:
            if a[0].count(".") == 3 or a[0] == "_gateway":
                macs.append(a[3])  # macs
                ips.append(a[0])  # ips
        except IndexError:
            pass
    return macs, ips


def checkAndAct(list_):
    """Takes input the tuple of lists(macs, ips) return None"""
    to_del = []  # list of what should be prevented
    statics = []  # list of what should be static

    for i in range(len(list_[0])):  # loop to filter macs weather familiar or spoofing or statics

        if list_[0][i] == "00:00:00:00:00:00":
            continue

        # if familiar macs are there, it will warning about strangers
        if familiar_macs and list_[0][i] not in list(familiar_macs.values()):
            if list_[0][i] not in strangers:
                strangers.append(list_[0][i])
                write_warnings(f"{list_[1][i]} : {list_[0][i]} Connected in LAN -at- {datetime.now()}\n",
                               list_of_strangers_paths)

        if list_[0].count(list_[0][i]) >= 2:
            to_del.append(i)
        else:
            statics.append(i)

    for i in to_del:  # loop to prevent macs and echo warnings
        got = {list_[1][i]: list_[0][i]}
        if got not in state_list and got not in blackListed:
            
            # blacklist a mac
            os.system(f"arptables -A INPUT -s {list_[1][i]} --source-mac {list_[0][i]} --opcode 2 -j DROP")
            write_warnings(f"{list_[1][i]} : {list_[0][i]} tried-to-spoof-you -at- {datetime.now()}\n",
                           list_of_warnings_paths)
            blackListed.append(got)

    if statics:  # if new unique macs it puts them statics
        for i in range(len(statics)):
            got = {list_[1][i]: list_[0][i]}
            if got not in state_list and got not in blackListed:
                # make a mac static
                os.system(f"arptables -A INPUT -s {list_[1][i]} --source-mac {list_[0][i]} -j ACCEPT")
                state_list.append(got)


while True:
    checkAndAct(get_mac_lists())
    time.sleep(1)
