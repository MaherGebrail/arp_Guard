#!/usr/bin/env python3
from datetime import datetime
import os
import time

# dict to add your familiar macs if you are in closed lan and want alerts if any stranger appears on pc's arp_table:
# ex: familiar_macs = {"my-pc": "aa:bb:cc:dd:ee:ff"}
# else leave it empty to stop annoying you from(stranger warnings)
familiar_macs = {}

blackListed = []
state_list = []
strangers = []


def create_warning_path(paths_=None):
    """It Creates the files names for both files ( strangers and spoofing )"""

    if not paths_:
        if not os.path.isdir('/opt/arp_guard/arp_warnings/'):
            os.system('mkdir /opt/arp_guard/arp_warnings')
        paths_ = ['/opt/arp_guard/arp_warnings/']  # default warning dir

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

# you can add here your paths for warning files ex:['/home/user1/Desktop/', '/home/user2/'] .. or let it be empty list.
my_paths = []
list_of_warnings_paths, list_of_strangers_paths = create_warning_path(my_paths)


def get_macs_ips():
    """This Function returns tuple of (macs, ips) lists"""
    macs = []
    ips = []
    with open(path_of_arp_table, "r") as f:
        getArp = f.readlines()

    for line in getArp:
        line = set(line.replace("\t", " ").split(" "))

        try:
            mac, ip = [mac for mac in line if mac.count(':') == 5][0], \
                      [ip for ip in line if ip.count('.') == 3][0]

            macs.append(mac)  # macs
            ips.append(ip)  # ips
        except IndexError:
            pass
    return macs, ips


def checkAndAct(tuple_macs_ips: tuple):
    """Takes input the tuple of lists(macs, ips) return None"""
    to_del = []  # list of indexes that should be prevented
    statics = []  # list of indexes that should be static

    macs, ips = tuple_macs_ips

    for i in range(len(macs)):  # loop to filter macs whether familiar or spoofing or statics

        if macs[i] == "00:00:00:00:00:00":
            continue

        # if familiar macs are there, it will warn about strangers
        if familiar_macs and macs[i] not in list(familiar_macs.values()):
            if macs[i] not in strangers:
                strangers.append(macs[i])
                write_warnings(f"{ips[i]} : {macs[i]} Connected in LAN -at- {datetime.now()}\n",
                               list_of_strangers_paths)

        if macs.count(macs[i]) >= 2:
            to_del.append(i)
        else:
            statics.append(i)

    got_blacklisted = False

    for i in to_del:  # if mac spoofed > prevent macs and echo warnings
        got = {ips[i]: macs[i]}
        if got not in state_list and got not in blackListed:
            os.system(f"arptables -A INPUT -s {ips[i]} --source-mac {macs[i]} --opcode 2 -j DROP")  # blacklist a mac
            write_warnings(f"{ips[i]} : {macs[i]} tried-to-spoof-you -at- {datetime.now()}\n",
                           list_of_warnings_paths)
            blackListed.append(got)
            got_blacklisted = True

    for i in range(len(statics)):  # if new unique macs -> it puts them statics
        got = {ips[i]: macs[i]}
        if got not in state_list and got not in blackListed:
            os.system(f"arptables -A INPUT -s {ips[i]} --source-mac {macs[i]} -j ACCEPT")  # make a mac static
            state_list.append(got)

    if got_blacklisted:
        os.system("ip -s -s neigh flush all")


while True:
    checkAndAct(get_macs_ips())
    time.sleep(1)
