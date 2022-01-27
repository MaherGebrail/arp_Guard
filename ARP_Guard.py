#!/usr/bin/env python3
import json
from datetime import datetime
import os
import time


def create_logging_paths(paths_=None, only_date=False):
    """It Returns a dict of files names for both ( strangers and spoofing ) OR date of today"""

    date_today = str(datetime.now().year) + "_" + str(datetime.now().month) + "_" + str(datetime.now().day)
    if only_date:
        return date_today
    if not paths_:
        if not os.path.isdir(path_script+'arp_warnings/'):
            os.system(f""" mkdir "{path_script}arp_warnings" """)
        paths_ = [f"{path_script}arp_warnings/"]  # default warning dir as install.sh is '/opt/arp_guard/arp_warnings/'

    spoofs_path = []
    strangers_paths = []

    for i in paths_:
        spoofs_path.append(i + "MacSpoof_warning_" + date_today)
        strangers_paths.append(i + "strangers_warning_" + date_today)
    return {'spoofs': spoofs_path, 'strangers': strangers_paths}


def write_warnings(message, paths_list):
    """This Function to write the warning messages into the files in the paths_list"""
    for path in paths_list:
        with open(path, 'a+') as f:
            f.write(message)


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


def checkAndAct(tuple_macs_ips: tuple, force_static=True):
    """tuple_macs_ips: tuple of lists(macs, ips).
        force_static: Boolean value, if true -> app will be less flexible as it'll not accept change of macs for ips.
        return None."""
    to_del = []  # list of indexes that should be prevented
    statics = []  # list of indexes that should be static

    macs, ips = tuple_macs_ips
    list_checked_macs = [v for d in stat_list + blackListed for v in d.values()]
    list_checked_ips = [k for d in stat_list + blackListed for k in d.keys()]

    rewrite_log = False
    for i in range(len(macs)):  # loop to filter macs whether familiar or spoofing or statics

        got = {ips[i]: macs[i]}
        if got in stat_list + blackListed or macs[i] == "00:00:00:00:00:00":
            continue

        # if familiar macs are there, it will warn about strangers
        if familiar_macs and macs[i] not in list(familiar_macs.values()):
            if macs[i] not in strangers:
                strangers.append(macs[i])
                write_warnings(f"{ips[i]} : {macs[i]} Connected in LAN -at- {datetime.now()}\n",
                               create_logging_paths(my_paths)['strangers'])
                rewrite_log = True

        if force_static:
            if got not in stat_list + blackListed:
                if macs[i] in list_checked_macs or ips[i] in list_checked_ips:
                    to_del.append(i)

        if macs.count(macs[i]) >= 2:
            to_del.append(i)
        else:
            statics.append(i)

    got_blacklisted = False

    for i in set(to_del):  # if mac spoofed > prevent macs and echo warnings
        got = {ips[i]: macs[i]}
        if got not in stat_list + blackListed:
            os.system(f"arptables -A INPUT -s {ips[i]} --source-mac {macs[i]} --opcode 2 -j DROP")  # blacklist a mac
            write_warnings(f"{ips[i]} : {macs[i]} tried-to-spoof-you -at- {datetime.now()}\n",
                           create_logging_paths(my_paths)['spoofs'])
            blackListed.append(got)
            got_blacklisted = True
            rewrite_log = True

    for i in range(len(statics)):  # if new unique macs -> it puts them statics
        got = {ips[i]: macs[i]}
        if got not in stat_list + blackListed:
            os.system(f"arptables -A INPUT -s {ips[i]} --source-mac {macs[i]} -j ACCEPT")  # make a mac static
            stat_list.append(got)
            rewrite_log = True

    if got_blacklisted:
        os.system("ip -s -s neigh flush all")
    if rewrite_log:
        log_current_process(path_of_current_log)


def log_current_process(needed_path=''):
    """ - needed_path (str): the path To log the current [strangers, blacklisted, statics] as json file.
        - IF needed_path is empty, The function produces the log files into (Logging)dir in the script file path.
        - if needed_path="NO_LOG", there will be no logging in the script.
    """

    if needed_path:
        if needed_path == "NO_LOG":
            return
        path_log = needed_path
    else:
        if not os.path.isdir(path_script+'Logging/'):
            os.system(f"""mkdir "{path_script}Logging" """)
        path_log = path_script+'Logging/'

    to_log = {
        "BlackListed": blackListed,
        "statics": stat_list
    }
    if familiar_macs:
        to_log['Strangers'] = strangers
    with open(path_log+"logging_"+create_logging_paths(only_date=True)+'.json', 'w') as f:
        f.write(json.dumps(to_log))


path_script = os.path.abspath(os.path.dirname(__file__))+'/'

# dict to add your familiar macs if you are in closed LAN and want alerts if any stranger pc appears on arp_table:
# ex: familiar_macs = {"my-pc": "aa:bb:cc:dd:ee:ff"}
# else leave it empty to stop annoying you from(stranger warnings)
familiar_macs = {}

blackListed = []  # The blacklisted [{ips:macs}].
stat_list = []  # [{ips:macs}] has been set to be statics.
strangers = []  # [macs] of stranger devices (if familiar_macs contains values)

path_of_arp_table = "/proc/net/arp"  # only change it if the arp file path changed.

# you can add here your paths for warning files ex:['/home/user1/Desktop/', '/home/user2/'], or let it be an empty list.
my_paths = []

# This is the path of logging Current-process of function [log_current_process]
# There are 3 Options : [1 - let it empty -> log in (Logging)dir in the same folder of script]
# [2 - path_of_current_log='NO_LOG' -> no logging produced] [3 - str of desired logging path]
path_of_current_log = ''

if __name__ == '__main__':
    while True:
        checkAndAct(get_macs_ips(), force_static=True)
        time.sleep(1)
