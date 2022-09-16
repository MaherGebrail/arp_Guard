#!/usr/bin/env python3
import json
from datetime import datetime
import os
import time


def create_warnings_logging_paths(warning_paths=None):
    """It Returns a dict of files names for both ( strangers and spoofing )"""

    date_today = datetime.now().strftime("%Y_%m_%d")
    if not warning_paths:
        path_warning = os.path.join(path_script, "arp_warnings")
        if not os.path.isdir(path_warning):
            os.system(f""" mkdir "{path_warning}" """)
        warning_paths = [path_warning]  # default warning dir as install.sh is '/opt/arp_guard/arp_warnings/'

    spoofs_path = []
    strangers_paths = []

    for w_path_dir in warning_paths:
        spoofs_path.append(os.path.join(w_path_dir, "MacSpoof_warning_" + date_today + '.txt'))
        strangers_paths.append(os.path.join(w_path_dir, "strangers_warning_" + date_today + '.txt'))
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
        get_arp = f.readlines()

    for line in get_arp:
        line = set(line.replace("\t", " ").split(" "))

        try:
            mac, ip = [mac for mac in line if mac.count(':') == 5][0], \
                      [ip for ip in line if ip.count('.') == 3][0]

            macs.append(mac)  # macs
            ips.append(ip)  # ips
        except IndexError:
            pass
    return macs, ips


def check_and_act(tuple_macs_ips: tuple, force_static=True):
    """tuple_macs_ips: tuple of lists(macs, ips).
        force_static: Boolean value (declared in the conf_file.json).
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

        # if familiar macs has been written in conf file, it will warn about strangers
        if familiar_macs and macs[i] not in list(familiar_macs.values()):
            if macs[i] not in strangers:
                strangers.append(macs[i])
                write_warnings(f"{ips[i]} : {macs[i]} Connected in LAN at {datetime.now().strftime('%I%p:%M:%S')}\n",
                               create_warnings_logging_paths(my_warning_paths)['strangers'])
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
            write_warnings(f"{ips[i]} : {macs[i]} tried-to-spoof-you at "
                           f"{datetime.now().strftime('%I%p:%M:%S')}\n", create_warnings_logging_paths(my_warning_paths)['spoofs'])
            blackListed.append(got)
            got_blacklisted = True
            rewrite_log = True

    for i in set(statics):  # if new unique macs -> it puts them statics
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
        path_log = os.path.join(path_script, 'Logging')
        if not os.path.isdir(path_log):
            os.system(f"""mkdir "{path_log}" """)

    to_log = {
        "last_time_updated": datetime.now().strftime("%Y-%m-%d_%I%p:%M:%S"),
        "BlackListed": blackListed,
        "statics": stat_list
    }

    if familiar_macs:
        to_log['Strangers'] = strangers

    with open(os.path.join(path_log, "current_log.json"), 'w') as f:
        json.dump(to_log, f, indent=4)


def get_conf_data(json_conf_file):
    with open(json_conf_file) as jf:
        conf_data = json.load(jf)
    return conf_data


path_script = os.path.abspath(os.path.dirname(__file__))

blackListed = []  # The blacklisted [{ips:macs}].
stat_list = []  # [{ips:macs}] has been set to be statics.
strangers = []  # [macs] of stranger devices (if familiar_macs contains values)

if __name__ == '__main__':

    json_conf_file_path = os.path.join(path_script, 'conf_file.json')
    data = get_conf_data(json_conf_file_path)

    familiar_macs = data['familiar_macs']['data']

    path_of_arp_table = data['path_of_arp_table']['data']

    my_warning_paths = data['my_warning_paths']['data']

    path_of_current_log = data['path_of_current_log']['data']

    while True:
        check_and_act(get_macs_ips(), force_static=data['force_static']['data'])
        time.sleep(1)
