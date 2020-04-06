import logging
import math
import os
import re
import shutil
import subprocess

from core.result_types import ResultType
from core import utility as util

# AVAIN variables & shared scan result
INTERMEDIATE_RESULTS = {ResultType.SCAN: None}
CONFIG = None
VERBOSE = None

# output files
SMBMAP_OUTPUT_FILE = "smbmap_out.txt"
ENUM4LINUX_OUTPUT_FILE = "enum4linux_out.txt"
NMAP_OUTPUT_FILE = "nmap_out.txt"
CREATED_FILES = [SMBMAP_OUTPUT_FILE, ENUM4LINUX_OUTPUT_FILE, NMAP_OUTPUT_FILE]


def run(results):
    """ Entry point of module """

    def print_divider(tool, extra_end="\n"):
        """ Print a divider to differentiate output of different modules """
        nonlocal cols
        tool = " %s " % tool
        count = cols - len(tool)
        util.printit(math.floor(count / 2) * "-", end="", color=util.BRIGHT_CYAN)
        util.printit(tool, end="")
        util.printit(math.ceil(count / 2) * "-" + extra_end, color=util.BRIGHT_CYAN)

    # setup logger
    logger = logging.getLogger(__name__)
    logger.info("Starting SMB enumeration")

    # determine targets
    targets = get_targets()

    # parse specified accounts to use from config
    accounts = []
    if CONFIG.get("accounts", ""):
        accounts_str = CONFIG["accounts"]
        accounts = parse_accounts_str(accounts_str)

    # run in order: SMBMap, Enum4Linux, Nmap SMB vuln scripts
    cols = shutil.get_terminal_size((100, 20))[0]
    print_divider("SMBMap", extra_end="")
    run_smbmap(targets, accounts)
    util.printit()
    print_divider("Enum4Linux")
    run_enum4linux(targets, accounts)
    util.printit()
    print_divider("Nmap SMB Vulnerability Scripts")
    run_nmap_vuln_scripts(targets)

    # no AVAIN results are returned
    logger.info("Finished SMB enumeration")



def get_targets():
    """ Return targets as dict of {"<ip>": [port1, port2]} from scan results """

    targets = {}
    for ip, host in INTERMEDIATE_RESULTS[ResultType.SCAN].items():
        for portid, portinfos in host["tcp"].items():
            for portinfo in portinfos:
                # check the three conditions for becoming a target
                if portid == "139" or portid == "445":
                    if ip not in targets:
                        targets[ip] = []
                    targets[ip].append(portid)
                elif "service" in portinfo and ("smb" in portinfo["service"].lower() or
                                                "samba" in portinfo["service"].lower()):
                    if ip not in targets:
                        targets[ip] = []
                    targets[ip].append(portid)
                elif "name" in portinfo and ("smb" in portinfo["name"].lower() or
                                                "samba" in portinfo["name"].lower()):
                    if ip not in targets:
                        targets[ip] = []
                    targets[ip].append(portid)
    return targets


def parse_accounts_str(accounts_str):
    """ Parse the given (config) string and return the contained accounts """

    accounts = []
    # split at outermost commas
    single_account_strs = util.parse_as_csv(accounts_str)

    # extract (user, pass) tuple from single account string, i.e. from ("user": "pass")
    for single_acc_str in single_account_strs:
        # remove surrounding parentheses
        if single_acc_str.startswith("(") and single_acc_str.endswith(")"):
            single_acc_str = single_acc_str[1:-1]

        # split at colon
        user, passwd = single_acc_str.split(":")
        user = user.strip()
        passwd = passwd.strip()

        # remove surrounding quotation marks and then append account to list
        if ((user.startswith("\"") or user.startswith("'")) and
            (user.endswith("\"") or user.endswith("'"))):
            user = user[1:-1]
        if ((passwd.startswith("\"") or passwd.startswith("'")) and
            (passwd.endswith("\"") or passwd.endswith("'"))):
            passwd = passwd[1:-1]
        accounts.append((user, passwd))
    return accounts


def run_smbmap(targets, accounts):
    """ Run SMBMap on the given targets with all of the given accounts """

    # add guest account to account list
    accounts.insert(0, ("", ""))

    # open redirect file for SMBMap output
    redr_file = open(SMBMAP_OUTPUT_FILE, "w")

    # iterate over targets and scan them
    for ip, ports in targets.items():
        for port in ports:
            # skip port 139 if 445 is also open b/c it 445 prefered for SMB
            if str(port) == "139" and ("445" in ports or 445 in ports):
                continue

            for user, passwd in accounts:
                # Prepare SMBMap call
                call = ["smbmap/smbmap.py", "-u" , user, "-p", passwd, "-P", port, "-H", ip]

                # Execute SMBMap call
                with subprocess.Popen(call, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        bufsize=1, universal_newlines=True) as proc:

                    # process the direct SMBMap output to improve reprinting
                    prev_line_work = False
                    for line in proc.stdout:
                        if prev_line_work:
                            if VERBOSE:
                                util.clear_previous_line()
                            prev_line_work = False
                        if "working on it..." in line.lower():
                            prev_line_work = True

                        # color target IP and show the used authentication
                        print_line = util.strip_ansi_escape_seq(line)
                        if line.startswith("[+] ") and "IP" in line:
                            name = line[line.find("Name: "):].strip()
                            print_line = util.GREEN + "[+] " + "%s:%s" % (ip, port)
                            if user:
                                print_line += util.SANE + "  (auth --> %s:%s)" % (user, passwd)
                            else:
                                print_line += util.SANE + "  (guest session)"
                            if name:
                                print_line += "    Name: " + name
                        print_line = print_line.replace("\n", "")

                        # print output to screen and write it to this module's output file
                        if VERBOSE and print_line:
                            util.printit(print_line)
                        if "working on it..." not in print_line.lower():
                            print_line = util.strip_ansi_escape_seq(print_line) + "\n"
                            redr_file.write(print_line)

    redr_file.close()


def run_enum4linux(targets, accounts):
    """ Run Enum4Linux on the given targets with all of the given accounts """

    # check that enum4linux is installed
    e4l_installed = subprocess.run(["which", "enum4linux"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE)
    # if it's not installed, return
    if e4l_installed.returncode != 0:
        util.printit("Skipping, because Enum4Linux is not installed.")
        util.printit("If you want AVAIN to use Enum4Linux, you have to install it manually.")
        return

    # some regexes to process output
    target_def_re = re.compile(r"Target\W*\.+\W*\d+\.\d+\.\d+.\d+")
    user_def_re = re.compile(r"Username\W*\.+\W*'.*'")
    pass_def_re = re.compile(r"Password\W*\.+\W*'.*'")

    # add guest account to account list
    accounts.insert(0, ("", ""))

    # open redirect file for Enum4Linux output
    redr_file = open(ENUM4LINUX_OUTPUT_FILE, "w")

    # iterate over targets and scan them
    for ip, _ in targets.items():
        # note: enum4linux does not allow specification of ports

        # call Enum4Linux once for every account
        for user, passwd in accounts:
            # Prepare Enum4Linux call
            if user and passwd:
                call = ["enum4linux", "-u" , user, "-p", passwd, ip]
            else:
                call = ["enum4linux", ip]

            # some more regexes to process output
            cur_ip_re = re.compile(r"%s" % re.escape(ip))
            cur_user_re = re.compile(r"%s" % re.escape(user))
            cur_passwd_re = re.compile(r"%s" % re.escape(passwd))

            # Execute Enum4Linux call
            with subprocess.Popen(call, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    bufsize=1, universal_newlines=True) as proc:

                for line in proc.stdout:
                    print_line = line

                    # add colorization to better differ output of several Enum4Linux runs
                    if target_def_re.match(print_line):
                        print_line = util.GREEN + print_line
                    elif user_def_re.match(print_line) or pass_def_re.match(print_line):
                        print_line = util.YELLOW + print_line

                    # color target IP and used username/password
                    print_line = cur_ip_re.sub(util.GREEN + ip + util.SANE, print_line)
                    if user:
                        print_line = cur_user_re.sub(util.YELLOW + user + util.SANE, print_line)
                    if passwd:
                        print_line = cur_passwd_re.sub(util.YELLOW + passwd + util.SANE, print_line)

                    # print processed line to screen
                    if VERBOSE and line and "*unknown*\*unknown*" not in line:
                        util.printit(print_line, end="")

                    # write original line to output file
                    redr_file.write(line)

            util.printit("\n")
            redr_file.write("\n\n")

    redr_file.close()


def run_nmap_vuln_scripts(targets):
    """ Run all available Nmap SMB vuln scripts on the given targets """

    # open redirect file for Nmap output
    redr_file = open(NMAP_OUTPUT_FILE, "w")

    # iterate over targets and scan them
    for ip, ports in targets.items():
        ports = ",".join(ports)

        # Prepare Nmap call
        call = ["nmap", "-Pn", "-n", "--script", "smb-vuln-*", "-p", ports, ip]

        # Execute Nmap call
        with subprocess.Popen(call, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                bufsize=1, universal_newlines=True) as proc:
            for line in proc.stdout:
                if VERBOSE:
                    util.printit(line, end="")
                redr_file.write(line)
        redr_file.write("\n")

    redr_file.close()
