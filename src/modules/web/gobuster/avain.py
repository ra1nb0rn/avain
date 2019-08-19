import datetime
import logging
import os
import requests
import socket
import subprocess


from core.result_types import ResultType
import core.utility as util

INTERMEDIATE_RESULTS = {ResultType.SCAN: None}  # get the current scan result
CONFIG = None
LOGGER = None
VERBOSE = False
CREATED_FILES = ["gobuster_out.txt"]

TARGETS = []  # list targets as (ip, host, port, service)
EXCLUDE_DIRS = set()

def run(results: list):
    global LOGGER, EXCLUDE_DIRS

    # setup logger
    LOGGER = logging.getLogger(__name__)
    LOGGER.info("Starting with gobuster scan")

    set_targets()
    webserver_map = {}
    EXCLUDE_DIRS = set([x.strip() for x in CONFIG.get("exclude_dirs", "").split(",")])

    # open file handle to redirect output
    redr_file = open(CREATED_FILES[0], "w+")

    for (ip, host, port, protocol) in TARGETS:
        if ip not in webserver_map:
            webserver_map[ip] = {}
            LOGGER.info("Initiating scan for %s" % ip)
            if VERBOSE:
                util.printit("*" * 30)
                redr_file.write("*" * 30 + "\n")

                util.printit("+ " + ip + " " + "*" * (27 - len(ip)))
                redr_file.write("+ " + ip + " " + "*" * (27 - len(ip)) + "\n")

                util.printit("*" * 30)
                redr_file.write("*" * 30 + "\n")

        if port not in webserver_map[ip]:
            webserver_map[ip][port] = {}
        if host in webserver_map[ip][port]:
            continue

        # omit port in url if possible
        if (protocol == "http" and port == "80") or (protocol == "https" and port == "443"):
            url = protocol + "://" + host
        else:
            url = protocol + "://" + host + ":" + port

        host_web_map = run_gobuster(url, redr_file)
        webserver_map[ip][port][host] = host_web_map

    # close redirect file
    redr_file.close()

    LOGGER.info("Finished gobuster scan")
    results.append((ResultType.WEBSERVER_MAP, webserver_map))


def run_gobuster(url, redr_file):
    depth = int(CONFIG["depth"])
    dirs = ["/"]

    webserver_map = {}

    start_host = datetime.datetime.now()
    for dir_ in dirs:
        if dir_.count("/") > depth:
            break
        elif (datetime.datetime.now() - start_host).total_seconds() > int(CONFIG["per_host_timeout"]):
            redr_file.write("\nWARNING: HOST SEARCH TIMEOUT ('%s', >%ss)\n" % (url, CONFIG["per_host_timeout"]))
            if VERBOSE:
                util.printit("\nWARNING: HOST SEARCH TIMEOUT ('%s', >%ss)\n" % (url, CONFIG["per_host_timeout"]), color=util.RED)
            break


        cur_url = url + dir_
        gobuster_call = ["gobuster", "dir", "-t", CONFIG["threads"], "-w", CONFIG["wordlist"], "-u", cur_url, "-x", CONFIG["extensions"], "-k"]
        findings = []
        printed_starting, printing_results = False, False
        prev_line_is_progress = False
        start_dir = datetime.datetime.now()
        killed = False
        with subprocess.Popen(gobuster_call, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              bufsize=1, universal_newlines=True) as proc:

            for line in proc.stdout:
                if (datetime.datetime.now() - start_dir).total_seconds() > int(CONFIG["per_directory_timeout"]):
                    redr_file.write("\nWARNING: DIRECTORY SEARCH TIMEOUT ('%s', >%ss)\n" % (dir_, CONFIG["per_directory_timeout"]))
                    if VERBOSE:
                        util.printit("\nWARNING: DIRECTORY SEARCH TIMEOUT ('%s', >%ss)\n" % (dir_, CONFIG["per_directory_timeout"]), color=util.RED)
                    proc.kill()
                    break
                elif (datetime.datetime.now() - start_host).total_seconds() > int(CONFIG["per_host_timeout"]):
                    proc.kill()
                    break

                # handle some weird gobuster printing behavior
                if line.startswith("\x1b[2K"):
                    line = line[len("\x1b[2K"):]
                if printing_results and line.strip() == "":
                    continue

                if VERBOSE:
                    if prev_line_is_progress:
                        util.acquire_print()
                        util.clear_previous_line()
                        util.release_print()
                        delete_last_line(redr_file)

                    prev_line_is_progress = line.startswith("Progress: ")
                    util.printit(line, end="")

                redr_file.write(line)
                if "Starting gobuster" in line:
                    printed_starting = True
                elif "================" in line and printed_starting and (not printing_results):
                    printing_results = True
                elif "================" in line and printing_results:
                    printing_results = False
                elif printing_results:
                    line = line.strip()
                    if line:
                        entry = line[:line.find("(")].strip()
                        code_start = line.find("Status: ") + len("Status: ")
                        code = line[code_start:code_start+3]
                        findings.append((entry, code))

        for finding in findings:
            try:
                code_str = finding[1]
                code = int(code_str)
            except:
                continue

            if finding[0].startswith("/"):
                path = dir_ + finding[0][1:]
            else:
                path = dir_ + finding[0]

            # get location of redirect
            if code == 301 or code == 302:
                resp = requests.get(url + path, allow_redirects=False)
                redirect_to = resp.headers["Location"]
                if redirect_to.startswith("http"):
                    if redirect_to == url + path + "/":
                        resp = requests.get(redirect_to, allow_redirects=False)
                        path = path + "/"
                        code_str = str(resp.status_code)
                    else:
                        if not code_str in webserver_map:
                            webserver_map[code_str] = []
                        webserver_map[code_str].append({"PATH": path, "INFO": "redirect to %s" % redirect_to})
                        continue
                else:
                    if (redirect_to == path + "/") or ("/" + redirect_to == path + "/"):
                        resp = requests.get(redirect_to, allow_redirects=False)
                        path = path + "/"
                        code_str = str(resp.status_code)
                    else:
                        if not code_str in webserver_map:
                            webserver_map[code_str] = []
                        webserver_map[code_str].append({"PATH": path, "INFO": "redirect to %s" % redirect_to})
                        continue

            if not code_str in webserver_map:
                webserver_map[code_str] = []
            webserver_map[code_str].append({"PATH": path})

            if finding[0][finding[0].find("/")+1:] not in EXCLUDE_DIRS:
                if path.endswith("/"):
                    dirs.append(path)
                elif CONFIG["allow_file_depth_search"].lower() == "true":
                    dirs.append(path + "/")

    return webserver_map


def set_targets():
    global TARGETS

    def add_targets(ip, port, protocol):
        nonlocal hosts

        for host in hosts:
            TARGETS.append((ip, host, port, protocol))


    for ip, host_info in INTERMEDIATE_RESULTS[ResultType.SCAN].items():
        hosts = get_hosts(ip)
        for portid, portinfos in host_info["tcp"].items():
            for portinfo in portinfos:
                if portid == "80":
                    add_targets(ip, portid, "http")
                elif portid == "443":
                    add_targets(ip, portid, "https")
                elif "service" in portinfo:
                    if "http" in portinfo["service"].lower():
                        add_targets(ip, portid, "http")
                    elif "https" in portinfo["service"].lower():
                        add_targets(ip, portid, "https")
                elif "name" in portinfo:
                    if "http" in portinfo["name"].lower():
                        add_targets(ip, portid, "http")
                    elif "https" in portinfo["name"].lower():
                        add_targets(ip, portid, "https")


def get_hosts(ip):
    hosts = []
    if CONFIG["do_reverse_dns"].lower() == "true":
        try:
            with open("/etc/hosts") as f:
                entries = f.read().split("\n")
                for entry in entries:
                    entry = entry.strip()
                    if entry.startswith(ip + " "):
                        hosts.append(entry[entry.rfind(" ")+1:])
        except FileNotFoundError:
            pass

        if not hosts:
            try:
                hosts.append(socket.gethostbyaddr(ip)[0])
            except socket.herror:
                hosts.append(ip)

    else:
        hosts = [ip]

    return hosts


def delete_last_line(file):
    """
    Delete the last line of the file handled by the "file" parameter
    Adapted from https://stackoverflow.com/a/10289740
    """

    # Move the pointer (similar to a cursor in a text editor) to the end of the file
    file.seek(0, os.SEEK_END)

    # This code means the following code skips the very last character in the file -
    # i.e. in the case the last line is null we delete the last line
    # and the penultimate one
    pos = file.tell() - 1

    # Read each character in the file one at a time from the penultimate
    # character going backwards, searching for a newline character
    # If we find a new line, exit the search
    while pos > 0 and file.read(1) != "\n":
        pos -= 1
        file.seek(pos, os.SEEK_SET)
    pos += 1

    # So long as we're not at the start of the file, delete all the characters ahead
    # of this position
    if pos > 0:
        file.seek(pos, os.SEEK_SET)
        file.truncate()
