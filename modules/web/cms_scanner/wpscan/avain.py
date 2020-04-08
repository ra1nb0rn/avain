import json
import logging
import math
import os
import pty
import re
import shutil
import subprocess

from core.result_types import ResultType
import core.utility as util

# Constants for variable and results sharing
INTERMEDIATE_RESULTS = {ResultType.SCAN: {}, ResultType.WEBSERVER_MAP: {}}
CONFIG = {}
VERBOSE = True

# output files
FOUND_WP_SITES_FILE = "found_wp_sites.json"
WPSCAN_OUTFILE = "wpscan_output.txt"
WPSCAN_OUTFILE_COLOR = "wpscan_output_color.txt"
CREATED_FILES = [FOUND_WP_SITES_FILE, WPSCAN_OUTFILE, WPSCAN_OUTFILE_COLOR]

# regexes to match WordPress path and WPScan version info
WP_FILES_RE = [re.compile(r"^(.*/wp-login.php)/?$"), re.compile(r"^(.*/wp-login.php)/.*"),
               re.compile(r"^(.*/wp-config.php)/?$"), re.compile(r"^(.*/wp-config.php)/.*"),
               re.compile(r"^(.*/wp-admin)/?$"), re.compile(r"^(.*/wp-admin)/.*"),
               re.compile(r"^(.*/wp-content)/?$"), re.compile(r"^(.*/wp-content)/.*"),
               re.compile(r"^(.*/wp-includes)/?$"), re.compile(r"^(.*/wp-includes)/.*")]
WP_VERSION_RE = re.compile(r"WordPress version (\d+(\.\d+)?(\.\d+)?) identified")


def run(results: list):
    """ Entry point for module """

    # setup logger
    logger = logging.getLogger(__name__)
    logger.info("Started scanning WordPress servers with WPScan module")

    # file handles to redirect WPScan output to
    redr_fd_color = open(WPSCAN_OUTFILE_COLOR, "w")
    redr_fd = open(WPSCAN_OUTFILE, "w")

    # loop over every target, identified by ip, hostname and port
    new_scan_result = {}
    webserver_map = INTERMEDIATE_RESULTS[ResultType.WEBSERVER_MAP]
    found_wp_sites = {}
    for ip in webserver_map:
        for portid in webserver_map[ip]:
            for host, host_node in webserver_map[ip][portid].items():
                # determine protocol from scan results if available
                protocol = "http"
                if (ip in INTERMEDIATE_RESULTS[ResultType.SCAN] and
                        portid in INTERMEDIATE_RESULTS[ResultType.SCAN][ip]["tcp"] and
                        "service" in INTERMEDIATE_RESULTS[ResultType.SCAN][ip]["tcp"][portid]):
                    protocol = INTERMEDIATE_RESULTS[ResultType.SCAN][ip]["tcp"][portid]["service"]

                # get WordPress sites that exist on this host
                targets = get_targets(host_node, protocol, host, portid)

                # run WPScan on found WP sites and store the sites for later review
                found_wp_versions = set()
                if targets:
                    if ip not in found_wp_sites:
                        found_wp_sites[ip] = {}
                    if portid not in found_wp_sites[ip]:
                        found_wp_sites[ip][portid] = {}
                    found_wp_sites[ip][portid][host] = list(targets)
                    found_wp_versions = run_wpscan(targets, redr_fd_color, redr_fd)

                # if WordPress versions were found, create a scan result for the host
                if found_wp_versions:
                    if ip not in new_scan_result:
                        new_scan_result[ip] = {"tcp": {}}
                    if portid not in new_scan_result[ip]["tcp"]:
                        new_scan_result[ip]["tcp"][portid] = []

                    for version in found_wp_versions:
                        cpe = "cpe:/a:wordpress:wordpress:" + version
                        scan_dict = {"cpes": [cpe], "name": "WordPress " + version, "portid": portid,
                                     "protocol": "tcp", "state": "open", "service": protocol}
                        new_scan_result[ip]["tcp"][portid].append(scan_dict)

    redr_fd_color.close()
    redr_fd.close()

    # store discovered WordPress sites in extra file
    with open(FOUND_WP_SITES_FILE, "w") as f:
        f.write(json.dumps(found_wp_sites))
    logger.info("Finished scanning WordPress servers with WPScan module")

    # return a new scan result containing the found WordPress CPEs
    if new_scan_result:
        results.append((ResultType.SCAN, new_scan_result))


def get_targets(host_node, protocol, host, portid):
    """ Get URL targets for the given host (hostnode, protocol, hostname, portid) """

    targets = set()
    # iterate over HTTP codes and server paths
    for _, code_node in host_node.items():
        for path in code_node:
            # check if a path contains a well known WordPress file / folder
            wp_path_match = None
            for path_re in WP_FILES_RE:
                wp_path_match = path_re.match(path)
                if wp_path_match:
                    break

            # if so, mark this host as target for WPScan
            if wp_path_match:
                match_path = wp_path_match.group(1)
                target = protocol + "://" + host
                if not((protocol == "http" and portid == "80") or (protocol == "https" and portid == "443")):
                    target += ":" + portid
                target += match_path[:match_path.rfind("/")+1]
                targets.add(target)

            # if target was found and only one WordPress instance per host is allowed, break
            if targets and CONFIG.get("multiple_wp_sites", "false").lower() == "false":
                break
        if targets and CONFIG.get("multiple_wp_sites", "false").lower() == "false":
            break
    return targets


def run_wpscan(targets, redr_fd_color, redr_fd):
    """ Run WPScan on the given targets and redirect the output """

    def reader(fd):
        """Read from the given file descriptor"""
        try:
            while True:
                buffer = os.read(fd, 1024)
                if not buffer:
                    return
                yield buffer
        except (IOError, OSError) as e:
            pass

    found_wp_versions = set()
    cols = shutil.get_terminal_size((80, 20)).columns
    for target in targets:
        # just some printing ...
        count = cols - len(" %s " % target)
        util.printit(math.floor(count / 2) * "-", end="", color=util.BRIGHT_CYAN)
        redr_fd_color.write(util.BRIGHT_CYAN + math.floor(count / 2) * "-" + util.SANE)
        redr_fd.write(math.floor(count / 2) * "-")
        util.printit(" %s " % target, end="")
        redr_fd_color.write(" %s " % target)
        redr_fd.write(" %s " % target)
        util.printit(math.ceil(count / 2) * "-", color=util.BRIGHT_CYAN)
        redr_fd_color.write(util.BRIGHT_CYAN + math.ceil(count / 2) * "-" + util.SANE + "\n")
        redr_fd.write(math.ceil(count / 2) * "-" + "\n")

        # setup WPScan call (for --enumerate: 'dbe' disabled for now b/c WPScan error)
        call = ["wpscan", "-v", "--url", target, "--enumerate", "vp,vt,tt,cb,u,m"]
        if CONFIG.get("wpvulndb_api_token", ""):
            call += ["--api-token", CONFIG["wpvulndb_api_token"]]
        if CONFIG.get("cookie_str", ""):
            call += ["--cookie-string", CONFIG["cookie_str"]]
        if CONFIG.get("max_threads", ""):
            call += ["--max-threads", CONFIG["max_threads"]]
        if CONFIG.get("disable_tls_checks", "true").lower() == "true":
            call += ["--disable-tls-checks"]
        if CONFIG.get("stealthy", "false").lower() == "true":
            call += ["--stealthy"]
        elif CONFIG.get("user_agent", ""):
            call += ["--user-agent", CONFIG["user_agent"]]

        util.acquire_print()
        # execute WPScan call in separate PTY to capture good output
        # adapted from: https://stackoverflow.com/a/28925318
        master, slave = pty.openpty()
        with subprocess.Popen(call, stdout=slave, stderr=subprocess.STDOUT, stdin=subprocess.PIPE,
                              bufsize=1, universal_newlines=True) as proc:
            os.close(slave)
            next_line_add = ""
            for line in reader(master):
                # decoding and processing of WPScan output specifics
                line = line.decode()
                line = line.replace("\r\n", "\n")
                line = next_line_add + line
                next_line_add = ""
                if line.endswith("\x1b["):
                    next_line_add = line[-2:]
                    line = line[:-2]

                # print to screen
                print(line, end="")

                # do not write temporary output to output file
                if not ("Time" in line and "ETA" in line):
                    redr_fd_color.write(line)
                    redr_fd.write(util.strip_ansi_escape_seq(line))

                # get WordPress version from WPScan output
                ver_match = WP_VERSION_RE.search(line)
                if ver_match:
                    # proactively try to fix badly formatted version strings
                    version = ver_match.group(1)
                    dot_count = version.count(".")
                    if dot_count == 0:
                        version += ".0"
                    elif dot_count == 1 and version.endswith("."):
                        version += "0"
                    elif dot_count == 2 and version.endswith("."):
                        version += "0"
                    elif dot_count == 3 and version.endswith("."):
                        version = version[:-1]
                    found_wp_versions.add(version)

        os.close(master)
        util.release_print()

        util.printit("-" * cols, color=util.BRIGHT_CYAN)
        redr_fd_color.write(util.BRIGHT_CYAN + "-" * cols + util.SANE + "\n")
        redr_fd.write("-" * cols + "\n")
        return found_wp_versions
