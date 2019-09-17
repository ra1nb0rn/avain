
import json
import logging
import socket

from core.result_types import ResultType
import core.utility as util
from . import crawler

# define the module's parameters
INTERMEDIATE_RESULTS = {ResultType.SCAN: {}, ResultType.WEBSERVER_MAP: {}}
CONFIG = {}
LOGGER = None
VERBOSE = False
CREATED_FILES = []

TARGETS = []  # list targets as (ip, host, port, service)
HELPER_OUTFILE_BASE = "crawl_helper-"  # stores the output of the crawl helper
NEW_NETLOCS_FILE = "discovered_domains.json"  # stores newly discovered network locations
COMMENTS_FILE_TXT = "discovered_comments.txt"  # stores discovered comments on webpages
COMMENTS_FILE_JSON = "discovered_comments.json"  # stores discovered comments on webpages


def run(results: list):
    """
    Crawl the hosts from the scan result that have a web server running
    """

    global LOGGER

    # setup logger
    LOGGER = logging.getLogger(__name__)
    LOGGER.info("Started webserver crawling")

    set_targets()

    # crawl all the discovered targets
    webserver_map = {}
    new_netlocs = {}
    comments = {}
    for target in TARGETS:
        ip, host, port, service = target
        # determine the base URL of the target
        base_url = build_base_url(host, port, service)

        # build name of file that stores output of helper
        helper_outfile = HELPER_OUTFILE_BASE + base_url.split("://")[1].replace("/", "_")
        if helper_outfile.endswith("_"):
            helper_outfile = helper_outfile[:-1]
        helper_outfile += ".txt"
        CREATED_FILES.append(helper_outfile)

        # determine the inital URLs to get crawled
        start_urls = []
        if INTERMEDIATE_RESULTS[ResultType.WEBSERVER_MAP]:
            if (ip in INTERMEDIATE_RESULTS[ResultType.WEBSERVER_MAP] and
                    port in INTERMEDIATE_RESULTS[ResultType.WEBSERVER_MAP][ip] and
                    host in INTERMEDIATE_RESULTS[ResultType.WEBSERVER_MAP][ip][port]):
                wmap_result = INTERMEDIATE_RESULTS[ResultType.WEBSERVER_MAP][ip][port][host]
                start_urls = get_start_urls(base_url, wmap_result)

        if VERBOSE:
            header = "**** %s:%s - %s ****" % (ip, str(port), host)
            full_header = "*" * len(header) + "\n" + header + "\n" + "*" * len(header) + "\n"
            util.printit(full_header)

        # set up a new crawler for the current target and start it
        crawler_obj = crawler.Crawler(base_url, start_urls, CONFIG, helper_outfile, VERBOSE)
        wmap, new_netlocs_host, comments_host = crawler_obj.crawl()
        del crawler_obj  # explicitly delete object to prevent hang ups

        # store the discovered network locations
        if new_netlocs_host:
            if ip not in new_netlocs:
                new_netlocs[ip] = {}
            if port not in new_netlocs[ip]:
                new_netlocs[ip][port] = list()

            for loc in new_netlocs_host:
                if loc not in new_netlocs[ip][port]:
                    new_netlocs[ip][port].append(loc)

        # store the discovered comments
        if comments_host:
            if ip not in comments:
                comments[ip] = {}
            if port not in comments[ip]:
                comments[ip][port] = {}
            comments[ip][port][host] = comments_host

        # store the actual webserver map information
        if wmap:
            if ip not in webserver_map:
                webserver_map[ip] = {}
            if port not in webserver_map[ip]:
                webserver_map[ip][port] = {}
            webserver_map[ip][port][host] = wmap

        if VERBOSE:
            util.printit("\n")

    # save file with discovered network locations
    with open(NEW_NETLOCS_FILE, "w") as f:
        f.write(json.dumps(new_netlocs, indent=4))
    CREATED_FILES.append(NEW_NETLOCS_FILE)

    # save discovered comments
    save_comments(comments)

    LOGGER.info("Finished webserver crawling")
    results.append((ResultType.WEBSERVER_MAP, webserver_map))


def save_comments(comments: dict):
    """
    Save the comments in JSON and txt format
    """

    # store comments in JSON file
    CREATED_FILES.append(COMMENTS_FILE_JSON)
    with open(COMMENTS_FILE_JSON, "w") as f:
        f.write(json.dumps(comments, indent=4))

    # create a textual representation of the discovered comments
    CREATED_FILES.append(COMMENTS_FILE_TXT)
    with open(COMMENTS_FILE_TXT, "w") as f:
        for ip, ports_node in comments.items():
            for portid, hosts_node in ports_node.items():
                # try to guess protocol prefix for the current network endpoint
                protocol_prefix = ""
                if str(portid) == "80":
                    protocol_prefix = "http://"
                elif str(portid) == "443":
                    protocol_prefix = "https://"

                # iterate over the host names and all its discovered comments
                for host, cur_comments_node in hosts_node.items():
                    header = "**** %s:%s - %s ****" % (ip, str(portid), host)
                    full_header = "*" * len(header) + "\n" + header + "\n" + "*" * len(header) + "\n"
                    f.write(full_header)

                    for path, cur_comments in cur_comments_node.items():
                        f.write("-" * 80 + "\n")
                        f.write(" [+] %s\n" % (protocol_prefix + host + path))
                        f.write("-" * 80 + "\n")

                        # print all of the comments
                        for comment in cur_comments:
                            justification = 14
                            f.write(("  Line %d: " % int(comment["line"])).ljust(justification))
                            lines = comment["comment"].splitlines()
                            if lines:
                                f.write(lines[0] + "\n")
                                if len(lines) > 1:
                                    for line in lines[1:]:
                                        f.write("  " + " " * justification + line + "\n")
                        f.write("\n")
                    f.write("\n")


def get_start_urls(base_url, webserver_map_entry):
    """
    Extract the start URLs from the current webserver map results if available
    """

    start_urls = []
    for _, pages_node in webserver_map_entry.items():
        for path in pages_node:
            # base_url[:-1] to strip trailing slash, b/c path has a '/' in front
            url = base_url[:-1] + path
            start_urls.append(url)

    return start_urls


def build_base_url(host, port, protocol):
    """
    Build the base URL for the given parameters and do not explicitly put the
    standard HTTP(s) ports into the URL.
    """

    base_url = "%s://%s" % (protocol, host)
    if protocol.lower() == "http" and int(port) != 80:
        base_url += ":%d" % int(port)
    elif protocol.lower() == "https" and int(port) != 443:
        base_url += ":%d" % int(port)
    base_url += "/"
    return base_url


def set_targets():
    """
    Determine the targets to crawl. Targets are determined
    by looking at port numbers, service infos and service names.
    """

    global TARGETS

    def add_targets(ip, port, protocol):
        """
        Add as targets this (ip, port, protocol) combination together with every
        available domain name for that IP to deal with virtual hosts.
        """
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
    """
    Return a list containing either only the given IP or a list of all
    available domain names that are bound to this IP. Names are first
    looked up in the local /etc/hosts file and then by actual reverse DNS.
    """

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
