from collections import Counter
import copy
import ipaddress
import math
import os
import re
import subprocess
import sys
import tempfile
import datetime
import xml.etree.ElementTree as ET
from threading import Lock

# define ANSI color escape sequences 
# Taken from: http://www.lihaoyi.com/post/BuildyourownCommandLinewithANSIescapecodes.html
# and: http://www.topmudsites.com/forums/showthread.php?t=413
SANE = "\u001b[0m"
GREEN = "\u001b[32m"
RED = "\u001b[31m"
YELLOW = "\u001b[33m"
BRIGHT_BLUE = "\u001b[34;1m"
MAGENTA = "\u001b[35m"

# other ANSI escape sequences
CURSOR_PREV_LINE = "\033[F"
CLEAR_UNTIL_EOL = "\033[K"

# mutex to prevent concurrent printing
PRINT_MUTEX = Lock()

# storing all parsed network expressions
parsed_network_exprs = {}


def add_wildcard_ipv4(network: str, store_hosts: bool=True):
    """
    Parse an IP (v4 or v6) wildcard expression (with range, prefix or '*') using Nmap's "-sL" option
    """

    def get_nmap_xml_hosts():
        nonlocal nmap_call, f
        devnull_fd = open(os.devnull)
        subprocess.call(nmap_call.split(" "), stdout=devnull_fd, stderr=subprocess.STDOUT)
        nm_xml_tree = ET.parse(f.name)
        nmaprun_elem = nm_xml_tree.getroot()
        devnull_fd.close()
        return nmaprun_elem.findall("host")

    if network in parsed_network_exprs:
        if store_hosts and len(parsed_network_exprs[network]) > 1:  # hosts are already stored
            return
        elif not store_hosts:
            return

    hosts = []
    host_ranges = []
    prev_ip = None

    with tempfile.NamedTemporaryFile() as f:
        # first try to parse as IPv4 address
        nmap_call = "nmap -n -sL -oX %s %s" % (f.name, network)
        host_elems = get_nmap_xml_hosts()

        if not host_elems:  # nmap could not parse IPv4 network expression
            # try to parse as IPv6 network expression
            nmap_call += " -6"
            host_elems = get_nmap_xml_hosts()
            if not host_elems:
                return False

        for host_elem in host_elems:
            ip = host_elem.find("address").attrib["addr"]
            if not host_ranges:
                host_ranges.append([ip, ip])
            elif prev_ip is not None:
                if ip_str_to_int(ip) != (ip_str_to_int(prev_ip) + 1):
                    host_ranges[-1][1] = prev_ip
                    host_ranges.append([ip, ip])

            if store_hosts:
                hosts.append(ip)
            prev_ip = ip

    if host_ranges:
        host_ranges[-1][1] = prev_ip  # close last IP range
    if store_hosts:
        parsed_network_exprs[network] = (hosts, host_ranges)
    else:
        parsed_network_exprs[network] = (host_ranges)
    return True


def get_ip_ranges(network: str):
    add_wildcard_ipv4(network)
    return parsed_network_exprs[network][1]


def is_valid_net_addr(network: str):
    return add_wildcard_ipv4(network)


def extend_network_to_hosts(network: str):
    add_wildcard_ipv4(network)
    return parsed_network_exprs[network][0]


def is_ipv4(ip: str):
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    return True


def is_ipv6(ip: str):
    try:
        ipaddress.IPv6Address(ip)
    except ipaddress.AddressValueError:
        return False
    return True


def ip_str_to_int(ip: str):
    if is_ipv4(ip):
        return int(ipaddress.IPv4Address(ip))
    else:
        return int(ipaddress.IPv6Address(ip))


def del_hosts_outside_net(hosts: dict, network: str):
    """
    Deletes all the hosts from the given dict that are
    not a part of the given network expression.
    """

    network_ranges = get_ip_ranges(network)
    network_ranges_int = [(ip_str_to_int(low), ip_str_to_int(high)) for (low, high) in network_ranges]
    hosts_cpy = copy.deepcopy(hosts)  # because a dict cannot change size during iteration
    for ip, _ in hosts_cpy.items():
        try:
            ip_int = ip_str_to_int(ip)
        except ValueError:
            continue
        if not any(low <= ip_int and ip_int <= high for (low, high) in network_ranges_int):
            del hosts[ip]


def print_exception_and_continue(e):
    print("Original exception is: ", file=sys.stderr)
    print(e, file=sys.stderr)
    print("===========================================================", file=sys.stderr)
    print("Continuing with scan ...", file=sys.stderr)


def get_current_timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def clear_previous_line():
    print(CURSOR_PREV_LINE, end="")
    print(CLEAR_UNTIL_EOL, end="")


def hide_cursor():
    print("\033[?25l", end="")


def show_cursor():
    print("\033[?25h", end="")


def parse_config(filepath: str, base_config:dict = {}):
    def remove_quotes(text: str):
        text = text.replace("\"", "")
        text = text.replace("'", "")
        return text

    config = copy.deepcopy(base_config)
    with open(filepath) as f:
        cur_module = "core"  # default to core
        if cur_module not in config:
            config[cur_module] = {}

        comment_started = False
        for line in f.readlines():
            line = line.strip()
            if comment_started:
                if "*/" in line:
                    comment_started = False
                    line = line[line.find("*/")+2:]
                else:
                    continue
            if "/*" in line:
                comment_started = True
                line = line[:line.find("/*")]

            comment_start = line.find("//")
            if comment_start != -1:
                line = line[:comment_start]
            if line == "":
                continue

            # start of module specification
            if line.startswith("["):
                cur_module = line[1:line.find("]")]
                if cur_module not in config:
                    config[cur_module] = {}
            else:
                k, v = line.split("=")
                k = k.strip()
                v = v.strip()
                k = remove_quotes(k)
                v = remove_quotes(v)
                config[cur_module][k] = v

    return config


def printit(text: str, end: str="\n", color=SANE):
    """
    A function allowing for thread safe printing in AVAIN.
    """

    PRINT_MUTEX.acquire()
    print(color, end="")
    print(text, end=end)
    PRINT_MUTEX.release()


def compute_cosine_similarity(text_1: str, text_2: str):
    """
    Compute the cosine similarity of two text strings.
    :param text_1: the first text
    :param text_2: the second text
    :return: the cosine similarity of the two text strings
    """

    def text_to_vector(text: str):
        """
        Get the vector representation of a text. It stores the word frequency
        of every word contained in the given text.
        :return: a Counter object that stores the word frequencies in a dict with the respective word as key
        """
        word = re.compile(r'\w+')
        words = word.findall(text)
        return Counter(words)

    text_vector_1, text_vector_2 = text_to_vector(text_1), text_to_vector(text_2)

    intersecting_words = set(text_vector_1.keys()) & set(text_vector_2.keys())
    inner_product = sum([text_vector_1[w] * text_vector_2[w] for w in intersecting_words])

    abs_1 = math.sqrt(sum([cnt**2 for cnt in text_vector_1.values()]))
    abs_2 = math.sqrt(sum([cnt**2 for cnt in text_vector_2.values()]))
    normalization_factor = abs_1 * abs_2

    if not normalization_factor:  # avoid divison by 0
        return 0.0
    else:
        return float(inner_product)/float(normalization_factor)


def is_neq_prefix(a: str, b: str):
    return a != b and a in b
