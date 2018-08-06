from collections import Counter
import copy
import ipaddress
import logging
import math
import re
import sys
import datetime

# TODO: How to handle broadcast and network identifier addresses. Decide to include or not and fix.

LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

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


def parse_wildcard_ipv4(network: str):
    """
    Parse an IPv4 wildcard expression (with range, prefix or '*')

    :return: a list of all contained hosts within the IP expression
    """

    def get_all_hosts(splits):
        if splits:
            if len(splits) == 1:
                return [str(i) for i in splits[0]]
            else:
                all_concat = []
                all_after = get_all_hosts(splits[1:])
                for i in splits[0]:
                    for j in all_after:
                        all_concat.append("%d.%s" % (i, j))
                return all_concat
        else:
            return []

    cidr = None
    if "/" in network:
        cidr = "".join(network[network.rfind("/")+1:])
        network = network[:network.rfind("/")]
    split_ip = network.split(".")

    for i, num in enumerate(split_ip):
        # only digit no wildcard
        try:
            num_int = int(num)
            if num_int in range(0, 256):
                split_ip[i] = [num_int]
            else:
                raise ValueError("A textual IP address does not contain numbers above 255")
        except ValueError:
            if "*" in num:
                if len(num) > 3:
                    raise ValueError("A textual IP address does not contain four-digit numbers")
                if num.count("*") > 1:
                    raise ValueError("You cannot have two wildcard symbols within one IP number")

                if num[0] == "*":
                    if len(num) == 3:
                        for j in range(10):
                            split_ip[i] += j * 100 + int(num[1:2])
                    elif len(num) == 2:
                        for j in range(10):
                            split_ip[i] += j * 10 + int(num[1])
                    else:
                        split_ip[i] = list(range(0, 256))
                elif num[1] == "*":
                    if len(num) == 3:
                        for j in range(10):
                            split_ip[i] += int(num[0]) * 100 + j * 10 + int(num[2])
                    elif len(num) == 2:
                        for j in range(10):
                            split_ip[i] += int(num[0]) * 10 + j
                elif num[2] == "*":
                    if len(num) == 3:
                        for j in range(10):
                            split_ip[i] += int(num[0]) * 100 + int(num[2]) * 10 + j 
            elif "-" in num:
                l, r = num.split("-")
                split_ip[i] = range(int(l), int(r)+1)

    if not cidr:
        return get_all_hosts(split_ip)
    else:
        all_hosts_no_cidr = get_all_hosts(split_ip) 
        all_hosts = []

        for host in all_hosts_no_cidr:
            all_hosts += parse_cidr_ipv4(host + "/" + cidr)

        return all_hosts


def is_cidr_ipv4(network: str):
    try:
        ipaddress.ip_network(network)
        return True
    except ValueError:
        return False


def parse_cidr_ipv4(network: str):
    if "/" in network:
        return list(str(ip) for ip in ipaddress.ip_network(network).hosts())
    else:
        return network


def is_valid_net_addr(network):
    if not is_cidr_ipv4(network):
        if (not "-" in network) and (not "*" in network):
            return False
    return True


def extend_network_to_hosts(network):
    if "*" in network or "-" in network:
        return parse_wildcard_ipv4(network)
    else:
        return parse_cidr_ipv4(network)


def ip_str_to_number(ip):
    return int.from_bytes([int(ip) for ip in ip.split(".")], "big")


def print_exception_and_continue(e):
    print("Original exception is: ", file=sys.stderr)
    print(e, file=sys.stderr)
    print("===========================================================", file=sys.stderr)
    print("Continuing with scan ...", file=sys.stderr)


def get_current_timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def get_logger(module_name: str, logfile: str):
    """
    Create a logger with the given module name logging to the given logfile.

    :param module_name: the name of the module the logger is for
    :param logile: filepath to the logfile
    :return: a logger with the specified attributes
    """

    logger = logging.getLogger(module_name)
    logger.setLevel(logging.INFO)

    # create log file handler
    handler = logging.FileHandler(logfile, encoding="utf-8")
    handler.setLevel(logging.INFO)

    # create logging format
    formatter = logging.Formatter(LOGGING_FORMAT)
    handler.setFormatter(formatter)

    # add the handler to the logger
    logger.addHandler(handler)

    return logger


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
