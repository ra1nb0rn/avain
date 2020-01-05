#!/usr/bin/env python3

import copy
import datetime
import json
import logging
import os
import sqlite3
import sys
import xml.etree.ElementTree as ET
import shutil

from cvsslib import cvss3, calculate_vector
from packaging import version

if __name__ != "__main__":
    from . import module_updater
    from core.result_types import ResultType
    import core.utility as util
else:
    sys.path.append("../../core")
    import utility as util

# Parameter definition
if __name__ != "__main__":
    INTERMEDIATE_RESULTS = {ResultType.SCAN: None}  # get the current scan result

VERBOSE = True  # specifies whether to provide verbose output or not
CONFIG = {}
CORE_CONFIG = {}

CREATED_FILES = []
HOST_CVE_FILE = "found_cves.json"
DATABASE_FILE = "nvd_db.db3"
SUMMARY_FILE = "cve_summary.json"

CPE_DICT_FILEPATH = ("..{0}resources{0}official-cpe-dictionary_v2.2.xml").format(os.sep)
CPE_DICT_ET_CPE_ITEMS = None
MAX_LOG_CPES = 30

LOGGER = None

CVSSV3_CAT_NAMES = {"AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required",
                    "UI": "User Interaction", "S": "Scope", "C": "Confidentiality",
                    "I": "Integrity", "A": "Availability"}

CVSSV3_VAL_NAMES = {"AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
                    "AC": {"L": "Low", "H": "High"},
                    "UI": {"N": "None", "R": "Required"},
                    "PR": {"N": "None", "L": "Low", "H": "High"},
                    "S": {"U": "Unchanged", "C": "Changed"},
                    "C": {"N": "None", "L": "Low", "H": "High"},
                    "I": {"N": "None", "L": "Low", "H": "High"},
                    "A": {"N": "None", "L": "Low", "H": "High"}}

QUERIED_CPES = {}


def run(results: list):
    """
    Analyze the specified hosts in HOSTS for CVEs that its software (or hardware) is affected by.
    """

    def process_port_cves(protocol: str):
        nonlocal host, ip
        for _, portinfos in host[protocol].items():
            for portinfo in portinfos:
                add_cves_to_node(portinfo, ip)

    global LOGGER, DB_CURSOR, CREATED_FILES

    # setup logger
    LOGGER = logging.getLogger(__name__)
    LOGGER.info("Starting with CVE analysis")

    hosts = INTERMEDIATE_RESULTS[ResultType.SCAN]

    # initialize database and check for up-to-dateness
    db_conn = None
    try:
        check_database()
    except Exception as excpt:
        util.printit(str(excpt), color=util.RED)
    try:
        db_creation_date = datetime.datetime.fromtimestamp(os.stat(DATABASE_FILE).st_ctime)
        LOGGER.info("Gathering information using the local CVE database last updated on %s",
                    str(db_creation_date))
        db_conn = sqlite3.connect(DATABASE_FILE)
        DB_CURSOR = db_conn.cursor()
    except Exception as excpt:
        util.printit(str(excpt), color=util.RED)
        return

    # start CVE discovery
    LOGGER.info("Starting with CVE discovery of all hosts")
    CREATED_FILES += [HOST_CVE_FILE, SUMMARY_FILE]
    for ip, host in hosts.items():

        if VERBOSE:
            header = "******** %s ********" % ip
            full_header = ("*" * len(header) + "\n" + header + "\n" + "*" * len(header) + "\n")
            util.printit(full_header)

        # get TCP and UDP CVEs
        process_port_cves("tcp")
        process_port_cves("udp")

        # get OS CVEs
        if CONFIG.get("skip_os", "false").lower() == "true":
            LOGGER.info("Skipping OS CVE analysis as stated in config file")
        else:
            for os_info in host["os"]:
                add_cves_to_node(os_info, ip)

    # compute scores and create summary
    LOGGER.info("Done")
    LOGGER.info("Computing final CVSSv3 scores for all hosts")
    scores = calculate_final_scores(hosts)
    LOGGER.info("Done")

    with open(HOST_CVE_FILE, "w") as file:
        file.write(json.dumps(hosts, ensure_ascii=False, indent=3))

    LOGGER.info("Creating summary")
    create_cve_summary(hosts)
    LOGGER.info("Done")

    results.append((ResultType.VULN_SCORE, scores))


def print_cves(all_cves: dict):
    """
    Print all CVEs contained in the given dictionary.

    :param all_cves: a dictionary of {cpe: cves} pairs
    """

    all_cve_nodes_list = list(all_cves.values())
    all_cve_nodes = {}
    for list_entry in all_cve_nodes_list:
        for cve_id, cve_node in list_entry.items():
            all_cve_nodes[cve_id] = cve_node

    all_cve_nodes = sorted(all_cve_nodes.values(), key=lambda entry: entry["cvssv3"], reverse=True)
    count = int(CONFIG.get("max_print_count", -1))
    if count == -1:
        count = len(all_cve_nodes)
    for print_node in all_cve_nodes[:count]:
        description = print_node["description"].replace("\r\n\r\n", "\n").replace("\n\n", "\n").strip()
        print_str = util.GREEN + print_node["id"] + util.SANE
        print_str += " (" + util.MAGENTA + str(print_node["cvssv3"]) + util.SANE + "): "
        print_str +=  description + "\n" + "Reference: " + print_node["href"]
        print_str += ", " + print_node["published"].split(" ")[0]
        util.printit(print_str)


def add_cves_to_node(node: dict, ip: str):
    """
    Search and store all CVEs the given node's CPEs are affected by.
    Print the given string if a CPE with its CVEs would be added twice to the node.
    """

    if "cpes" in node:
        node_cpes = node["cpes"]
        node["original_cpes"] = node_cpes
        node["cpes"] = {}
        broad_cpes = set()
        for cpe in node_cpes:
            # take care of printing
            if VERBOSE:
                protocol = "base"
                if "service" in node:
                    protocol = node["service"].upper()
                elif "protocol" in node:
                    protocol = node["protocol"].upper()
                port = ":" + node["portid"] if protocol != "base" else ""
                print_str = util.BRIGHT_CYAN + "[+] %s%s (%s)" % (ip, port, protocol) + util.SANE
                print_str += " - " + util.YELLOW + cpe + util.SANE + "\n"
                util.printit(print_str)

            # get CPE's CVEs
            all_cves, broad_search = get_cves_to_cpe(cpe)

            if VERBOSE:
                print_cves(all_cves)
                columns = shutil.get_terminal_size((80, 20)).columns
                util.printit("-" * columns + "\n")

            # save all CPEs with their CVEs to the node
            for cur_cpe, cves in all_cves.items():
                if broad_search:
                    broad_cpes.add(cpe)

                if cur_cpe not in node["cpes"]:
                    node["cpes"][cur_cpe] = cves
                elif cur_cpe not in node["original_cpes"]:
                    LOGGER.warning("CPE '%s' already stored in host '%s'\'s %s %s", cur_cpe, ip,
                                   "information node; check whether program correctly replaced",
                                   "vaguer CPEs with more specific CPEs")

        # inform user about imprecise software / vulnerability information
        if len(broad_cpes) == 1:
            add_extra_info(node, "cve_extrainfo", ("Original CPE was invalid, unofficial " +
                                                   "or too broad '%s'. " % next(iter(broad_cpes))) +
                           "Determined more specific / correct CPEs and included their CVEs")
        elif len(broad_cpes) > 1:
            add_extra_info(node, "cve_extrainfo", ("The following original CPEs were invalid, " +
                                                   "unofficial or too broad '%s'. "
                                                   % ", ".join(broad_cpes)) +
                           "Determined more specific / correct CPEs and included their CVEs")
    else:
        # Maybe use https://github.com/cloudtracer/text2cpe here?
        LOGGER.warning("OS of host %s does not have a CPE. %s", ip,
                       "Therefore no CVE analysis can be done for this host's OS.")


def create_cve_summary(hosts: dict):
    """
    For every host create a summary of its CVE analysis and store all summaries in SUMMARY_FILE
    """

    def create_node_summary(node_src: dict, node_dst_list: list):
        """
        Create the CVE analysis summary of the given node
        :param node_src: node containing the detailed analysis results
        :param node_dst: node to store the analysis summary in
        :return: the number of CVEs the node had stored, taken from a set of all the node's CVE-IDs
        """
        counted_cves, cve_count = set(), 0
        # iterate over the node's attributes
        node_dst = {}
        for key, value in node_src.items():
            if key not in ("cpes", "original_cpes"):
                node_dst[key] = value
            elif key == "original_cpes":
                node_dst["cpes"] = value
            else:  # key = "cpes"
                # compute a count of the CVEs of this node
                for _, cves in node_src["cpes"].items():
                    for cve_id in cves:
                        if cve_id not in counted_cves:
                            cve_count += 1
                            counted_cves.add(cve_id)
                node_dst["cve_count"] = str(cve_count)

        try:
            node_dst["cvssv3_severity"] = get_cvss_severity(
                float(node_src.get("aggregated_cvssv3", "N/A")))
        except ValueError:
            pass

        node_dst_list.append(node_dst)

        return cve_count

    def create_port_summaries(protocol: str):
        """
        Create the summary for all ports with the given protocol as transport layer protocol
        """
        nonlocal host, host_summary, total_cve_count
        if protocol in host:
            host_summary[protocol] = {}
            for portid, portinfos in host[protocol].items():
                host_summary[protocol][portid] = []
                for portinfo in portinfos:
                    cve_count = create_node_summary(portinfo, host_summary[protocol][portid])
                    total_cve_count += cve_count


    summary = {}
    for ip, host in hosts.items():
        host_summary = {}
        total_cve_count = 0
        host_summary["os"] = []
        # create OS and port summaries
        if "os" in host and not CONFIG.get("skip_os", "false").lower() == "true":
            for os_info in host["os"]:
                cve_count = create_node_summary(os_info, host_summary["os"])
                total_cve_count += cve_count
        create_port_summaries("tcp")
        create_port_summaries("udp")

        # create full host summary
        host_summary["total_cve_count"] = str(total_cve_count)
        host_summary["final_cvssv3"] = host["final_cvssv3"]
        try:
            host_summary["cvssv3_severity"] = get_cvss_severity(float(host.get("final_cvssv3", "N/A")))
        except ValueError:
            pass

        # copy IP and MAC fields if they originally existed
        if "ip" in host:
            host_summary["ip"] = host["ip"]
        if "mac" in host:
            host_summary["mac"] = host["mac"]

        summary[ip] = host_summary

    # store summary
    with open(SUMMARY_FILE, "w") as file:
        file.write(json.dumps(summary, ensure_ascii=False, indent=3))


def get_cvss_severity(score: float):
    """
    Return the severity of the given CVSSv3 score as string.
    Taken from https://nvd.nist.gov/vuln-metrics/cvss
    """
    if score == 0:
        return "None"
    if 0 < score < 4:
        return "Low"
    if 4 <= score < 7:
        return "Medium"
    if 7 <= score < 9:
        return "High"
    if 9 <= score <= 10:
        return "Critical"
    return "N/A"


def aggregate_scores_weighted_mean(scores: list):
    """
    Aggregate the given scores using a weighted arithmetic mean algorithm
    """
    if not scores:
        return "N/A"

    weights, weight_sum = {}, 0
    for i, score in enumerate(scores):
        try:
            score = float(score)
        except ValueError:
            continue

        weight = (1 / (10.01 - score))**0.8
        weights[i] = weight
        weight_sum += weight

    if weight_sum > 0:
        numerator = sum([weights[i] * scores[i] for i in range(len(scores))])
        end_score = numerator / weight_sum
        end_score = max(0, end_score)  # ensure score is >= 0
        end_score = min(10, end_score) # ensure score is <= 10
    else:
        end_score = "N/A"
    return end_score

def aggregate_scores_max(scores: list):
    """
    Aggregate the given scores by choosing the highest one
    """
    if not scores:
        return "N/A"

    end_score = -1
    for score in scores:
        try:
            score = float(score)
        except ValueError:
            continue
        if score > end_score:
            end_score = score

    end_score = max(0, end_score)  # ensure score is >= 0
    end_score = min(10, end_score) # ensure score is <= 10
    return end_score

def is_broad_cve_entry(entry: dict):
    """
    Return True if the given entry's analysis result is based on a broad CPE, False otherwise.
    """

    def string_in_info(info: str):
        return ("Original CPE was invalid, unofficial or too broad" in info
                or "original CPEs were invalid, unofficial" + "or too broad" in info)

    info_key = "cve_extrainfo"
    if info_key not in entry:
        return False

    if string_in_info(entry[info_key]):
        return True

    i = 1
    while True:
        extra_string = "%s_%d" % (info_key, i)
        if extra_string not in entry:
            return False
        if string_in_info(entry[extra_string]):
            return True
        i += 1


def aggregate_node_scores(node: dict):
    """
    Aggregate the CVSSv3 scores of the given node.
    :return: a tuple containing whether the aggregated node contained broad CPEs
             as well as the aggregated score in that order.
    """
    if is_broad_cve_entry(node):
        counted_cves = set()
        score_list = []
        for _, cves_entry in node.get("cpes", {}).items():
            for cve_id, cve in cves_entry.items():
                if cve_id in counted_cves:
                    continue
                counted_cves.add(cve_id)
                try:
                    score = float(cve["cvssv3"])
                except ValueError:
                    continue
                score_list.append(score)
        return True, aggregate_scores_weighted_mean(score_list)
    else:
        score_list = []
        for _, cves_entry in node.get("cpes", {}).items():
            cves_score_list = [cves_entry[cve_id]["cvssv3"] for cve_id in cves_entry]
            score_list += cves_score_list
        return False, aggregate_scores_max(score_list)


def calculate_final_scores(hosts: dict):
    """
    Calculate the aggregated CVSSv3 scores for every host and its
    services and OS.
    """

    def add_to_score_lists(broad_aggr: bool, score):
        """Add score to one of the two aggregation lists depending on broad_aggr"""
        nonlocal score_list_aggr, score_list_max

        if not isinstance(score, float) and not isinstance(score, int):
            try:
                score = float(score)
            except ValueError:
                return
        if broad_aggr:
            score_list_aggr.append(score)
        else:
            score_list_max.append(score)

    def aggregate_protocol_entry(protocol: str):
        """Aggregate all port nodes with services using TCP as transport protocol"""
        nonlocal host
        if protocol in host:
            for _, portinfos in host[protocol].items():
                for portinfo in portinfos:
                    is_broad_entry, score = aggregate_node_scores(portinfo)
                    portinfo["aggregated_cvssv3"] = score
                    add_to_score_lists(is_broad_entry, portinfo["aggregated_cvssv3"])

    host_scores = {}
    for ip, host in hosts.items():
        score_list_aggr = []
        score_list_max = []

        # aggregate scores of OS and every port to a respective node score
        if "os" in host and not CONFIG.get("skip_os", "false").lower() == "true":
            for os_info in host["os"]:
                broad_aggr, score = aggregate_node_scores(os_info)
                os_info["aggregated_cvssv3"] = score
                add_to_score_lists(broad_aggr, score)
        aggregate_protocol_entry("tcp")
        aggregate_protocol_entry("udp")

        # aggregate the OS and port scores to host score
        if max(score_list_aggr, default=-1) > max(score_list_max, default=-1):
            final_score = aggregate_scores_weighted_mean(score_list_aggr + score_list_max)
        else:
            final_score = aggregate_scores_max(score_list_aggr + score_list_max)
        host["final_cvssv3"] = final_score
        host_scores[ip] = host["final_cvssv3"]

    return host_scores

def parse_cpe_dict():
    """
    If not already parsed, parse the CPE dict stored under
    CPE_DICT_FILEPATH to retrieve a list of all available CPEs.
    """
    global CPE_DICT_ET_CPE_ITEMS

    if not CPE_DICT_ET_CPE_ITEMS:
        # open file descriptor for CPE dict in case further lookup has to be done
        LOGGER.info("Parsing CPE dictionary for further lookups")
        # first child needs to be skipped, because it's XML generator
        CPE_DICT_ET_CPE_ITEMS = list(ET.parse(CPE_DICT_FILEPATH).getroot())[1:]
        LOGGER.info("Done")


def add_extra_info(dict_: dict, info_key: str, text: str):
    """
    Add extra info as string to the given dict. If the dict already contains the
    given key, increasing numbers are appended to the key.

    :param dict_: the dict to append to
    :param info_key: the key under which to store the extran information
    :param text: the information to store
    """
    if info_key not in dict_:
        dict_[info_key] = text
    else:
        i = 1
        while True:
            extra_string = "%s_%d" % (info_key, i)
            if extra_string not in dict_:
                dict_[extra_string] = text
                return
            i += 1


def is_neq_prefix(text_1, text_2):
    """Return True if text_1 is a non-equal prefix of text_2"""
    return text_1 != text_2 and text_2.startswith(text_1)


def get_cpe_version(cpe: str):
    """Return the version entry of the given CPE"""
    split_cpe = cpe.split(":")
    if len(split_cpe) > 4:
        return split_cpe[4]
    return ""


def is_unknown_cpe(cpe: str):
    """Return True if cpe is not in official CPE dicionary, False otherwise"""
    parse_cpe_dict()
    return not any(cpe == cpe_iter.attrib["name"] for cpe_iter in CPE_DICT_ET_CPE_ITEMS)


def get_cves_to_cpe(cpe: str):
    """
    Gather CVE information for the given CPE string.

    :param cpe: the CPE string
    :return: a dict indexed by "related" CPEs and CVE information as value
    """

    # if CPE has already been queried before
    if cpe in QUERIED_CPES:
        return copy.deepcopy(QUERIED_CPES[cpe])

    # get information about CPE-CVE correlation
    broad_search, found_cves, general_cve_cpe_data = gather_cve_cpe_information(cpe)
    cpe_version = get_cpe_version(cpe)

    if cpe_version:
        process_general_cve_cpe_data(found_cves, general_cve_cpe_data)
    elif CONFIG.get("allow_versionless_search", "true").lower() == "true":
        for entry in general_cve_cpe_data:
            cve_id, entry_cpe, with_cpes = entry[0], entry[1], entry[6]
            if not entry_cpe in found_cves:
                found_cves[entry_cpe] = {}
            found_cves[entry_cpe][cve_id] = with_cpes

    # limit number of entries per CPE string
    if CONFIG.get("max_cve_count", "-1") != "-1":
        count = int(CONFIG["max_cve_count"])
        found_cves_copy = copy.deepcopy(found_cves)
        for cpe_iter, cve_dict in found_cves_copy.items():
            cve_ids = list(set(cve_dict))[:count]
            found_cves[cpe_iter] = {}

            for cve_id in cve_ids:
                found_cves[cpe_iter][cve_id] = cve_dict[cve_id]

    # get detailed CVE information and add it
    cve_details = get_cve_details(found_cves)
    cve_results = add_cve_details(cpe, found_cves, cve_details)

    if not cve_results:
        cve_results = {cpe: {}}

    QUERIED_CPES[cpe] = (copy.deepcopy(cve_results), broad_search)
    return cve_results, broad_search


def gather_cve_cpe_information(cpe: str):
    """
    Query the local NVD database to retrieve information about CVEs and CPEs
    affected by them that are "related" to the given CPE.
    """

    def is_broad_version():
        """
        Return True if there is a macthing CPE available in the CPE dict whose version
        is more precise than cpe_version, False otherwise
        """
        nonlocal general_cpe, cpe_version, values

        parse_cpe_dict()
        found_more_precise = False
        for cpe_item in CPE_DICT_ET_CPE_ITEMS:
            dict_cpe = cpe_item.attrib["name"]
            dict_cpe_fields = dict_cpe[7:].split(":")
            dict_general_cpe = dict_cpe[:7] + ":".join(dict_cpe_fields[:2])

            if len(dict_cpe_fields) > 2:
                if general_cpe == dict_general_cpe:
                    if cpe_version == dict_cpe_fields[2]:  # if exact CPE version match found, version is not broad
                        return False
                    elif is_neq_prefix(cpe_version, dict_cpe_fields[2]):
                        found_more_precise = True
            if len(values) > 3 and dict_cpe.startswith((general_cpe + ":" + cpe_version + ":")):
                found_more_precise = True

        return found_more_precise

    def is_unknown_version():
        """
        Return True if cpe is not a match or prefix of any CPE in the CPE dict,
        False otherwise.
        """
        nonlocal general_cpe, cpe_version
        parse_cpe_dict()
        for cpe_item in CPE_DICT_ET_CPE_ITEMS:
            if cpe == cpe_item.attrib["name"]:
                return False
            if general_cpe + ":" + cpe_version + ":" in cpe_item.attrib["name"]:
                return False
        return True

    values = cpe[7:].split(":")
    general_cpe = cpe[:7] + ":".join(values[:2])
    # nvd.nist seems to do this with e.g. cpe:/o:microsoft:windows_10:1607::~~~~x64~
    # if len(values) > 3:
    #     cpe = cpe[:7] + ":".join(values[:3])

    # query exactly matching CPEs for CVE data
    found_cves = {}
    query = "SELECT DISTINCT cve_id, with_cpes FROM cve_cpe WHERE cpe=\"%s\"" % cpe
    if CONFIG.get("max_cve_count", "-1") != "-1":
        query += " LIMIT %s" % CONFIG["max_cve_count"]
    found_cves_specific = DB_CURSOR.execute(query).fetchall()

    found_cves[cpe] = {}
    if found_cves_specific:
        for cve_id, with_cpes in found_cves_specific:
            found_cves[cpe][cve_id] = with_cpes

    if len(values) == 2:
        cpe_version = None
    elif len(values) > 2:
        cpe_version = values[2]

    # query DB for general CPE-CVE data with cpe_version_start and cpe_version_end fields
    if CONFIG.get("allow_versionless_search", "true").lower() == "true":
        query = ("SELECT cve_id, cpe, cpe_version_start, cpe_version_start_type, cpe_version_end, " +
                 "cpe_version_end_type, with_cpes FROM cve_cpe WHERE cpe LIKE \"%s%%\"" % general_cpe)
    else:
        query = ("SELECT cve_id, cpe, cpe_version_start, cpe_version_start_type, cpe_version_end, " +
                 "cpe_version_end_type, with_cpes FROM cve_cpe WHERE cpe=\"%s\" " % general_cpe +
                 "UNION " +
                 "SELECT cve_id, cpe, cpe_version_start, cpe_version_start_type, cpe_version_end, " +
                 "cpe_version_end_type, with_cpes FROM cve_cpe WHERE cpe LIKE \"%s::%%\"" % general_cpe)

    if CONFIG.get("max_cve_count", "-1") != "-1":
        query += " LIMIT %s" % CONFIG["max_cve_count"]

    general_cve_cpe_data = DB_CURSOR.execute(query).fetchall()
    broad_search = (cpe_version is None or is_broad_version() or
                    is_unknown_version() or cpe_version == "-")  # '-' stands for all versions
    # find the most specific CPE possible
    if broad_search:
        if cpe_version:
            cur_cpe = general_cpe + ":" + cpe_version
        else:
            cur_cpe = cpe

        specific_cves = []
        # while cur_cpe has at least a version
        while len(cur_cpe) > 0 and not cur_cpe.count(":") < 4:
            query = "SELECT DISTINCT cve_id, cpe, with_cpes FROM cve_cpe WHERE cpe LIKE \"%s%%\"" % cur_cpe
            if CONFIG.get("max_cve_count", "-1") != "-1":
                query += " LIMIT %s" % CONFIG["max_cve_count"]
            specific_cves = DB_CURSOR.execute(query).fetchall()
            if specific_cves:
                discv_cpes_query = "SELECT DISTINCT cpe FROM cve_cpe WHERE cpe LIKE \"%s%%\"" % cur_cpe
                discv_cpes = DB_CURSOR.execute(discv_cpes_query).fetchall()

                # if original CPE was broad, but only one new CPE could be discovered
                if len(discv_cpes) == 1:
                    broad_search = False
                break

            if is_broad_version():
                cur_cpe = ""
            else:
                cur_cpe = cur_cpe[:-1]

        for cve_id, cpe_iter, with_cpes in specific_cves:
            # nvd.nist seems to do this with e.g. cpe:/o:microsoft:windows_10:1607::~~~~x64~
            # values = cpe_iter[7:].split(":")
            # if len(values) > 3:
            #     cpe_iter = cpe_iter[:7] + ":".join(values[:3])
            if cpe_iter not in found_cves:
                found_cves[cpe_iter] = {}
            found_cves[cpe_iter][cve_id] = with_cpes

    return broad_search, found_cves, general_cve_cpe_data


def process_general_cve_cpe_data(found_cves: dict, general_cve_cpe_data: dict):
    """
    Process the general CVE-CPE data that potentially has cpe_version_start
    or cpe_version_end entries.
    :param found_cves: so far discovered CVEs indexed by CPEs affected by them
    :param general_cve_cpe_data: the general CVE-CPE data
    """

    for cpe_iter in found_cves:
        cpe_iter_split = cpe_iter[7:].split(":")
        cpe_iter_version = cpe_iter_split[2]
        cpe_iter_version = version.parse(cpe_iter_version)

        for entry in general_cve_cpe_data:
            entry_cpe = entry[1]
            entry_cpe_split = entry_cpe[7:].split(":")
            version_start, version_start_type = entry[2], entry[3]
            version_end, version_end_type = entry[4], entry[5]
            with_cpes = entry[6]

            # check if current CPE's version is within a range of vulnerable versions
            cpe_in = False

            if version_start and version_end:
                if version_start_type == "Including" and version_end_type == "Including":
                    cpe_in = version.parse(version_start) <= cpe_iter_version <= version.parse(version_end)
                elif version_start_type == "Including" and version_end_type == "Excluding":
                    cpe_in = version.parse(version_start) <= cpe_iter_version < version.parse(version_end)
                elif version_start_type == "Excluding" and version_end_type == "Including":
                    cpe_in = version.parse(version_start) < cpe_iter_version <= version.parse(version_end)
                else:
                    cpe_in = version.parse(version_start) < cpe_iter_version < version.parse(version_end)
            elif version_start:
                if version_start_type == "Including":
                    cpe_in = version.parse(version_start) <= cpe_iter_version
                elif version_start_type == "Excluding":
                    cpe_in = version.parse(version_start) < cpe_iter_version
            elif version_end:
                if version_end_type == "Including":
                    cpe_in = cpe_iter_version <= version.parse(version_end)
                elif version_end_type == "Excluding":
                    cpe_in = cpe_iter_version < version.parse(version_end)
            elif len(entry_cpe_split) > 1:  # make sure that at least product information is available
                cpe_in = True
                for i in range(min(len(entry_cpe_split), len(cpe_iter_split))):
                    if entry_cpe_split[i] == "" or entry_cpe_split[i] == "-":  # '-' as symbol for 'any'
                        continue
                    if entry_cpe_split[i] != cpe_iter_split[i]:
                        cpe_in = False
                        break

            if cpe_in:
                if len(cpe_iter_split) > 2 and len(entry_cpe_split) > 2:
                    # check that everything after the version entry matches
                    if len(entry_cpe_split) > 2 and entry_cpe_split[2] == "" or entry_cpe_split[2] == "-":
                        cpe_in = ":".join(cpe_iter_split[3:]) == ":".join(entry_cpe_split[3:])

            if cpe_in:
                found_cves[cpe_iter][entry[0]] = with_cpes


def get_cve_details(found_cves: dict):
    """
    Gather all remaining available information for the discovered CVEs.
    """

    cve_details = {}
    for _, cve_dict in found_cves.items():
        cve_ids = set(cve_dict)

        for cve_id in cve_ids:
            if cve_id in cve_details:
                continue

            descr, publ, last_mod, cvss_ver, score, vector = DB_CURSOR.execute("SELECT description, " +
                "published, last_modified, cvss_version, base_score, vector FROM cve WHERE cve_id = \"%s\"" % (cve_id)).fetchone()
            cve_details[cve_id] = {"id": cve_id, "description": descr, "published": publ, "modified": last_mod,
                                   "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id}

            if float(cvss_ver) == 2:
                cve_details[cve_id]["cvssv2"] = float(score)
                cve_details[cve_id]["vector_short"] = vector
                transform_cvssv2_to_cvssv3(cve_details[cve_id])
                add_detailed_vector(cve_details[cve_id])
                add_extra_info(cve_details[cve_id], "extrainfo", ("Specified CVSSv3 score was converted from CVSSv2 " +
                                                                  "score because there was no CVSSv3 score available."))
            elif float(cvss_ver) == 3 or float(cvss_ver) == 3.1:
                cve_details[cve_id]["cvssv3"] = float(score)
                cve_details[cve_id]["vector_short"] = vector
                add_detailed_vector(cve_details[cve_id])
            else:
                cve_details[cve_id]["cvssv3"] = -1  # replace with N/A later, but needed for sorting here
                cve_details[cve_id]["vector_short"] = "N/A"
                add_extra_info(cve_details[cve_id], "extrainfo", "No CVSS score available in the NVD.")
    return cve_details


def add_cve_details(cpe: str, found_cves: dict, cve_details: dict):
    """
    Add the detailed CVE information to the already discovered CVE IDs.
    """

    cpe_version = get_cpe_version(cpe)
    cve_results = {}
    for cpe_iter, cve_dict in found_cves.items():
        cve_ids = sorted(set(cve_dict), key=lambda cve_id: cve_details[cve_id]["cvssv3"], reverse=True)
        found_cves_dict = {}

        for cve_id in cve_ids:
            cve_entry = copy.deepcopy(cve_details[cve_id])
            if cve_entry["vector_short"] == "N/A":
                cve_entry["cvssv3"] = "N/A"

            with_cpes_list = list(filter(None, cve_dict[cve_id].split(",")))
            if len(with_cpes_list) == 1:
                add_extra_info(cve_entry, "extrainfo", "Note - only vulnerable in conjunction " +
                               "with '%s'" % ", ".join(with_cpes_list))
            elif len(with_cpes_list) > 1:
                add_extra_info(cve_entry, "extrainfo", "Note - only vulnerable in conjunction " +
                               "with either one of {%s}" % ", ".join(with_cpes_list))
            found_cves_dict[cve_id] = cve_entry

        # check if "broad" CPE was "only" missing a separator between CPE version and update
        # e.g. scan-result: cpe:/a:openbsd:openssh:6.7p1  correct CPE: cpe:/a:openbsd:openssh:6.7:p1
        cpe_iter_parts = cpe_iter[5:].split(":")
        if len(cpe_iter_parts) == 5:
            cpe_check = cpe_iter[:5] + ":".join(cpe_iter_parts[:-1]) + cpe_iter_parts[-1]
        elif len(cpe_iter_parts) > 5:
            cpe_check = (cpe_iter[:5] + ":".join(cpe_iter_parts[:4]) + cpe_iter_parts[4] +
                         "::" + ":".join(cpe_iter_parts[5:]))
        else:
            cpe_check = None

        if cpe_check and cpe_check == cpe:
            cve_results = {cpe_iter: found_cves_dict}
            break
        # enforce that if original cpe has version,
        # its version is part of current iterating cpe's version
        elif not cpe_version or cpe_version in cpe_iter_parts[3]:
            if CONFIG.get("squash_cpes", "True") == "True":
                if not cpe in cve_results:
                    cve_results[cpe] = {}
                for cve_id, cve_entry in found_cves_dict.items():
                    if not cve_id in cve_results[cpe]:
                        cve_results[cpe][cve_id] = cve_entry
            else:
                cve_results[cpe_iter] = found_cves_dict
    return cve_results


def add_detailed_vector(cve: dict):
    """
    Use the given CVE node's short CVSSv3 vector to add a detailed CVSSv3 vector version to it.
    """
    vector_short = cve["vector_short"]
    if vector_short == "N/A":  # no CVSS score available
        return

    if vector_short.startswith("CVSS:3.0/"):
        vector_short = vector_short[len("CVSS:3.0/"):]
    elif vector_short.startswith("CVSS:3.1/"):
        vector_short = vector_short[len("CVSS:3.1/"):]

    vector_detail = {}
    fields = vector_short.split("/")
    for field in fields:
        key, value = field.split(":")
        vector_detail[CVSSV3_CAT_NAMES[key]] = CVSSV3_VAL_NAMES[key][value]

    cve["vector_detail"] = vector_detail


def transform_cvssv2_to_cvssv3(cve: dict):
    """
    Transform CVSSv2 vector and score of given CVE to CVSSv3
    """
    # Conversion incentives are taken from: https://security.stackexchange.com/questions/127335/how-to-convert-risk-scores-cvssv1-cvssv2-cvssv3-owasp-risk-severity
    converted_cvssv3_vector = ""
    vector_fields = cve["vector_short"].split("/")  # remove left and right parenthesis
    for vector_field in vector_fields:
        key, val = vector_field.split(":")
        # straightforware value conversion
        if key == "AC":
            if val == "M":
                val = "L"
        elif key == "Au":
            if val == "S":
                val = "L"
            elif val == "M":
                val = "H"
            key = "PR"
        elif key in ("C", "I", "A"):
            if val == "C":
                val = "H"
            elif val == "P":
                val = "H"
            elif val == "N":
                val = "N"
        elif key == "RL":
            if val == "OF":
                val = "O"
            elif val == "TF":
                val = "T"
            elif val == "ND":
                val = "X"
        elif key == "RC":
            if val == "UR":
                val = "R"
            elif val == "UC":
                val = "U"
            elif val == "ND":
                val = "X"

        converted_cvssv3_vector += "%s:%s/" % (key, val)

    # always declare Scope as "unchanged"
    converted_cvssv3_vector += "S:U/"

    # derive value for user interaction from access complexity metric
    if "AC:H" in cve["vector_short"] or "AC:M" in cve["vector_short"]:
        converted_cvssv3_vector += "UI:R/"
    else:
        converted_cvssv3_vector += "UI:N/"

    converted_cvssv3_vector = converted_cvssv3_vector[:-1]  # remove trailing /

    # backup the original CVSSv2 information and add the CVSSv3 information
    if "vector_detail" in cve:
        del cve["vector_detail"]
    cve["orig_cvssv2"] = cve["cvssv2"]
    del cve["cvssv2"]
    cve["orig_cvssv2_vector"] = cve["vector_short"]
    del cve["vector_short"]
    cve["vector_short"] = ("CVSS:3.0/%s" % converted_cvssv3_vector).replace("(", "")
    vector_v3 = "CVSS:3.0/" + converted_cvssv3_vector
    cvssv3 = calculate_vector(vector_v3, cvss3)[0]  # get base score of cvssv3 score vector
    cve["cvssv3"] = cvssv3


def check_database():
    """
    Check the CVE database for validity. Validity means:
    1.) it exists; 2.) it is up-to-date with regard to
    the expire time stored in the used config file.
    """

    def do_db_update(log_msg: str):
        """
        Conduct a database update after logging the given message.
        """
        global CREATED_FILES

        LOGGER.info(log_msg)
        module_updater.run([])
        LOGGER.info("Done.")
        os.makedirs("db_update", exist_ok=True)
        update_files = module_updater.CREATED_FILES
        for file in update_files:
            new_file = os.path.join("db_update", file)
            os.rename(os.path.abspath(file), new_file)
        CREATED_FILES.append("db_update")

    if os.path.isfile(DATABASE_FILE):
        # do not update DB if automatic updates are disabled
        if CORE_CONFIG["automatic_module_updates"].lower() != "true":
            return

        # otherwise check DB creation date and update if outdaded
        db_date = util.get_creation_date(DATABASE_FILE)
        db_age = datetime.datetime.now() - db_date
        try:
            db_age_limit = datetime.timedelta(minutes=int(CONFIG["DB_expire"]))
        except ValueError:
            LOGGER.warning("DB_expire is invalid and cannot be processed. %s",
                           "Skipping check whether database is up-to-date.")

        if db_age > db_age_limit:
            do_db_update("Database has expired. Conducting update.")
        else:
            LOGGER.info("Database is up-to-date; expires in %s", str(db_age_limit - db_age))
    else:
        do_db_update("Database does not exist. Installing.")


if __name__ == "__main__":
    # Provide CPE CVE lookup functionality if this file is called on its own
    if 2 <= len(sys.argv) <= 3:
        cpe = sys.argv[1]
        util.printit("\n" + "[+] " + cpe, color=util.BRIGHT_CYAN)
        util.printit("-" * 80, color=util.BRIGHT_CYAN)

        # setup
        VERBOSE = False  # disable AVAIN's verbose printing
        logging.basicConfig(stream=sys.stdout, level=logging.CRITICAL)
        LOGGER = logging.getLogger(__name__)
        db_conn = sqlite3.connect(DATABASE_FILE)
        DB_CURSOR = db_conn.cursor()

        retrieved_cves = get_cves_to_cpe(cpe)[0]
        print_cves(retrieved_cves)

        if len(sys.argv) > 2:
            outfile = sys.argv[2]
            if not os.path.isabs(outfile):
                outfile = os.path.join(os.environ.get("CUR_DIR", "."), outfile)

            result = {"count": 0}
            for key_g, value_g in retrieved_cves.items():
                result["count"] += len(value_g)
                result[key_g] = value_g
            with open(outfile, "w") as file:
                file.write(json.dumps(result, ensure_ascii=False, indent=3))
            LOGGER.info("Done")
    else:
        print("Error: wrong number of arguments.")
        print("usage: %s cpe [outfile]" % sys.argv[0])
