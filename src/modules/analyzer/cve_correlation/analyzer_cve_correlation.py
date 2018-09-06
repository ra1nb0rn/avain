#!/usr/bin/env python3

from bs4 import BeautifulSoup
import copy
from cvsslib import cvss3, calculate_vector
import datetime
import json
import logging
import os
from packaging import version
import requests
import subprocess
import sqlite3
import sys
import vulners
import warnings
import xml.etree.ElementTree as ET

if __name__ != "__main__":
    from .module_updater import update_module
    from core import utility as util

HOST_CVE_FILE = "found_cves.json"
DATABASE_FILE = "nvd_db.db3"
SUMMARY_FILE = "cve_summary.json"

HOSTS = {}  # a string representing the network to analyze
ONLINE_ONLY = False
VERBOSE = False  # specifying whether to provide verbose output or not
CONFIG = {}

CREATED_FILES = []

CPE_DICT_FILEPATH = "{0}{1}resources{1}official-cpe-dictionary_v2.2.xml".format(os.environ["AVAIN_DIR"], os.sep)
CPE_DICT_ET_CPE_ITEMS = None
NUM_CVES_PER_CPE_MAX = 25
VULNERS_MAX_VULNS = 1000
MAX_LOG_CPES = 30

logger = None

CVSSV3_CAT_NAMES = {"AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required", "UI": "User Interaction",
                    "S": "Scope", "C": "Confidentiality", "I": "Integrity", "A": "Availability"}

CVSSV3_VAL_NAMES = {"AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
                    "AC": {"L": "Low", "H": "High"}, "UI": {"N": "None", "R": "Required"},
                    "PR": {"N": "None", "L": "Low", "H": "High"}, "S": {"U": "Unchanged", "C": "Changed"},
                    "C": {"N": "None", "L": "Low", "H": "High"}, "I": {"N": "None", "L": "Low", "H": "High"},
                    "A": {"N": "None", "L": "Low", "H": "High"}}

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for CVEs belonging regarding its software.

    :return: a tuple contaiging the analyis results/scores and a list of created files by writing it into the result list.
    """

    def process_os_cves():
        nonlocal host, ip

        if "cpes" in host["os"]:
            os_cpes = host["os"]["cpes"]
            host["os"]["original_cpes"] = os_cpes
            host["os"]["cpes"] = {}
            broad_cpes = set()
            for cpe in os_cpes:
                # get cpe cves
                if ONLINE_ONLY:
                    all_cves, broad_search = get_cves_to_cpe_via_vulners(cpe, NUM_CVES_PER_CPE_MAX)
                else:
                    all_cves, broad_search = get_cves_to_cpe(cpe, NUM_CVES_PER_CPE_MAX)

                for cur_cpe, cves in all_cves.items():
                    if broad_search:
                        broad_cpes.add(cpe)

                    if cur_cpe not in host["os"]["cpes"]:
                        host["os"]["cpes"][cur_cpe] = cves
                    else:
                        logger.warning("CPE '%s' already stored in host '%s'\'s OS information; " % (cur_cpe, ip) +
                            "check whether program correctly replaced vaguer CPEs with more specific CPEs")

            if len(broad_cpes) == 1:
                add_extra_info(host["os"], "cve_extrainfo", ("Original CPE was invalid, unofficial or too broad '%s'. " % next(iter(broad_cpes))) + \
                    "Determined more specific / correct CPEs and included their CVEs")
            elif len(broad_cpes) > 1:
                add_extra_info(host["os"], "cve_extrainfo", ("The following original CPEs were invalid, unofficial or too broad '%s'. " % ", ".join(broad_cpes)) + \
                    "Determined more specific / correct CPEs and included their CVEs")
        else:
            # TODO: implement / how about using https://github.com/cloudtracer/text2cpe ?
            logger.warning("OS of host %s does not have a CPE. Therefore no CVE analysis can be done for this host's OS." % ip)

    def process_port_cves(protocol):
        nonlocal host, ip

        for portid, portinfo in host[protocol].items():
            if "cpes" in portinfo:
                service_cpes = portinfo["cpes"]
                portinfo["original_cpes"] = service_cpes
                portinfo["cpes"] = {}
                broad_cpes = set()
                for cpe in service_cpes:
                    # get cpe cves
                    if ONLINE_ONLY:
                        all_cves, broad_search = get_cves_to_cpe_via_vulners(cpe, NUM_CVES_PER_CPE_MAX)
                    else:
                        all_cves, broad_search = get_cves_to_cpe(cpe, NUM_CVES_PER_CPE_MAX)

                    if broad_search:
                        broad_cpes.add(cpe)
                    for cur_cpe, cves in all_cves.items():
                        if cur_cpe not in portinfo["cpes"]:
                            portinfo["cpes"][cur_cpe] = cves
                        else:
                            logger.warning("CPE '%s' already stored in host '%s'\'s information of port '%s'; " % (cur_cpe, ip, portid) +
                                "check whether program correctly replaced vaguer CPEs with more specific CPEs")

                if len(broad_cpes) == 1:
                    add_extra_info(portinfo, "cve_extrainfo", ("Original CPE was invalid, unofficial or too broad '%s'. " % next(iter(broad_cpes))) + \
                        "Determined more specific / correct CPEs and included their CVEs.")
                elif len(broad_cpes) > 1:
                    add_extra_info(portinfo, "cve_extrainfo", ("The following original CPEs were invalid, unofficial or too broad '%s'. " % ", ".join(broad_cpes)) + \
                        "Determined more specific CPEs and included their CVEs.")
            else:
                # TODO: implement / how about using https://github.com/cloudtracer/text2cpe ?
                logger.warning("%s port %s of host %s does not have a CPE. Therefore no CVE analysis can be done for this port." % (protocol.upper(), str(portid), ip))

    global logger, vulners_api, db_cursor, CREATED_FILES

    # setup logger
    logger = logging.getLogger(__name__)
    logger.info("Starting with CVE analysis")

    cve_results = {}
    hosts = HOSTS

    db_conn = None
    if ONLINE_ONLY:
        logger.info("Gathering information using the online CVE databases.")
        vulners_api = vulners.Vulners()
    else:
        try:
            check_database()
            db_creation_date = datetime.datetime.fromtimestamp(os.stat(DATABASE_FILE).st_ctime)
            logger.info("Gathering information using the local CVE database last updated on %s" % str(db_creation_date))
            db_conn = sqlite3.connect(DATABASE_FILE)
            db_cursor = db_conn.cursor()
        except Exception as e:
            print(str(e))

    logger.info("Starting with CVE discovery of all hosts")
    CREATED_FILES += [HOST_CVE_FILE, SUMMARY_FILE]
    for ip, host in hosts.items():
        if CONFIG["skip_os"].lower() == "true":
            logger.info("Skipping OS CVE analysis as stated in config file")
        else:
            process_os_cves()

        # get TCP and UDP cves
        process_port_cves("tcp")
        process_port_cves("udp")

    logger.info("Done")
    logger.info("Computing final CVSSv3 scores for all hosts")
    scores = calculate_final_scores(hosts)
    logger.info("Done")

    with open(HOST_CVE_FILE, "w") as f:
        f.write(json.dumps(hosts, ensure_ascii=False, indent=3))

    logger.info("Creating summary")
    create_cve_summary(hosts, scores)
    logger.info("Done")

    results.append(scores)

def create_cve_summary(hosts, scores):
    def process_port(protocol):
        nonlocal host, host_summary, total_cve_count
        if protocol in host:
            host_summary[protocol] = {}
            for portid, portinfo in host[protocol].items():
                host_summary[protocol][portid] = {}
                counted_cves = set()
                for k, v in portinfo.items():
                    if k != "cpes" and k != "original_cpes":
                        host_summary[protocol][portid][k] = v
                    elif k == "original_cpes":
                        host_summary[protocol][portid]["cpes"] = v
                    else:
                        cve_count = 0
                        for _, cves in v.items():
                            for cve_id in cves:
                                if cve_id not in counted_cves:
                                    cve_count += 1
                                    counted_cves.add(cve_id)
                        total_cve_count += cve_count
                        host_summary[protocol][portid]["cve_count"] = str(cve_count)

                    try:
                        host_summary[protocol][portid]["cvssv3_severity"] = get_text_assessment(float(host[protocol][portid].get("aggregated_cvssv3", "N/A")))
                    except ValueError:
                        pass

    def get_text_assessment(score):
        # Taken from https://nvd.nist.gov/vuln-metrics/cvss
        if score == 0:
            assessment = "None"
        elif score > 0 and score < 4:
            assessment = "Low"
        elif score >= 4 and score < 7:
            assessment = "Medium"
        elif score >= 7 and score < 9:
            assessment = "High"
        elif score >= 9 and score <= 10:
            assessment = "Critical"
        return assessment 

    summary = {}
    for ip, host in hosts.items():
        host_summary = {}
        total_cve_count = 0
        host_summary["os"] = {}
        if "os" in host and not CONFIG["skip_os"].lower() == "true":
            counted_cves = set()
            for k, v in host["os"].items():
                if k != "cpes" and k != "original_cpes":
                    host_summary["os"][k] = v
                elif k == "original_cpes":
                    host_summary["os"]["cpes"] = v
                else:
                    cve_count = 0
                    for _, cves in host["os"]["cpes"].items():
                        for cve_id in cves:
                            if cve_id not in counted_cves:
                                cve_count += 1
                                counted_cves.add(cve_id)
                    total_cve_count += cve_count
                    host_summary["os"]["cve_count"] = str(cve_count)

            try:
                host_summary["os"]["cvssv3_severity"] = get_text_assessment(float(host["os"].get("aggregated_cvssv3", "N/A")))
            except ValueError as e:
                pass

        if "ip" in host:
            host_summary["ip"] = host["ip"]
        if "mac" in host:
            host_summary["mac"] = host["mac"]

        process_port("tcp")
        process_port("udp")

        host_summary["total_cve_count"] = str(total_cve_count)
        host_summary["final_cvssv3"] = host["final_cvssv3"]
        try:
            host_summary["cvssv3_severity"] = get_text_assessment(float(host.get("final_cvssv3", "N/A")))
        except ValueError as e:
            pass

        summary[ip] = host_summary

    with open(SUMMARY_FILE, "w") as f:
        f.write(json.dumps(summary, ensure_ascii=False, indent=3))


def check_database():
    """
    Check the CVE database for validity. Validity means:
    1.) it exists; 2.) it is up-to-date with regard to
    the expire time stored in the used config file.
    """

    def get_creation_date(filepath):
        """
        Get the creation date of a file on a Unix based system.
        If creation date is not available, return last-modified date.
        Taken and adapted from https://stackoverflow.com/a/39501288 .
        """
        filestat = os.stat(filepath)
        try:
            return datetime.datetime.fromtimestamp(filestat.st_birthtime)
        except AttributeError:
            return datetime.datetime.fromtimestamp(filestat.st_mtime)

    def do_db_update(log_msg: str):
        """
        Conduct a database update after logging the given message.
        """
        global CREATED_FILES

        update_files = []
        logger.info(log_msg)
        update_module(update_files, logfile=LOGFILE)
        logger.info("Done.")
        os.makedirs("db_update", exist_ok=True)
        update_files_renamed = []
        for file in update_files:
            new_file = os.path.join("db_update", file)
            os.rename(os.path.abspath(file), new_file)
            update_files_renamed.append(new_file)
        CREATED_FILES += update_files_renamed

    if os.path.isfile(DATABASE_FILE):
        db_date = get_creation_date(DATABASE_FILE)
        db_age = datetime.datetime.now() - db_date
        try:
            db_age_limit = datetime.timedelta(minutes = int(CONFIG["DB_expire"]))
        except ValueError:
            logger.warning("DB_expire is invalid and cannot be processed. Skipping check whether database is up-to-date.")

        if db_age > db_age_limit:
            do_db_update("Database has expired. Conducting update.")
        else:
            logger.info("Database is up-to-date; expires in %s" % str(db_age_limit - db_age))
    else:
        do_db_update("Database does not exist. Installing.")


def calculate_final_scores(hosts: dict):
    def aggregate_scores_weighted_mean(scores: list):
        weights, weight_sum = {}, 0
        for i, score in enumerate(scores):
            try:
                score = float(score)
            except ValueError:
                continue
            if score == 10.0:
                score = 9.99  # prevent division by 0
            weight = (1 / (10 - score))**0.8
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
        end_score = -1
        for score in scores:
            try:
                score = float(score)
            except ValueError:
                continue
            if score > end_score:
                end_score = score

        if end_score < 0:
            end_score = "N/A"

        return end_score

    def add_to_score_lists(broad_aggr: bool, score):
        nonlocal score_list_aggr, score_list_max
        if type(score) != float:
            return
        if broad_aggr:
            score_list_aggr.append(score)
        else:
            score_list_max.append(score)

    def aggregate_entry(entry: dict):
        is_broad_entry = set(entry.get("cpes", {}).keys()) != set(entry.get("original_cpes", {}))
        if is_broad_entry:
            counted_cves = set()
            score_list = []
            for _, cves_entry in entry.get("cpes", {}).items():
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
            for _, cves_entry in entry.get("cpes", {}).items():
                cves_score_list = [cves_entry[cve_id]["cvssv3"] for cve_id in cves_entry]
                score_list += cves_score_list
            return False, aggregate_scores_max(score_list)

    def aggregate_protocol_entry(protocol: str):
        nonlocal host
        if protocol in host:
            for portid, portinfo in host[protocol].items():
                is_broad_entry, score = aggregate_entry(portinfo)
                portinfo["aggregated_cvssv3"] = score
                add_to_score_lists(is_broad_entry, portinfo["aggregated_cvssv3"])

    host_scores = {}
    for ip, host in hosts.items():
        score_list_aggr = []
        score_list_max = []

        # aggregate entries from OS and ports
        if "os" in host:
            broad_aggr, score = aggregate_entry(host["os"])
            host["os"]["aggregated_cvssv3"] = score
            add_to_score_lists(broad_aggr, host["os"]["aggregated_cvssv3"])
        aggregate_protocol_entry("tcp")
        aggregate_protocol_entry("udp")

        if max(score_list_aggr, default=-1) > max(score_list_max, default=-1):
            final_score = aggregate_scores_weighted_mean(score_list_aggr + score_list_max)
        else:
            final_score = aggregate_scores_max(score_list_aggr + score_list_max)
        # then aggregate OS and port entries
        host["final_cvssv3"] = final_score
        host_scores[ip] = host["final_cvssv3"]

    return host_scores

def parse_cpe_dict():
    global CPE_DICT_ET_CPE_ITEMS

    if not CPE_DICT_ET_CPE_ITEMS:
        # open file descriptor for CPE dict in case further lookup has to be done
        logger.info("Parsing CPE dictionary for further lookups")
        CPE_DICT_ET_CPE_ITEMS = list(ET.parse(CPE_DICT_FILEPATH).getroot())[1:]  # first child needs to be skipped, because it's generator
        logger.info("Done")


def get_all_related_cpes(cpe: str):
    global CPE_DICT_ET_CPE_ITEMS

    parse_cpe_dict()

    related_cpes = []
    for cpe_item in CPE_DICT_ET_CPE_ITEMS:
        cur_cpe = cpe_item.attrib.get("name", "")
        if cur_cpe.startswith(cpe) and not cur_cpe == cpe:
            related_cpes.append(cur_cpe)
    return related_cpes


def get_more_specific_cpe_cves(cpe: str, cve_gathering_function, max_vulnerabilities):
        logger.info("Trying to find more specific CPEs and look for CVEs again")
        related_cpes = get_all_related_cpes(cpe)
        logger.info("Done")
        cve_results = {}
        if related_cpes:
            num_cves_per_cpe = (max_vulnerabilities // len(related_cpes)) + 1
            logger.info("Found the following more specific CPEs: %s" % ",".join(related_cpes[:MAX_LOG_CPES]))
            for cpe in related_cpes:
                cves, _ = cve_gathering_function(cpe, num_cves_per_cpe)
                for cur_cpe, cves in cves.items():
                    cve_results[cur_cpe] = cves
        else:
            logger.info("Could not find any more specific CPEs")

        if not cve_results:
            cve_results = {cpe: {}}

        return cve_results


def add_extra_info(dict_: dict, info_key: str, text: str):
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


def get_cves_to_cpe(cpe: str, max_vulnerabilities = 500):
    def is_broad_version():
        nonlocal general_cpe, cpe_version

        parse_cpe_dict()

        return not any((general_cpe + ":" + cpe_version) == cpe_item.attrib["name"] or
            (general_cpe + ":" + cpe_version + ":") in cpe_item.attrib["name"]
            for cpe_item in CPE_DICT_ET_CPE_ITEMS)

    cve_results = {}
    values = cpe[7:].split(":")
    general_cpe = cpe[:7] + ":".join(values[:2])

    # if len(values) > 3:
    #     cpe = cpe[:7] + ":".join(values[:3])  # nvd.nist seems to do this with e.g. cpe:/o:microsoft:windows_10:1607::~~~~x64~
    found_cves = {}
    found_cves_specific = db_cursor.execute("SELECT DISTINCT cve_id, with_cpes FROM cve_cpe WHERE cpe=\"%s\"" % cpe).fetchall()
    if found_cves_specific:
        found_cves[cpe] = {}
        for cve_id, with_cpes in found_cves_specific:
            found_cves[cpe][cve_id] = with_cpes 

    if len(values) == 2:
        cpe_version = None
    elif len(values) > 2:
        cpe_version = values[2]

    general_cve_cpe_data = db_cursor.execute("SELECT cve_id, cpe_version_start, cpe_version_start_type, cpe_version_end," +
                                        "cpe_version_end_type, with_cpes FROM cve_cpe WHERE cpe=\"%s\"" % general_cpe).fetchall()
    general_cve_cpe_data += db_cursor.execute("SELECT cve_id, cpe_version_start, cpe_version_start_type, cpe_version_end," +
                                        "cpe_version_end_type, with_cpes FROM cve_cpe WHERE cpe LIKE \"%s\"" % (general_cpe + "::%%")).fetchall()

    broad_search = cpe_version is None or is_broad_version() or cpe_version == "-"  # '-' stands for all versions
    if broad_search:
        if cpe_version:
            cur_cpe = general_cpe + ":" + cpe_version
        else:
            cur_cpe = cpe

        specific_cves = []
        while len(cur_cpe) > 0:
            specific_cves = db_cursor.execute("SELECT cve_id, cpe, with_cpes FROM cve_cpe WHERE cpe LIKE \"%s%%\"" % cur_cpe).fetchall()
            if specific_cves:
                break
            cur_cpe = cur_cpe[:-1]

        for cve_id, cpe_iter, with_cpes in specific_cves:
            # values = cpe_iter[7:].split(":")
            # if len(values) > 3:
            #     cpe_iter = cpe_iter[:7] + ":".join(values[:3])  # nvd.nist seems to do this with e.g. cpe:/o:microsoft:windows_10:1607::~~~~x64~
            if cpe_iter not in found_cves:
                found_cves[cpe_iter] = {}
            found_cves[cpe_iter][cve_id] = with_cpes

    if cpe_version:
        for cpe_iter in found_cves:
            cpe_iter_version = "".join(cpe_iter[7:].split(":")[2:])
            cpe_iter_version = version.parse(cpe_iter_version)
            cpe_fields = cpe_iter

            for entry in general_cve_cpe_data:
                version_start, version_start_type = entry[1], entry[2]
                version_end, version_end_type = entry[3], entry[4]
                with_cpes = entry[5]

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

                if cpe_in:
                    found_cves[cpe_iter][entry[0]] = with_cpes

    # retrieve detailed CVE information
    cve_details = {}
    for cpe_iter, cve_dict in found_cves.items():
        cve_ids = set(cve_dict)
        cve_detail_entry = {}
        for cve_id in cve_ids:
            if cve_id in cve_details:
                continue

            descr, publ, last_mod, cvss_ver, score, vector = db_cursor.execute("SELECT description, published, last_modified, " +
                "cvss_version, base_score, vector FROM cve WHERE cve_id = \"%s\"" % (cve_id)).fetchone()
            cve_details[cve_id] = {"id": cve_id, "description": descr, "published": publ, "modified": last_mod,
                                    "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id}

            if int(float(cvss_ver)) == 2:
                cve_details[cve_id]["cvssv2"] = score
                cve_details[cve_id]["vector_short"] = vector
                transform_cvssv2_to_cvssv3(cve_details[cve_id])
                add_extra_info(cve_details[cve_id], "extrainfo", "Specified CVSSv3 score was converted from CVSSv2 score because there was no CVSSv3 score available.")
            elif int(float(cvss_ver)) == 3:
                cve_details[cve_id]["cvssv3"] = score
                cve_details[cve_id]["vector_short"] = vector
            else:
                cve_details[cve_id]["cvssv3"] = -1  # replace with N/A later, but needed for sorting here
                cve_details[cve_id]["vector_short"] = "N/A"
                add_extra_info(cve_details[cve_id], "extrainfo", "No CVSS score available in the NVD.")

    for cpe_iter, cve_dict in found_cves.items():
        cve_ids = sorted(set(cve_dict), key=lambda cve_id: cve_details[cve_id]["cvssv3"], reverse=True)
        found_cves_dict = {}
        for cve_id in cve_ids:
            cve_entry = copy.deepcopy(cve_details[cve_id])
            if cve_entry["vector_short"] ==  "N/A":
                cve_entry["cvssv3"] = score

            with_cpes_list = cve_dict[cve_id]
            if len(with_cpes_list) == 1:
                add_extra_info(cve_entry, "extrainfo", "Note - only vulnerable in conjunction with '%s'" % ", ".join(with_cpes_list))
            elif len(with_cpes_list) > 1:
                add_extra_info(cve_entry, "extrainfo", "Note - only vulnerable in conjunction with either one of {%s}" % ", ".join(with_cpes_list))
            found_cves_dict[cve_id] = cve_entry

        cve_results[cpe_iter] = found_cves_dict

    if not cve_results:
        cve_results = {cpe: {}}

    return cve_results, broad_search


def add_detailed_vector(cve: dict):
    vector_short = cve["vector_short"]
    if vector_short == "N/A":  # no CVSS score available
        return

    if vector_short.startswith("CVSS:3.0/"):
        vector_short = vector_short[len("CVSS:3.0/"):]

    vector_detail = {}
    fields = vector_short.split("/")
    for field in fields:
        k, v = field.split(":")
        vector_detail[CVSSV3_CAT_NAMES[k]] = CVSSV3_VAL_NAMES[k][v]

    cve["vector_detail"] = vector_detail


def get_cves_to_cpe_via_vulners(cpe: str, max_vulnerabilities = 500):
    def slim_cve_results(cve_results: list):
        slimmed_results = []
        for cve_result in cve_results:
            slimmed_result = {}
            for attr in {"description", "id", "published", "modified"}:
                slimmed_result[attr] = cve_result.get(attr, "")
            slimmed_result["published"] = slimmed_result["published"].replace("T", " ")
            slimmed_result["modified"] = slimmed_result["modified"].replace("T", " ")
            slimmed_result["href"] = "https://nvd.nist.gov/vuln/detail/%s" % slimmed_result["id"]
            slimmed_results.append(slimmed_result)
        return slimmed_results

    def process_cve_results(results: dict, max_vulns: int):
        results = results.get("NVD", {})
        results = results[:max_vulnerabilities]
        if results:
            results = slim_cve_results(results)
            for result in results:
                cve_id = result["id"]
                add_additional_cve_info(result)
        return results

    with warnings.catch_warnings():  # ignore warnings that vulners might throw
        warnings.filterwarnings('error')
        cve_results = {}
        try:
            cve_results = vulners_api.cpeVulnerabilities(cpe, maxVulnerabilities=VULNERS_MAX_VULNS)
        except ValueError as e:
            logger.warning("Getting CVEs for CPE '%s' resulted in the following ValueError: %s" % (cpe, e))
            if str(e) == "Malformed CPE string. Please, refer to the https://cpe.mitre.org/specification/. Awaiting like 'cpe:/a:cybozu:garoon:4.2.1'":
                return get_more_specific_cpe_cves(cpe, get_cves_to_cpe_via_vulners, max_vulnerabilities), True
        except AttributeError as e:
            logger.warning("Getting CVEs for CPE '%s' resulted in the following AttributeError: %s . Can be caused by Vulners not handling Burpsuite's 'internal server error'" % (cpe, e))
        except Warning as w:
            if str(w) == "Nothing found for Burpsuite search request":
                logger.info("Getting CVEs for CPE '%s' resulted in no CVEs" % cpe)
                return get_more_specific_cpe_cves(cpe, get_cves_to_cpe_via_vulners, max_vulnerabilities), True
            elif str(w) == "Software name or version is not provided":
                logger.info("Finding CVEs for CPE '%s' resulted in missing CPE software name or version" % cpe)
                return get_more_specific_cpe_cves(cpe, get_cves_to_cpe_via_vulners, max_vulnerabilities), True

    if cve_results:
        cves = process_cve_results(cve_results, max_vulnerabilities)
        cves_dict = {}
        for cve in cves:
            cves_dict[cve["id"]] = cve
        cve_results = {cpe: cves_dict}
    else:
        cve_results = {cpe: {}}

    return cve_results, False


def add_additional_cve_info(cve: dict):
    # TODO: check if HTTP Response is OK before using retrieved HTML

    # get the CVE's html text on nvd.nist.org
    nvd_cve_html = requests.get(cve["href"]).text
    soup = BeautifulSoup(nvd_cve_html, 'html.parser')

    # retrieve the CVSSv3 score
    cvssv3_score_tag = soup.find("span", {"data-testid" : "vuln-cvssv3-base-score"})
    if cvssv3_score_tag:
        cve["cvssv3"] = cvssv3_score_tag.text.strip()
    else:
        cvssv2_score_tag = soup.find("span", {"data-testid" : "vuln-cvssv2-base-score"})
        if cvssv2_score_tag:
            cve["cvssv2"] = cvssv2_score_tag.text.strip()

    # retrieve the short form of the attack vector
    if "cvssv3" in cve:
        vector_short_tag = soup.find("span", {"data-testid" : "vuln-cvssv3-vector"})
    elif "cvssv2" in cve:
        vector_short_tag = soup.find("span", {"data-testid" : "vuln-cvssv2-vector"})
    else:
        vector_short_tag = None

    if vector_short_tag:
        vector_short = vector_short_tag.text.strip().split(" ")[0].strip()  # split at space to ignore the (V3 legend) at the end
        if "cvssv3" in cve and not vector_short.startswith("CVSS:3.0/"):
            vector_short = "CVSS:3.0/" + vector_short

        cve["vector_short"] = vector_short

    # retrieve the full text version of the attack vector
    cve["vector_detail"] = {}
    if "cvssv3" in cve:
        vector_detail_container = soup.find("p", {"data-testid" : "vuln-cvssv3-metrics-container"})
    elif "cvssv2" in cve:
        vector_detail_container = soup.find("p", {"data-testid" : "vuln-cvssv2-metrics-container"})
    else:
        vector_detail_container = None

    if vector_detail_container:
        strong_tags = vector_detail_container.findAll("strong")
        span_tags = vector_detail_container.findAll("span")
        for i, strong_tag in enumerate(strong_tags):
            span_tag = span_tags[i]
            for br in span_tag.find_all("br"):
                br.replace_with("")
            attr = strong_tag.text.strip()[:-1]  # ignore last text character (a colon)
            value = span_tag.text.strip()
            cve["vector_detail"][attr] = value  # replace possible HTML <br> tags with newline character

    if "cvssv2" in cve:
        transform_cvssv2_to_cvssv3(cve)
        add_detailed_vector(cve)
        cve["extrainfo"] = "Specified CVSSv3 score was converted from CVSSv2 score because there was no CVSSv3 score available."

def transform_cvssv2_to_cvssv3(cve: dict):
    # Conversion incentives are takten from: https://security.stackexchange.com/questions/127335/how-to-convert-risk-scores-cvssv1-cvssv2-cvssv3-owasp-risk-severity
    # If the conversion incentive is indecisive, the more likely conversion was taken
    converted_cvssv3_vector = ""
    vector_fields = cve["vector_short"][1:-1].split("/")  # remove left and right parenthesis
    for vector_field in vector_fields:
        key, val = vector_field.split(":")
        # key == "AV": just copy values
        if key == "AC":
            if val == "M":
                val = "L"
        elif key == "Au":
            if val == "S":
                val = "L"
            elif val == "M":
                val = "H"
            key = "PR"
        elif key == "C" or key == "I" or key == "A":
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

    converted_cvssv3_vector += "S:U/"

    if "AC:H" in cve["vector_short"] or "AC:M" in cve["vector_short"]:
        converted_cvssv3_vector += "UI:R/"
    else:
        converted_cvssv3_vector += "UI:N/"

    converted_cvssv3_vector = converted_cvssv3_vector[:-1]  # remove trailing /

    if "vector_detail" in cve:
        del cve["vector_detail"]
    cve["orig_cvssv2"] = cve["cvssv2"]
    del cve["cvssv2"]
    cve["orig_cvssv2_vector"] = cve["vector_short"]
    del cve["vector_short"]
    cve["vector_short"] = ("CVSS:3.0/%s" % converted_cvssv3_vector).replace("(", "")
    vector_v3 = "CVSS:3.0/" + converted_cvssv3_vector
    cvssv3 = str(calculate_vector(vector_v3, cvss3)[0])  # get base score of cvssv3 score vector
    cve["cvssv3"] = cvssv3

if __name__ == "__main__":
    if len(sys.argv) > 2:
        import logging
        logger = logging.getLogger(__name__)
        db_conn = sqlite3.connect(DATABASE_FILE)
        db_cursor = db_conn.cursor()
        cves = get_cves_to_cpe(sys.argv[1])[0]

        result = {"Count": 0}
        for k, v in cves.items():
            result["Count"] += len(v)
            result[k] = v
        with open(sys.argv[2], "w") as f:
            f.write(json.dumps(result, ensure_ascii=False, indent=3))
    else:
        print("Error: wrong number of arguments.")
        print("usage: ./analyzer_cve_correlation.py [cpe] [outfile]")
