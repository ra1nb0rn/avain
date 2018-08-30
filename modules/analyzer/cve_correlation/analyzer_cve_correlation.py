#!/usr/bin/env python3

from bs4 import BeautifulSoup
import copy
from cvsslib import cvss3, calculate_vector
import datetime
import json
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
    from . import module_updater
    from ... import utility as util

HOST_CVE_FILE = "found_cves.json"
DATABASE_FILE = "cve_db.db3"
SUMMARY_FILE = "cve_summary.json"

HOSTS = {}  # a string representing the network to analyze
ONLINE_ONLY = False
VERBOSE = False  # specifying whether to provide verbose output or not
LOGFILE = ""
CONFIG = {}

CPE_DICT_FILEPATH = "..{0}..{0}..{0}resources{0}official-cpe-dictionary_v2.2.xml".format(os.sep)
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
                host["os"]["cve_extrainfo"] = ("Could not find any CVEs for original CPE '%s'. " % next(iter(broad_cpes))) + \
                    "Determined more specific CPEs and included some of their CVEs."
            elif len(broad_cpes) > 1:
                host["os"]["cve_extrainfo"] = ("Could not find any CVEs for original CPEs '%s'. " % ", ".join(broad_cpes)) + \
                    "Determined more specific CPEs and included some of their CVEs."
        else:
            # TODO: implement
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
                    portinfo["cve_extrainfo"] = ("Could not find any CVEs for original CPE '%s'. " % next(iter(broad_cpes))) + \
                        "Determined more specific CPEs and included some of their CVEs."
                elif len(broad_cpes) > 1:
                    portinfo["cve_extrainfo"] = ("Could not find any CVEs for original CPEs '%s'. " % ", ".join(broad_cpes)) + \
                        "Determined more specific CPEs and included some of their CVEs."
            else:
                # TODO: implement
                logger.warning("%s port %s of host %s does not have a CPE. Therefore no CVE analysis can be done for this port." % (protocol.upper(), str(portid), ip))

    global logger, vulners_api, db_cursor, created_files

    # setup logger
    logger = util.get_logger(__name__, LOGFILE)
    logger.info("Starting with CVE analysis")

    cve_results = {}
    created_files = []
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

    created_files += [HOST_CVE_FILE, SUMMARY_FILE]
    results.append((scores, created_files))

def create_cve_summary(hosts, scores):
    def process_port(protocol):
        nonlocal host, host_summary, total_cve_count
        if protocol in host:
            host_summary[protocol] = {}
            for portid, portinfo in host[protocol].items():
                host_summary[protocol][portid] = {}
                for k, v in portinfo.items():
                    if k != "cpes" and k != "original_cpes":
                        host_summary[protocol][portid][k] = v
                    elif k == "original_cpes":
                        host_summary[protocol][portid]["cpes"] = v
                    else:
                        cve_count = 0
                        for _, cves in v.items():
                            cve_count += len(cves.keys())
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
            for k, v in host["os"].items():
                if k != "cpes" and k != "original_cpes":
                    host_summary["os"][k] = v
                elif k == "original_cpes":
                    host_summary["os"]["cpes"] = v
                else:
                    cve_count = 0
                    for _, cves in host["os"]["cpes"].items():
                        cve_count += len(cves.keys())
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
        global created_files

        update_files = []
        logger.info(log_msg)
        module_updater.update_module(update_files)
        logger.info("Done.")
        os.makedirs("db_update", exist_ok=True)
        update_files_renamed = []
        for file in update_files:
            new_file = os.path.join("db_update", file)
            os.rename(os.path.abspath(file), new_file)
            update_files_renamed.append(new_file)
        created_files += update_files_renamed

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
        do_db_update("Database has expired. Conducting update.")


def calculate_final_scores(hosts: dict):
    def calculate_weight(score: float, item_count: int):
        return (1/item_count) * score**2 * (score/10)

    def get_end_score(weight_sum: float, unnormalized_score_sum: float):
        if weight_sum:  # check if weight_sum is not zero
            end_score = unnormalized_score_sum/weight_sum
            end_score = max(0, end_score)  # ensure score is greater than 0
            end_score = min(10, end_score)  # ensure score is less than 10
            end_score = str(end_score)  # turn into str (to have an alternative if no score exists, i.e. N/A)
        else:
            end_score = "N/A"
        return end_score

    def process_port_cve_scores(protocol):
        nonlocal aggregate_score_count

        for _, portinfo in host[protocol].items():
            if "cpes" in portinfo:
                service_cpes = portinfo["cpes"]
                service_weight_sum, service_score_sum, service_cve_count = 0, 0, 0

                for cpe in service_cpes: 
                    service_cve_count += len(portinfo["cpes"][cpe].keys())

                for cpe in service_cpes:
                    for _, cve in portinfo["cpes"][cpe].items():
                        cvssv3_score = float(cve["cvssv3"])
                        service_weight = calculate_weight(cvssv3_score, service_cve_count)
                        service_weight_sum += service_weight
                        service_score_sum += service_weight * cvssv3_score

                end_score = get_end_score(service_weight_sum, service_score_sum)
                portinfo["aggregated_cvssv3"] = end_score

                aggregate_score_count += 1

            else:
                # TODO: implement
                pass

    def process_port_aggregate_score(protocol):
        nonlocal weight_sum, score_sum
        for _, portinfo in host[protocol].items():
            if "aggregated_cvssv3" in portinfo:
                try:
                    cvssv3 = float(portinfo["aggregated_cvssv3"])
                    weight = calculate_weight(cvssv3, aggregate_score_count)
                    weight_sum += weight
                    score_sum += weight * cvssv3
                except:
                    pass
            else:
                # TODO: implement
                pass

    aggregate_score_count = 0
    # calculate intermediate scores
    for ip, host in hosts.items():
        # get OS CVEs
        if "cpes" in host["os"] and not CONFIG["skip_os"].lower() == "true":
            os_cpes = host["os"]["cpes"]
            os_weight_sum, os_score_sum, os_cve_count = 0, 0, 0

            for cpe in os_cpes: 
                os_cve_count += len(os_cpes[cpe].keys())

            for cpe in os_cpes:
                for _, cve in os_cpes[cpe].items():
                    cvssv3_score = float(cve["cvssv3"])
                    os_weight = calculate_weight(cvssv3_score, os_cve_count)
                    os_weight_sum += os_weight
                    os_score_sum += os_weight * cvssv3_score
            aggregate_score_count += 1

            end_score = get_end_score(os_weight_sum, os_score_sum)
            host["os"]["aggregated_cvssv3"] = end_score

        else:
            # TODO: implement
            pass

        # get TCP and UDP cvssv3 score
        process_port_cve_scores("tcp")
        process_port_cve_scores("udp")

    host_scores = {}
    for ip, host in hosts.items():
        weight_sum, score_sum = 0, 0
        if "aggregated_cvssv3" in host["os"]:
            try:
                cvssv3 = float(host["os"]["aggregated_cvssv3"])
                weight = calculate_weight(cvssv3, aggregate_score_count)
                weight_sum += weight
                score_sum += weight * cvssv3
            except:
                pass

        process_port_aggregate_score("tcp")
        process_port_aggregate_score("udp")
        end_score = get_end_score(weight_sum, score_sum)
        host["final_cvssv3"] = end_score
        host_scores[ip] = end_score

    return host_scores

def get_all_related_cpes(cpe: str):
    global CPE_DICT_ET_CPE_ITEMS

    if not CPE_DICT_ET_CPE_ITEMS:
        # open file descriptor for CPE dict in case further lookup has to be done
        logger.info("Parsing CPE dictionary for further lookups")
        CPE_DICT_ET_CPE_ITEMS = ET.parse(CPE_DICT_FILEPATH).getroot().getchildren()[1:]  # first child needs to be skipped, because it's generator
        logger.info("Done")

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

def get_cves_to_cpe(cpe: str, max_vulnerabilities = 500):
    def is_broad_version():
        count_direct = db_cursor.execute("SELECT COUNT(cve_id) FROM cve_cpe WHERE cpe LIKE \"{0}:%%\" OR cpe = \"{0}\"".format(general_cpe + ":" + cpe_version)).fetchone()[0]
        count_indirect = db_cursor.execute("SELECT COUNT(cve_id) FROM cve_cpe WHERE cpe LIKE \"%s%%\"" % (general_cpe + ":" + cpe_version)).fetchone()[0]

        if count_direct == 0 and count_indirect > 0:
            return True
        return False

    cve_results = {}
    values = cpe[7:].split(":")
    general_cpe = cpe[:7] + ":".join(values[:2])

    # if len(values) > 3:
    #     cpe = cpe[:7] + ":".join(values[:3])  # nvd.nist seems to do this with e.g. cpe:/o:microsoft:windows_10:1607::~~~~x64~
    found_cves = db_cursor.execute("SELECT DISTINCT cve_id, with_cpes FROM cve_cpe WHERE cpe=\"%s\"" % (cpe)).fetchall()

    if len(values) == 2:
        cpe_version = None
    elif len(values) > 2:
        cpe_version = values[2]
    general_cve_cpe_data = db_cursor.execute("SELECT cve_id, cpe_version_start, cpe_version_start_type, cpe_version_end," +
                                        "cpe_version_end_type, with_cpes FROM cve_cpe WHERE cpe=\"%s\"" % (general_cpe)).fetchall()

    if cpe_version and len(found_cves) > 0:
        broad_search = False
        if cpe_version == "-":  # '-' stands for all versions
            all_version_cves = db_cursor.execute("SELECT cve_id, with_cpes FROM cve_cpe WHERE cpe LIKE \"%s:%%\"" % (general_cpe)).fetchall()
            found_cves += all_version_cves
        else:
            broad_search = is_broad_version()

            cpe_version = version.parse(cpe_version)

            for entry in general_cve_cpe_data:
                version_start, version_start_type = entry[1], entry[2]
                version_end, version_end_type = entry[3], entry[4]
                with_cpes = entry[5]

                cpe_in = False
                if version_start and version_end:
                    if version_start_type == "Including" and version_end_type == "Including":
                        cpe_in = version.parse(version_start) <= cpe_version <= version.parse(version_end)
                    elif version_start_type == "Including" and version_end_type == "Excluding":
                        cpe_in = version.parse(version_start) <= cpe_version < version.parse(version_end)
                    elif version_start_type == "Excluding" and version_end_type == "Including":
                        cpe_in = version.parse(version_start) < cpe_version <= version.parse(version_end)
                    else:
                        cpe_in = version.parse(version_start) < cpe_version < version.parse(version_end)
                elif version_start:
                    if version_start_type == "Including":
                        cpe_in = version.parse(version_start) <= cpe_version
                    elif version_start_type == "Excluding":
                        cpe_in = version.parse(version_start) < cpe_version
                elif version_end:
                    if version_end_type == "Including":
                        cpe_in = cpe_version <= version.parse(version_end)
                    elif version_end_type == "Excluding":
                        cpe_in = cpe_version < version.parse(version_end)

                if cpe_in:
                    found_cves.append((entry[0], with_cpes))

        found_cves = sorted(set(found_cves), key=lambda cve: cve[0], reverse=True)
        found_cves_dict = {}
        for cve_id, with_cpes in found_cves:
            descr, publ, last_mod, cvss_ver, score, vector = db_cursor.execute("SELECT description, published, last_modified, " +
                "cvss_version, base_score, vector FROM cve WHERE cve_id = \"%s\"" % (cve_id)).fetchone()
            found_cves_dict[cve_id] = {"id": cve_id, "description": descr, "published": publ, "modified": last_mod,
                                        "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id}

            if int(float(cvss_ver)) == 2:
                found_cves_dict[cve_id]["cvssv2"] = score
                found_cves_dict[cve_id]["vector_short"] = vector
                transform_cvssv2_to_cvssv3(found_cves_dict[cve_id])
                found_cves_dict[cve_id]["extrainfo"] = "Specified CVSSv3 score was converted from CVSSv2 score because there was no CVSSv3 score available."
            else:
                found_cves_dict[cve_id]["cvssv3"] = score
                found_cves_dict[cve_id]["vector_short"] = vector

            add_detailed_vector(found_cves_dict[cve_id])

            if with_cpes != "":
                field = "extrainfo"
                if field in found_cves_dict[cve_id]:
                    for i in range(1, 10):
                        field = "extrainfo%d" % i
                        if not field in found_cves_dict[cve_id]:
                             break

                with_cpes_list = with_cpes.split(",")
                if len(with_cpes_list) == 1:
                    found_cves_dict[cve_id][field] = "Note - only vulnerable in conjunction with '%s'" % ", ".join(with_cpes_list)
                else:
                    found_cves_dict[cve_id][field] = "Note - only vulnerable in conjunction with either one of {%s}" % ", ".join(with_cpes_list)

        cve_results[cpe] = found_cves_dict
    else:
        if cpe_version:
            logger.info("Finding CVEs for CPE '%s' resulted in too broad CPE version" % cpe)
            cpe_to_search = cpe
        else:
            logger.info("Finding CVEs for CPE '%s' resulted in missing CPE version" % cpe)
            cpe_to_search = general_cpe

        broad_search = True
        more_specifc_cves = get_more_specific_cpe_cves(cpe_to_search, get_cves_to_cpe, max_vulnerabilities)
        logger.info("Retrieved CVEs for all more specific CPEs to '%s'" % cpe_to_search)
        for cpe, cves in more_specifc_cves.items():
            cve_results[cpe] = cves

    if not cve_results:
        cve_results = {cpe: {}}

    return cve_results, broad_search


def add_detailed_vector(cve: dict):
    vector_short = cve["vector_short"]
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
