from bs4 import BeautifulSoup
import copy
from cvsslib import cvss3, calculate_vector
import json
import os
import requests
import subprocess
import sys
import vulners
import warnings
import xml.etree.ElementTree as ET

from ... import utility as util

HOST_CVE_FILE = "found_cves.json"

HOSTS = {}  # a string representing the network to analyze
VERBOSE = False  # specifying whether to provide verbose output or not
LOGFILE = ""

CPE_DICT_FILEPATH = ".." + os.sep + ".." + os.sep + ".." + os.sep + "official-cpe-dictionary_v2.2.xml"
CVE_AMOUNT = 0
CPE_DICT_ET_CPE_ITEMS = None
NUM_CVES_PER_CPE_MAX = 25
VULNERS_MAX_VULNS = 1000

logger = None

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for CVEs belonging regarding its software.

    Returns a tuple contaiging the analyis results/scores and a list of created files by writing it into the result list.
    """
    
    def process_port_cves(protocol):
        global CVE_AMOUNT
        nonlocal hosts

        for portid, portinfo in host[protocol].items():
            if "cpes" in portinfo:
                service_cpes = portinfo["cpes"]
                portinfo["cpes"] = {}
                for cpe in service_cpes:
                    # get cpe cves
                    all_cves = get_cves_to_cpe(vulners_api, cpe, NUM_CVES_PER_CPE_MAX)
                    for cur_cpe, cves in all_cves.items():
                        if cur_cpe not in portinfo["cpes"]:
                            portinfo["cpes"][cur_cpe] = cves
                            CVE_AMOUNT += len(cves)
                        else:
                            logger.warning("CPE '%s' already stored in host '%s'\'s information of port '%s'; " % (cur_cpe, host["ip"]["addr"], portid) +
                                "check whether program correctly replaced vaguer CPEs with more specific CPEs")
            else:
                # TODO: implement
                pass

    global CVE_AMOUNT, logger, CPE_DICT_ET_CPE_ITEMS

    # setup logger
    logger = util.get_logger(__name__, LOGFILE)
    logger.info("Starting with CVE analysis")

    # open file descriptor for CPE dict in case further lookup has to be done
    logger.info("Parsing CPE dictionary in case of further lookups")
    CPE_DICT_ET_CPE_ITEMS = ET.parse(CPE_DICT_FILEPATH).getroot().getchildren()[1:]  # first child needs to be skipped, because it's generator
    logger.info("Done")

    cve_results = {}
    vulners_api = vulners.Vulners()
    hosts = copy.deepcopy(HOSTS)

    logger.info("Starting with CVE discovery of all hosts")
    for ip, host in hosts.items():
        # get OS CVEs
        if "cpes" in host["os"]:
            os_cpes = host["os"]["cpes"]
            host["os"]["cpes"] = {}
            for cpe in os_cpes:
                # get cpe cves
                all_cves = get_cves_to_cpe(vulners_api, cpe, NUM_CVES_PER_CPE_MAX)
                for cur_cpe, cves in all_cves.items():
                    if cur_cpe not in host["os"]["cpes"]:
                        host["os"]["cpes"][cur_cpe] = cves
                        CVE_AMOUNT += len(cves)
                    else:
                        logger.warning("CPE '%s' already stored in host '%s'\'s OS information; " % (cur_cpe, ip) +
                            "check whether program correctly replaced vaguer CPEs with more specific CPEs")
        else:
            # TODO: implement
            pass

        # get TCP and UDP cves
        process_port_cves("tcp")
        process_port_cves("udp")

    with open(HOST_CVE_FILE, "w") as f:
        f.write(json.dumps(hosts, ensure_ascii=False, indent=3))

    logger.info("Done")
    logger.info("Computing final CVSSv3 scores for all hosts")
    scores = calculate_final_scores(hosts)
    logger.info("Done")
    created_files = [HOST_CVE_FILE]
    results.append((scores, created_files))


def calculate_final_scores(hosts: dict):
    def process_port_cve_scores(protocol):
        global CVE_AMOUNT
        nonlocal unnormalized_score_sum, weight_sum
        
        for _, portinfo in host[protocol].items():
            if "cpes" in portinfo:
                service_cpes = portinfo["cpes"]
                for cpe in service_cpes:
                    for _, cve in portinfo["cpes"][cpe].items():
                        cvssv3_score = float(cve["cvssv3"])
                        weight = (1/CVE_AMOUNT) * cvssv3_score**2 * (cvssv3_score/10)
                        weight_sum += weight
                        unnormalized_score_sum += weight * cvssv3_score
            else:
                # TODO: implement
                pass

    host_scores = {}
    for ip, host in hosts.items():
        unnormalized_score_sum = 0
        weight_sum = 0

        # get OS CVEs
        if "cpes" in host["os"]:
            os_cpes = host["os"]["cpes"]
            for cpe in os_cpes:
                for _, cve in os_cpes[cpe].items():
                    cvssv3_score = float(cve["cvssv3"])
                    weight = (1/CVE_AMOUNT) * cvssv3_score * (cvssv3_score/10)
                    weight_sum += weight
                    unnormalized_score_sum += weight * cvssv3_score
        else:
            # TODO: implement
            pass

        # get TCP and UDP cvssv3 score
        process_port_cve_scores("tcp")
        process_port_cve_scores("udp")

        if weight_sum:  # check if weight_sum is not zero
            end_score = unnormalized_score_sum/weight_sum
            end_score = max(0, end_score)  # ensure score is greater than 0
            end_score = min(10, end_score)  # ensure score is less than 10
            end_score = str(end_score)  # turn into str (to have an alternative if no score exists, i.e. N/A)
        else:
            end_score = "N/A"

        host_scores[ip] = end_score

    return host_scores


def slim_cve_results(cve_results: list):
    slimmed_results = []
    for cve_result in cve_results:
        slimmed_result = {}
        for attr in {"description", "id"}:
            slimmed_result[attr] = cve_result.get(attr, "")
        # slimmed_result["href"] = cve_results.get("href", "")  # TODO: use vulners or harcoded link?
        slimmed_result["href"] = "https://nvd.nist.gov/vuln/detail/%s" % slimmed_result["id"]
        slimmed_results.append(slimmed_result)
    return slimmed_results

def get_all_related_cpes(cpe: str):
    related_cpes = []
    for cpe_item in CPE_DICT_ET_CPE_ITEMS:
        cur_cpe = cpe_item.attrib.get("name", "")
        if cur_cpe.startswith(cpe) and not cur_cpe == cpe:
            related_cpes.append(cur_cpe)
    return related_cpes

def get_cves_to_cpe(vulners_api, cpe: str, max_vulnerabilities = 500):
    def process_cve_results(results: dict, max_vulns: int):
        results = results.get("NVD", {})
        results = results[:max_vulnerabilities]
        if results:
            results = slim_cve_results(results)
            for result in results:
                cve_id = result["id"]
                add_additional_cve_info(result)
        return results

    def get_more_specific_cpe_cves(cpe):
        logger.info("Trying to find more specific CPEs and look for CVEs again")
        related_cpes = get_all_related_cpes(cpe)
        logger.info("Done")
        cve_results = {}
        if related_cpes:
            num_cves_per_cpe = (max_vulnerabilities // len(related_cpes)) + 1
            logger.info("Found the following more specific CPEs: %s" % ",".join(related_cpes))
            for cpe in related_cpes:
                cves = get_cves_to_cpe(vulners_api, cpe, num_cves_per_cpe)
                for cur_cpe, cves in cves.items():
                    cve_results[cur_cpe] = cves
        else:
            logger.info("Could not find any more specific CPEs")
        return cve_results

    with warnings.catch_warnings():  # ignore warnings that vulners might throw
        warnings.filterwarnings('error')
        cve_results = {}
        try:
            cve_results = vulners_api.cpeVulnerabilities(cpe, maxVulnerabilities=VULNERS_MAX_VULNS)
        except ValueError as e:
            logger.warning("Getting CVEs for CPE '%s' resulted in the following ValueError: %s." % (cpe, e))
        except Warning as w:
            if str(w) == "Nothing found for Burpsuite search request":
                logger.info("Getting CVEs for CPE '%s' resulted in no CVEs" % cpe)
                return get_more_specific_cpe_cves(cpe)
            elif str(w) == "Software name or version is not provided":
                logger.info("Getting CPE '%s' is missing sotware name or version" % cpe)
                return get_more_specific_cpe_cves(cpe)

    if cve_results:
        cves = process_cve_results(cve_results, max_vulnerabilities)
        cves_dict = {}
        for cve in cves:
            cves_dict[cve["id"]] = cve
        cve_results = {cpe: cves_dict}
    else:
        cve_results = {cpe: {}}

    return cve_results


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
        cve["vector_short"] = vector_short_tag.text.strip().split(" ")[0].strip()  # split at space to ignore the (V3 legend) at the end

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
                br.replace_with("\n")
            attr = strong_tag.text.strip()[:-1]  # ignore last text character (a colon)
            value = span_tag.text.strip()
            cve["vector_detail"][attr] = value  # replace possible HTML <br> tags with newline character

    if "cvssv2" in cve:
        transfrom_cvssv2_to_cvssv3(cve)


def transfrom_cvssv2_to_cvssv3(cve: dict):
    # Conversion incentives are takten from: https://security.stackexchange.com/questions/127335/how-to-convert-risk-scores-cvssv1-cvssv2-cvssv3-owasp-risk-severity
    # If the conversion incentive is indecisive, the more likely conversion was taken
    converted_cvssv3_vector = ""
    vector_fields = cve["vector_short"][1:-1].split("/")  # remove left and right parenthesis
    for vector_field in vector_fields:
        key, val = vector_field.split(":")
        if key == "AV":
            converted_cvssv3_vector += "%s:%s/" % (key, val)  # just copy AV field
        elif key == "AC":
            if val == "M":
                val = "H"
            converted_cvssv3_vector += "%s:%s/" % (key, val)
        elif key == "Au":
            if val == "S":
                val = "L"
            elif val == "M":
                val = "H"
            converted_cvssv3_vector += "%s:%s/" % ("PR", val)
        elif key == "Au":
            if val == "S":
                val = "L"
            elif val == "M":
                val = "H"
            converted_cvssv3_vector += "%s:%s/" % (key, val)
        elif key == "C" or key == "I" or key == "A":
            if val == "C":
                val = "H"
            elif val == "P":
                val = "L"
            elif val == "N":
                val = "N"
            converted_cvssv3_vector += "%s:%s/" % (key, val)
        elif key == "RL":
            if val == "OF":
                val = "O"
            elif val == "TF":
                val = "T"
            elif val == "ND":
                val = "X"
            converted_cvssv3_vector += "%s:%s/" % (key, val)
        elif key == "RL":
            if val == "UR":
                val = "R"
            elif val == "UC":
                val = "U"
            elif val == "ND":
                val = "X"
            converted_cvssv3_vector += "%s:%s/" % (key, val)

    if "C:C" in converted_cvssv3_vector and "I:C" in converted_cvssv3_vector and "A:C" in converted_cvssv3_vector:
        converted_cvssv3_vector += "S:C/"
    else:
        converted_cvssv3_vector += "S:U/"

    if "AC:H" in cve["vector_short"]:
        converted_cvssv3_vector += "UI:R/"
    else:
        converted_cvssv3_vector += "UI:N/"

    converted_cvssv3_vector = converted_cvssv3_vector[:-1]  # remove trailing /

    del cve["vector_detail"]
    cve["orig_cvssv2"] = cve["cvssv2"]
    del cve["cvssv2"]
    cve["orig_cvssv2_vector"] = cve["vector_short"]
    del cve["vector_short"]
    cve["converted_cvssv3_vector"] = "(%s)" % converted_cvssv3_vector
    vector_v3 = "CVSS:3.0/" + converted_cvssv3_vector
    cvssv3 = str(calculate_vector(vector_v3, cvss3)[0])  # get base score of cvssv3 score vector
    cve["cvssv3"] = cvssv3
