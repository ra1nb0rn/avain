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

from ... import utility as util

HOST_CVE_FILE = "found_cves.json"

HOSTS = {}  # a string representing the network to analyze
VERBOSE = False  # specifying whether to provide verbose output or not
LOGFILE = ""

logger = None

CVE_AMOUNT = 0

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for CVEs belonging regarding its software.

    Returns a tuple contaiging the analyis results/scores and a list of created files by writing it into the result list.
    """
    
    def process_port_cves(protocol):
        global CVE_AMOUNT
        nonlocal hosts

        for _, portinfo in host[protocol].items():
            if "cpes" in portinfo:
                service_cpes = portinfo["cpes"]
                portinfo["cpes"] = {}
                for cpe in service_cpes:
                    # get cpe cves
                    cves = get_cves(vulners_api, cpe)
                    CVE_AMOUNT += len(cves)
                    cves_dict = {}
                    for cve in cves:
                        cves_dict[cve["id"]] = cve
                    portinfo["cpes"][cpe] = cves_dict
            else:
                # TODO: implement
                pass

    global CVE_AMOUNT, logger   
    # setup logger
    logger = util.get_logger(__name__, LOGFILE)
    logger.info("Starting with CVE analysis")

    cve_results = {}
    vulners_api = vulners.Vulners()
    hosts = copy.deepcopy(HOSTS)

    logger.info("Starting with CVE discovery of all hosts")
    for _, host in hosts.items():
        # get OS CVEs
        if "cpes" in host["os"]:
            os_cpes = host["os"]["cpes"]
            host["os"]["cpes"] = {}
            for cpe in os_cpes:
                # get cpe cves
                cves = get_cves(vulners_api, cpe)
                CVE_AMOUNT += len(cves)
                cves_dict = {}
                for cve in cves:
                    cves_dict[cve["id"]] = cve
                host["os"]["cpes"][cpe] = cves_dict
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


def get_cves(vulners_api, cpe: str):
    with warnings.catch_warnings():  # ignore warnings that vulners might throw
        warnings.simplefilter("ignore")
        try:
            cve_results = vulners_api.cpeVulnerabilities(cpe, maxVulnerabilities=500)  # TODO: handle limit better?
        except ValueError:
            logger.warning("Getting CVEs for CPE '%s' resulted in a ValueError. Maybe CPE is malformed.")
            cve_results = {}

    cve_results = cve_results.get("NVD", [])
    if cve_results:
        cve_results = slim_cve_results(cve_results)
        for cve_result in cve_results:
            cve_id = cve_result["id"]
            add_additional_cve_info(cve_result)
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
