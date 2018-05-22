from bs4 import BeautifulSoup
import copy
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

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for CVEs belonging regarding its software.

    Returns a tuple contaiging the analyis results/scores and a list of created files by writing it into the result list.
    """
    
    def process_port_cves(protocol):
        nonlocal hosts
        for _, portinfo in host[protocol].items():
            if "cpes" in portinfo:
                service_cpes = portinfo["cpes"]
                portinfo["cpes"] = {}
                for cpe in service_cpes:
                    # get cpe cves
                    cves = get_cves(vulners_api, cpe)
                    cves_dict = {}
                    for cve in cves:
                        cves_dict[cve["id"]] = cve
                    portinfo["cpes"][cpe] = cves_dict
            else:
                # TODO: implement
                pass

    # setup logger
    logger = util.get_logger(__name__, LOGFILE)
    logger.info("Starting with CVE analysis")

    cve_results = {}
    vulners_api = vulners.Vulners()
    # hosts = copy.deepcopy(HOSTS)
    hosts = {'192.168.0.101': {'os': {'name': 'Apple OS X 10.10.X', 'cpes': ['cpe:/o:apple:mac_os_x:10.10'], 'accuracy': '97', 'type': 'general purpose'}, 'ip': {'addr': '192.168.0.101', 'type': 'ipv4'}, 'mac': {'addr': '', 'vendor': ''}, 'tcp': {'80': {'portid': '80', 'protocol': 'tcp', 'state': 'open', 'name': 'http', 'product': 'Apache httpd', 'version': '2.4.29', 'extrainfo': '(Unix)', 'cpes': ['cpe:/a:apache:http_server:2.4.29']}}, 'udp': {}}}

    for _, host in hosts.items():
        # get OS CVEs
        if "cpes" in host["os"]:
            os_cpes = host["os"]["cpes"]
            host["os"]["cpes"] = {}
            for cpe in os_cpes:
                # get cpe cves
                cves = get_cves(vulners_api, cpe)
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

    scores = determine_final_scores(hosts)
    created_files = [HOST_CVE_FILE]
    results.append(({}, created_files))
    # results.append((hosts, created_files))


def determine_final_scores(hosts: dict):
    # TODO: implement
    # TODO: aggregate using weights to have high scores be more impactful
    for _, host in hosts.items():
        pass


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
        cve_results = vulners_api.cpeVulnerabilities(cpe, maxVulnerabilities=500)  # TODO: handle limit better?
    
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

    # retrieve the short form of the attack vector
    vector_short_tag = soup.find("span", {"data-testid" : "vuln-cvssv3-vector"})
    if vector_short_tag:
        cve["vector_short"] = vector_short_tag.text.strip().split(" ")[0].strip()  # split at space to ignore the (V3 legend) at the end

    # retrieve the full text version of the attack vector
    cve["vector_detail"] = {}
    vector_detail_container = soup.find("p", {"data-testid" : "vuln-cvssv3-metrics-container"})
    if vector_detail_container:
        strong_tags = vector_detail_container.findAll("strong")
        span_tags = vector_detail_container.findAll("span")

        for i, strong_tag in enumerate(strong_tags):
            span_tag = span_tags[i]
            attr = strong_tag.text.strip()[:-1]  # ignore last text character (a colon)
            value = span_tag.text.strip()
            cve["vector_detail"][attr] = value
