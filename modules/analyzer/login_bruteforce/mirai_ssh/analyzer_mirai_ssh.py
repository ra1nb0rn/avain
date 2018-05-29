import json
import os
import subprocess

from .... import utility as util

HYDRA_TEXT_OUTPUT = "hydra_output.txt"
HYDRA_JSON_OUTPUT = "hydra_output.json"
HYDRA_TARGETS_FILE = "targets.txt"

HOSTS = {}  # a string representing the network to analyze
VERBOSE = False  # specifying whether to provide verbose output or not
LOGFILE = ""

WORDLIST_PATH = "..{0}wordlists{0}mirai_user_pass.txt".format(os.sep)

logger = None

### Calculation in CVSS v3 for default credential vulnerability resulted in:
###    CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H with base score of 9.8

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for susceptibility to SSH password cracking with the MIRAI credentials.

    Returns a tuple contaiging the analyis results/scores and a list of created files by writing it into the result list.
    """

    # setup logger
    global logger
    logger = util.get_logger(__name__, LOGFILE)
    logger.info("Starting with Mirai SSH susceptibility analysis")

    cleanup()  # cleanup potentially old files
    with open(HYDRA_TARGETS_FILE, "w") as f:
        for ip, host in HOSTS.items():
            for portid, portinfo in host["tcp"].items():
                if portid == "22" or "ssh" in portinfo["name"].lower() or "ssh" in portinfo["product"].lower():
                    f.write("%s:%s" % (ip, portid))

    hydra_call = ["hydra", "-C", WORDLIST_PATH, "-M", HYDRA_TARGETS_FILE, "-b", "json", "-o", HYDRA_JSON_OUTPUT, "ssh"]

    logger.info("Beginning Hydra Brute Force with command: %s" % " ".join(hydra_call))
    redr_file = open(HYDRA_TEXT_OUTPUT, "w")
    subprocess.call(hydra_call, stdout=redr_file, stderr=subprocess.STDOUT)
    redr_file.close()
    logger.info("Done")

    logger.info("Processing Hydra Output")
    result = process_hydra_output()
    logger.info("Done")
    created_files = [HYDRA_TEXT_OUTPUT, HYDRA_JSON_OUTPUT, HYDRA_TARGETS_FILE]
    results.append((result, created_files))


def cleanup():
    def remove_file(file):
        if os.path.isfile(file):
            os.remove(file)

    remove_file(HYDRA_TEXT_OUTPUT)
    remove_file(HYDRA_JSON_OUTPUT)
    remove_file(HYDRA_TARGETS_FILE)


def process_hydra_output():
    def process_hydra_result(hydra_result):
        nonlocal vuln_hosts
        for entry in hydra_result["results"]:
            vuln_hosts[entry["host"]] = "9.8"  # give CVSS v3 score of 9.8

    vuln_hosts = {}

    with open(HYDRA_JSON_OUTPUT) as f:
        try:
            hydra_results = json.load(f)
        except json.decoder.JSONDecodeError:
            # Hydra seems to output a malformed JSON file if only one host is scanned
            # and it refuses connection. In that case it is should be fine to return no results.
            logger.warning("Got JSONDecodeError when parsing %s" % HYDRA_JSON_OUTPUT)
            return {}

    if isinstance(hydra_results, list):
        for hydra_result in hydra_results:
            process_hydra_result(hydra_result)
    elif isinstance(hydra_results, dict):
        process_hydra_result(hydra_results)
    else:
        logger.warning("Cannot parse JSON of Hydra output.")

    return vuln_hosts