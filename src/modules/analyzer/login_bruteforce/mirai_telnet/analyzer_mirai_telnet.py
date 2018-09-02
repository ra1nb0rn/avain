import json
import logging
import os
import subprocess

from core import utility as util

# Output files
HYDRA_TEXT_OUTPUT = "hydra_output.txt"
HYDRA_JSON_OUTPUT = "hydra_output.json"
HYDRA_TARGETS_FILE = "targets.txt"
TIMEOUT_FILE = "timeout.txt"

# Module parameters
HOSTS = {}  # a string representing the network to analyze
VERBOSE = False  # specifying whether to provide verbose output or not

# Module variables
WORDLIST_PATH = "..{0}wordlists{0}mirai_user_pass.txt".format(os.sep)
HYDRA_TIMEOUT = 300  # in seconds
logger = None

### Calculation in CVSS v3 for default credential vulnerability resulted in:
###    CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H with base score of 9.8

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for susceptibility to Telnet password cracking with the MIRAI credentials.

    :return: a tuple containing the analyis results/scores and a list of created files by writing it into the result list.
    """

    # setup logger
    global logger, created_files
    logger = logging.getLogger(__name__)
    logger.info("Starting with Mirai Telnet susceptibility analysis")
    wrote_target = False

    cleanup()  # cleanup potentially old files
    # write all potential targets to a file
    with open(HYDRA_TARGETS_FILE, "w") as f:
        for ip, host in HOSTS.items():
            for portid, portinfo in host["tcp"].items():
                if portid == "23":
                    f.write("%s:%s\n" % (ip, portid))
                    wrote_target = True
                elif "service" in portinfo and "telnet" in portinfo["service"].lower():
                    f.write("%s:%s\n" % (ip, portid))
                    wrote_target = True
                elif "name" in portinfo and "telnet" in portinfo["name"].lower():
                    f.write("%s:%s\n" % (ip, portid))
                    wrote_target = True

    hydra_call = ["hydra", "-C", WORDLIST_PATH, "-I", "-M", HYDRA_TARGETS_FILE, "-b", "json", "-o", HYDRA_JSON_OUTPUT, "telnet"]

    if wrote_target:
        # execute hydra command if at least one target exists
        logger.info("Beginning Hydra Brute Force with command: %s" % " ".join(hydra_call))
        redr_file = open(HYDRA_TEXT_OUTPUT, "w")
        created_files = [HYDRA_TEXT_OUTPUT, HYDRA_JSON_OUTPUT, HYDRA_TARGETS_FILE]
        try:
            subprocess.call(hydra_call, stdout=redr_file, stderr=subprocess.STDOUT, timeout=HYDRA_TIMEOUT)
        except subprocess.TimeoutExpired:
            with open(TIMEOUT_FILE, "w") as f:
                f.write("Hydra took longer than %ds and thereby timed out. Analysis was unsuccessful." % HYDRA_TIMEOUT)
            logger.warning("Hydra took longer than %ds and thereby timed out. Analysis was unsuccessful." % HYDRA_TIMEOUT)
            created_files.append(TIMEOUT_FILE)
            results.append(({}, created_files))
            return

        redr_file.close()
        logger.info("Done")

        # parse and process Hydra output
        logger.info("Processing Hydra Output")
        if os.path.isfile(HYDRA_JSON_OUTPUT):
            result = process_hydra_output()
        else:
            result = {}
        logger.info("Done")
    else:
        # remove created but empty targets file
        os.remove(HYDRA_TARGETS_FILE)
        logger.info("Did not receive any targets. Skipping analysis.")
        result = {}
        created_files = []

    # return result
    results.append((result, created_files))


def cleanup():
    """
    Cleanup potentially previously created files
    """

    def remove_file(file):
        if os.path.isfile(file):
            os.remove(file)

    remove_file(HYDRA_TEXT_OUTPUT)
    remove_file(HYDRA_JSON_OUTPUT)
    remove_file(HYDRA_TARGETS_FILE)
    remove_file(TIMEOUT_FILE)


def process_hydra_output():
    """
    Parse and process Hydra's Json output to retrieve all vulnerable hosts and their score.

    :return: all vulnerable hosts as dict with their score as value
    """

    global created_files

    def process_hydra_result(hydra_result):
        nonlocal vuln_hosts
        for entry in hydra_result["results"]:
            vuln_hosts[entry["host"]] = "9.8"  # give CVSS v3 score of 9.8

    vuln_hosts = {}

    with open(HYDRA_JSON_OUTPUT) as f:
        try:
            hydra_results = json.load(f)
        except json.decoder.JSONDecodeError:
            # Hydra seems to sometimes output a malformed JSON file.
            logger.warning("Got JSONDecodeError when parsing %s" % HYDRA_JSON_OUTPUT)
            logger.info("Trying to parse again by replacing ', ,' with ','")

            replaced_file_name = os.path.splitext(HYDRA_JSON_OUTPUT)[0] + "_replaced.json"

            with open(replaced_file_name, "w") as fr:
                text = f.read()
                text = text.replace(", ,", ", ")
                fr.write(text)
                created_files.append(replaced_file_name)

            with open(replaced_file_name, "r") as fr:
                try:
                    hydra_results = json.load(fr)
                except json.decoder.JSONDecodeError:
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