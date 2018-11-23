import json
import logging
import os
import subprocess

from core import utility as util

# Output files
HYDRA_OUTPUT_DIR = "hydra_output"
HYDRA_TEXT_OUTPUT = "hydra_output.txt"
HYDRA_JSON_OUTPUT = "hydra_output.json"
HYDRA_TARGETS_FILE = "targets.txt"
TIMEOUT_FILE = "timeout.txt"
VALID_CREDS_FILE = "valid_credentials.txt"

# Module parameters
HOSTS = {}  # a string representing the network to analyze
VERBOSE = False  # specifying whether to provide verbose output or not
CONFIG = None  # the configuration to use

CREATED_FILES = []

# Module variables
MIRAI_WORDLIST_PATH = "..{0}wordlists{0}mirai_user_pass.txt".format(os.sep)
HYDRA_TIMEOUT = 300  # in seconds
VALID_CREDS = {}
logger = None

### Calculation in CVSS v3 for default credential vulnerability resulted in:
###    CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H with base score of 9.8

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for susceptibility to Telnet password cracking with the MIRAI credentials.

    :return: a tuple containing the analyis results/scores and a list of created files by writing it into the result list.
    """

    # setup logger
    global logger, CREATED_FILES
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

    # run hydra if at least one target exists
    if wrote_target:
        CREATED_FILES.append(HYDRA_TARGETS_FILE)
        # get wordlists
        wordlists = [w.strip() for w in CONFIG.get("wordlists", MIRAI_WORDLIST_PATH).split(",")]

        if len(wordlists) > 1:
            os.makedirs(HYDRA_OUTPUT_DIR, exist_ok=True)

        for i, wlist in enumerate(wordlists):
            if not os.path.isfile(wlist):
                logger.warning("%s does not exist" % wlist)
                continue

            text_out, json_out, to_file = HYDRA_TEXT_OUTPUT, HYDRA_JSON_OUTPUT, TIMEOUT_FILE
            if i > 0:
                txt_base, txt_ext = os.path.splitext(text_out)
                json_base, json_ext = os.path.splitext(json_out)
                to_base, to_ext = os.path.splitext(to_file)
                text_out = txt_base + "_%d" % i + txt_ext
                json_out = json_base + "_%d" % i + json_ext
                to_file = to_base + "_%d" % i + to_ext

            if len(wordlists) > 1:
                text_out = os.path.join(HYDRA_OUTPUT_DIR, text_out)
                json_out = os.path.join(HYDRA_OUTPUT_DIR, json_out)
                to_file = os.path.join(HYDRA_OUTPUT_DIR, to_file)

            hydra_call = ["hydra", "-C", wlist, "-I", "-M", HYDRA_TARGETS_FILE, "-b", "json", "-o", json_out, "telnet"]
            logger.info("Beginning Hydra Telnet Brute Force with command: %s" % " ".join(hydra_call))
            redr_file = open(text_out, "w")
            CREATED_FILES += [text_out, json_out]
            try:
                subprocess.call(hydra_call, stdout=redr_file, stderr=subprocess.STDOUT, timeout=HYDRA_TIMEOUT)
            except subprocess.TimeoutExpired:
                with open(to_file, "w") as f:
                    if len(wordlists) > 1:
                        f.write("Hydra took longer than %ds and thereby timed out with wordlist %s" % (HYDRA_TIMEOUT, wlist))
                        logger.warning("Hydra took longer than %ds and thereby timed out with wordlist %s" % (HYDRA_TIMEOUT, wlist))
                    else:
                        f.write("Hydra took longer than %ds and thereby timed out. Analysis was unsuccessful." % HYDRA_TIMEOUT)
                        logger.warning("Hydra took longer than %ds and thereby timed out. Analysis was unsuccessful." % HYDRA_TIMEOUT)
                CREATED_FILES.append(to_file)
                redr_file.close()
                continue

            redr_file.close()
            logger.info("Done")

            # parse and process Hydra output
            logger.info("Processing Hydra Output")
            if os.path.isfile(json_out):
                result = process_hydra_output(json_out)
            else:
                result = {}
            logger.info("Done")
    else:
        # remove created but empty targets file
        os.remove(HYDRA_TARGETS_FILE)
        logger.info("Did not receive any targets. Skipping analysis.")
        CREATED_FILES = []

    result = {}
    for host in VALID_CREDS:
        result[host] = 9.8  # Give vulnerable host CVSSv3 score of 9.8

    # store valid credentials
    if VALID_CREDS:
        with open(VALID_CREDS_FILE, "w") as f:
            f.write(json.dumps(VALID_CREDS, ensure_ascii=False, indent=3))
        CREATED_FILES.append(VALID_CREDS_FILE)

    # return result
    results.append(result)


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
    if os.path.isdir(file):
        shutil.rmtree(HYDRA_OUTPUT_DIR)


def process_hydra_output(filepath: str):
    """
    Parse and process Hydra's Json output to retrieve all vulnerable hosts and their score.

    :param filepath: the filepath to Hydra's Json output
    :return: all vulnerable hosts as dict with their score as value
    """

    global CREATED_FILES, VALID_CREDS

    def process_hydra_result(hydra_result):
        for entry in hydra_result["results"]:
            addr, port = entry["host"], entry["port"]
            account = {"user": entry["login"], "pass": entry["password"]}

            # Add to credential storage
            if addr not in VALID_CREDS:
                VALID_CREDS[addr] = {}
            if port not in VALID_CREDS[addr]:
                VALID_CREDS[addr][port] = []
            if account not in VALID_CREDS[addr][port]:
                VALID_CREDS[addr][port].append(account)

    with open(filepath) as f:
        try:
            hydra_results = json.load(f)
        except json.decoder.JSONDecodeError:
            # Hydra seems to sometimes output a malformed JSON file.
            logger.warning("Got JSONDecodeError when parsing %s" % filepath)
            logger.info("Trying to parse again by replacing ', ,' with ','")

            replaced_file_name = os.path.splitext(filepath)[0] + "_replaced.json"

            with open(replaced_file_name, "w") as fr:
                text = f.read()
                text = text.replace(", ,", ", ")
                fr.write(text)
                CREATED_FILES.append(replaced_file_name)

            with open(replaced_file_name, "r") as fr:
                try:
                    hydra_results = json.load(fr)
                except json.decoder.JSONDecodeError:
                    logger.warning("Got JSONDecodeError when parsing %s" % filepath)
                return {}

    if isinstance(hydra_results, list):
        for hydra_result in hydra_results:
            process_hydra_result(hydra_result)
    elif isinstance(hydra_results, dict):
        process_hydra_result(hydra_results)
    else:
        logger.warning("Cannot parse JSON of Hydra output.")
