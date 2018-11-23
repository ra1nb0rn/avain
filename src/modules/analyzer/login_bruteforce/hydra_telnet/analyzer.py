import json
import logging
import os
import shutil
import subprocess

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
LOGGER = None

## Score calculation aligned to CVSS v3 for default credential vulnerability resulted in: ##
##           CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H with base score of 9.8          ##

def conduct_analysis(results: list):
    """
    Analyze the specified hosts in HOSTS for susceptibility to Telnet password
    cracking with the configured list of credentials (by default the Mirai creds).

    :return: a tuple containing the analyis results/scores
    """

    # setup logger
    global LOGGER, CREATED_FILES
    LOGGER = logging.getLogger(__name__)
    LOGGER.info("Starting with Mirai Telnet susceptibility analysis")

    # cleanup potentially old files
    cleanup()
    # write all potential targets to a file
    wrote_target = write_targets_file()

    # run hydra if at least one target exists
    if wrote_target:
        CREATED_FILES.append(HYDRA_TARGETS_FILE)
        # get wordlists
        wordlists = [w.strip() for w in CONFIG.get("wordlists", MIRAI_WORDLIST_PATH).split(",")]

        if len(wordlists) > 1:
            os.makedirs(HYDRA_OUTPUT_DIR, exist_ok=True)

        # call Hydra once for every configured wordlist
        for i, wlist in enumerate(wordlists):
            if not os.path.isfile(wlist):
                LOGGER.warning("%s does not exist", wlist)
                continue

            # determine correct output file names
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

            # Preparse Hydra call and run it
            hydra_call = ["hydra", "-C", wlist, "-I", "-M", HYDRA_TARGETS_FILE,
                          "-b", "json", "-o", json_out, "telnet"]
            LOGGER.info("Beginning Hydra Telnet Brute Force with command: %s", " ".join(hydra_call))
            redr_file = open(text_out, "w")
            CREATED_FILES += [text_out, json_out]

            # Sometimes, Hydra and other cracking tools do not seem to work properly
            # with Telnet services. Therefore, Hydra is run with a timeout.
            try:
                subprocess.call(hydra_call, stdout=redr_file, stderr=subprocess.STDOUT,
                                timeout=HYDRA_TIMEOUT)
            except subprocess.TimeoutExpired:
                with open(to_file, "w") as file:
                    if len(wordlists) > 1:
                        file.write("Hydra took longer than %ds and thereby timed out with wordlist %s" % (HYDRA_TIMEOUT, wlist))
                        LOGGER.warning("Hydra took longer than %ds and thereby timed out with wordlist %s", HYDRA_TIMEOUT, wlist)
                    else:
                        file.write("Hydra took longer than %ds and thereby timed out. Analysis was unsuccessful." % HYDRA_TIMEOUT)
                        LOGGER.warning("Hydra took longer than %ds and thereby timed out. Analysis was unsuccessful.", HYDRA_TIMEOUT)
                CREATED_FILES.append(to_file)
                redr_file.close()
                continue

            redr_file.close()
            LOGGER.info("Done")

            # parse and process Hydra output
            LOGGER.info("Processing Hydra Output")
            if os.path.isfile(json_out):
                process_hydra_output(json_out)
            LOGGER.info("Done")
    else:
        # remove created but empty targets file
        os.remove(HYDRA_TARGETS_FILE)
        LOGGER.info("Did not receive any targets. Skipping analysis.")
        CREATED_FILES = []

    # assign a score to every vulnerable host
    result = {}
    for host in VALID_CREDS:
        result[host] = 9.8  # Give vulnerable host CVSSv3 score of 9.8

    # store valid credentials
    if VALID_CREDS:
        with open(VALID_CREDS_FILE, "w") as file:
            file.write(json.dumps(VALID_CREDS, ensure_ascii=False, indent=3))
        CREATED_FILES.append(VALID_CREDS_FILE)

    # return result
    results.append(result)


def write_targets_file():
    """
    Write all brute force targets to file

    :return: True if at least one target exists, False otherwise
    """
    wrote_target = False
    with open(HYDRA_TARGETS_FILE, "w") as file:
        for ip, host in HOSTS.items():
            for portid, portinfo in host["tcp"].items():
                if portid == "23":
                    file.write("%s:%s\n" % (ip, portid))
                    wrote_target = True
                elif "service" in portinfo and "telnet" in portinfo["service"].lower():
                    file.write("%s:%s\n" % (ip, portid))
                    wrote_target = True
                elif "name" in portinfo and "telnet" in portinfo["name"].lower():
                    file.write("%s:%s\n" % (ip, portid))
                    wrote_target = True
    return wrote_target


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
    if os.path.isdir(HYDRA_OUTPUT_DIR):
        shutil.rmtree(HYDRA_OUTPUT_DIR)


def process_hydra_output(filepath: str):
    """
    Parse and process Hydra's Json output to retrieve all vulnerable hosts and their score.

    :param filepath: the filepath to Hydra's Json output
    """

    global CREATED_FILES

    with open(filepath) as file:
        try:
            hydra_results = json.load(file)
        except json.decoder.JSONDecodeError:
            # Hydra seems to sometimes output a malformed JSON file. Try to correct it.
            LOGGER.warning("Got JSONDecodeError when parsing %s", filepath)
            LOGGER.info("Trying to parse again by replacing ', ,' with ','")

            replaced_file_name = os.path.splitext(filepath)[0] + "_replaced.json"

            with open(replaced_file_name, "w") as file_repl:
                text = file.read()
                text = text.replace(", ,", ", ")
                file_repl.write(text)
                CREATED_FILES.append(replaced_file_name)

            with open(replaced_file_name, "r") as file_repl:
                try:
                    hydra_results = json.load(file_repl)
                except json.decoder.JSONDecodeError:
                    LOGGER.warning("Got JSONDecodeError when parsing %s", filepath)

    # extract valid credentials stored in Hydra output
    if isinstance(hydra_results, list):
        for hydra_result in hydra_results:
            process_hydra_result(hydra_result)
    elif isinstance(hydra_results, dict):
        process_hydra_result(hydra_results)
    else:
        LOGGER.warning("Cannot parse JSON of Hydra output.")


def process_hydra_result(hydra_result: dict):
    """
    Process the given hydra result to retrieve
    vulnerable hosts and valid credentials
    """
    global VALID_CREDS
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
