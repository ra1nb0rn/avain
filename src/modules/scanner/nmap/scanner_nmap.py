import copy
import json
import logging
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from core import utility as util

XML_NMAP_OUTPUT_PATH = "raw_nmap_scan_results.xml"
TEXT_NMAP_OUTPUT_PATH = "raw_nmap_scan_results.txt"
POT_OSS_PATH, MATCH_STR_PATH = "potential_oss.json", "matching_string.txt"
OS_SELECTION_SCORES_PATH = "os_selection_scores.json"
NETWORKS_PATH, NETWORKS_OMIT_PATH = "networks.list", "networks_omit.list"

NETWORKS = []  # a list representing the networks (as strings) to analyze
OMIT_NETWORKS = []  # a list of networks as strings to omit from the analysis
VERBOSE = False  # specifying whether to provide verbose output or not
PORTS = None  # the ports to scan
CONFIG = {}  # configuration for this module

DETECTED_OSS = {}  # stores for every host a list of potential OSs
OS_SIM_SCORES = {}  # stores for every host the likelihood of having an OS
CREATED_FILES = []  # stores created intermediate files
LOGGER = None


def conduct_scan(results: list):
    """
    Scan the above specified networks with Nmap and process the results.
    """

    global CREATED_FILES, LOGGER

    # setup logger
    LOGGER = logging.getLogger(__name__)
    LOGGER.info("Setting up Nmap scan")

    # use Nmap
    nmap_call = create_nmap_call()
    call_nmap(nmap_call, TEXT_NMAP_OUTPUT_PATH)

    LOGGER.info("Parsing Nmap XML output")
    result = parse_output_file(XML_NMAP_OUTPUT_PATH)

    # check if there was an IPv6 network in NETWORKS and run Nmap again in that case
    with open(TEXT_NMAP_OUTPUT_PATH) as file:
        text = " ".join(file.readlines())
        if "looks like an IPv6 target specification -- you have to use the -6 option." in text:
            LOGGER.info("IPv6 addresses were specified, running Nmap again with '-6' option.")
            text_name, text_ext = os.path.splitext(TEXT_NMAP_OUTPUT_PATH)
            textout = text_name + "_ipv6" + text_ext
            xml_name, xml_ext = os.path.splitext(XML_NMAP_OUTPUT_PATH)
            xmlout = xml_name + "_ipv6" + xml_ext
            CREATED_FILES += [textout, xmlout]
            nmap_call[nmap_call.index("-oX")+1] = xmlout
            nmap_call.append("-6")

            # same as above
            call_nmap(nmap_call, textout)
            LOGGER.info("Parsing Nmap XML output")
            result_ipv6 = parse_output_file(xmlout)

            # add to result
            for ip, host in result_ipv6.items():
                result[ip] = host

    # write intermediate OS results
    with open(POT_OSS_PATH, "w") as file:
        file.write(json.dumps(DETECTED_OSS, ensure_ascii=False, indent=3))
    CREATED_FILES.append(POT_OSS_PATH)

    with open(OS_SELECTION_SCORES_PATH, "w") as file:
        file.write(json.dumps(OS_SIM_SCORES, ensure_ascii=False, indent=3))
    CREATED_FILES.append(OS_SELECTION_SCORES_PATH)

    LOGGER.info("Done")
    results.append(result)


def create_nmap_call():
    """
    Create the concrete Nmap call to use
    """

    def check_sufficient_privs():
        nonlocal scan_type
        if os.geteuid() != 0 and ("S" in scan_type or "U" in scan_type):
            util.printit("Configured scan type requires root privileges!", color=util.RED)
            util.printit("Either run as root or change the config file.", color=util.RED)
            return False
        return True

    global CREATED_FILES
    # write the networks to scan into a file to give to nmap
    LOGGER.info("Writing networks to scan into '%s'", NETWORKS_PATH)
    with open(NETWORKS_PATH, "w") as file:
        for net in NETWORKS:
            file.write(net + "\n")

    # prepare the base of the nmap call
    if CONFIG.get("fast_scan", "false").lower() == "false":
        nmap_call = ["nmap", "-Pn", "-n", "-A", "--osscan-guess", "-T3",
                     "-oX", XML_NMAP_OUTPUT_PATH, "-iL", NETWORKS_PATH]
    elif PORTS:
        nmap_call = ["nmap", "-Pn", "-n", "-A", "--osscan-guess", "-T5",
                     "-oX", XML_NMAP_OUTPUT_PATH, "-iL", NETWORKS_PATH]
    else:
        nmap_call = ["nmap", "-Pn", "-n", "-A", "--osscan-guess", "-T5",
                     "-F", "-oX", XML_NMAP_OUTPUT_PATH, "-iL", NETWORKS_PATH]

    # use configuration setting to specify scan type
    scan_type = CONFIG.get("scan_type", "SU")
    nmap_call.append("-s" + scan_type)
    # check if privileges are sufficient for scan type
    check_sufficient_privs()

    # add nmap scripts to nmap call
    if "add_scripts" in CONFIG:
        nmap_call.append("--script=%s" % CONFIG["add_scripts"].replace(" ", ""))

    # if only specific ports should be scanned, append that to the nmap call
    if PORTS:
        nmap_call.append("-p%s" % PORTS)

    # if nmap output should be verbose
    if VERBOSE:
        nmap_call.append("-v")

    # write the networks to exclude from the scan to an extra file that nmap can take as input
    if OMIT_NETWORKS:
        LOGGER.info("Writing networks to omit into '%s'", NETWORKS_OMIT_PATH)
        with open(NETWORKS_OMIT_PATH, "w") as file:
            for net in OMIT_NETWORKS:
                file.write(net + "\n")
        nmap_call.append("--excludefile")
        nmap_call.append(NETWORKS_OMIT_PATH)

    # add to files before calling Nmap, in case Nmap errors during runtime
    CREATED_FILES += [TEXT_NMAP_OUTPUT_PATH, XML_NMAP_OUTPUT_PATH, NETWORKS_PATH]
    if OMIT_NETWORKS:
        CREATED_FILES.append(NETWORKS_OMIT_PATH)

    # append additional config parameters
    if "add_nmap_params" in CONFIG:
        nmap_call += CONFIG["add_nmap_params"].split(" ")

    return nmap_call


def call_nmap(nmap_call: list, redr_filepath: str):
    """
    Call Nmap using the given arguments and output redirection file
    """

    LOGGER.info("Executing Nmap call '%s'", " ".join(nmap_call))

    # open file handle to redirect nmap's stderr
    redr_file = open(redr_filepath, "w")

    # call nmap with the created command
    if VERBOSE:
        with subprocess.Popen(nmap_call, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              bufsize=1, universal_newlines=True) as proc:
            for line in proc.stdout:
                util.printit(line, end="")
                redr_file.write(line)
    else:
        subprocess.call(nmap_call, stdout=redr_file, stderr=subprocess.STDOUT)

    # close redirect file again
    redr_file.close()

    LOGGER.info("Nmap scan done. Stdout and Stderr have been written to '%s'. %s '%s'",
                redr_filepath, "The XML output has been written to",
                nmap_call[nmap_call.index("-oX") + 1])


def cleanup():
    """
    Delete the nmap input-list and exclude-file
    """
    def remove_file(path: str):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    remove_file(NETWORKS_PATH)
    remove_file(NETWORKS_OMIT_PATH)


def parse_output_file(filepath: str):
    """
    Parse the nmap xml output file into the common dict format for AVAIN scan results.

    :param filepath: the location of the output Nmap XML file
    :return: a dict having host IPs as keys and their scan results as values
    """

    parsed_hosts = parse_nmap_xml(filepath)  # mostly plain parsing
    final_hosts = {}

    for parsed_host in parsed_hosts:
        # remove unuseful info and aggregate
        host = transform_to_avain_scan_format(parsed_host)
        final_hosts[host["ip"]["addr"]] = host
    return final_hosts


def parse_nmap_xml(filepath: str):
    """
    Parse the XML output file created by Nmap into a python dict for easier processing.

    :param filepath: The filepath to the Nmap XML file
    :return: a dict containing the relevant information of the nmap XML
    """

    ################################################
    #### Definition of parsing helper functions ####
    ################################################

    def parse_addresses():
        """
        Parse the <address> tags containing IP and MAC information.
        """

        nonlocal host, host_elem

        ip, ip_type = "", ""
        mac, vendor = "", ""
        for addr in host_elem.findall("address"):
            if addr.attrib["addrtype"] == "ipv4" or addr.attrib["addrtype"] == "ipv6":
                ip = addr.attrib["addr"]
                ip_type = addr.attrib["addrtype"]
            elif addr.attrib["addrtype"] == "mac":
                mac = addr.attrib["addr"]
                vendor = addr.attrib.get("vendor", "")

        host["ip"] = {"addr": ip, "type": ip_type}
        host["mac"] = {"addr": mac, "vendor": vendor}

    def parse_osmatches():
        """
        Parse all <osmatch> and their <osclass> tags to gather OS information.
        """

        nonlocal host, host_elem
        osmatches = []

        os_elem = host_elem.find("os")
        if os_elem is not None:
            # iterate over all osmatch tags
            for osmatch_elem in os_elem.findall("osmatch"):
                osmatch = {}
                # parse general OS information
                for key, value in osmatch_elem.attrib.items():
                    if key != "line":
                        osmatch[key] = value

                # parse specific OS information contained in the osclass tags
                osclasses = []
                for osclass_elem in osmatch_elem.findall("osclass"):
                    osclass = {}
                    # copy all values contained in the XML to the dict
                    for key, value in osclass_elem.attrib.items():
                        osclass[key] = value

                    cpe_elems = osclass_elem.findall("cpe")
                    cpes = []
                    for cpe_elem in cpe_elems:
                        cpes.append(cpe_elem.text)

                    osclass["cpes"] = cpes
                    osclasses.append(osclass)

                osmatch["osclasses"] = osclasses
                osmatches.append(osmatch)

        host["osmatches"] = osmatches

    def parse_port_information():
        """
        Parse all <port> tags contained in <ports> to gather port information.
        """

        nonlocal host, host_elem
        tcp_ports, udp_ports = {}, {}

        port_elem = host_elem.find("ports")
        if port_elem is not None:
            # iterate over all port tags
            for port_elem in port_elem.findall("port"):
                port = {}
                # save general port information
                port["portid"] = port_elem.attrib["portid"]
                port["protocol"] = port_elem.attrib["protocol"]
                port["state"] = port_elem.find("state").attrib["state"]
                # if port is not useful, skip it
                if "closed" in port["state"] or "filtered" in port["state"]:
                    continue

                new_os_si_added = False  # save if the current service revealed any OS information
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    for key, value in service_elem.attrib.items():
                        # if current attribute is useful and unrelated to OS, store it as port info
                        if key not in ("conf", "method", "ostype", "devicetype"):
                            port[key] = value
                        # handle OS information and add as new item to host dict
                        elif key == "ostype":
                            if "os_si" not in host:
                                host["os_si"] = []
                            if not any(os_si["name"] == value for os_si in host["os_si"]):
                                host["os_si"].append({"name": value})
                                if "devicetype" in service_elem.attrib:
                                    host["os_si"][-1]["type"] = service_elem.attrib["devicetype"]
                                new_os_si_added = True

                    # parse CPE information for service and OS (if it exists)
                    cpe_elems = service_elem.findall("cpe")
                    cpes = []
                    for cpe_elem in cpe_elems:
                        cpe_text = cpe_elem.text
                        # if the CPE is related to the offered service
                        if cpe_text.startswith("cpe:/a:"):
                            cpes.append(cpe_text)
                        # if CPE is related to underlaying OS and new OS information was registered
                        elif cpe_text.startswith("cpe:/o:") and new_os_si_added:
                            if not "cpes" in host["os_si"][-1]:
                                host["os_si"][-1]["cpes"] = []
                            host["os_si"][-1]["cpes"].append(cpe_text)

                    if cpes:
                        port["cpes"] = cpes

                if port["protocol"] == "tcp":
                    tcp_ports[port["portid"]] = port
                elif port["protocol"] == "udp":
                    udp_ports[port["portid"]] = port

        host["tcp"] = tcp_ports
        host["udp"] = udp_ports

    def parse_smb_script_information():
        """
        Parse the SMB script tag to get SMB information about the OS if possible.
        """

        nonlocal host, smb_elem
        os_name, cpe = "", ""

        # find and parse CPE strings
        cpe_elem = smb_elem.find(".//elem[@key='cpe']")
        if cpe_elem is not None:
            # Assumption: script only returns one CPE (check if True)
            cpe = cpe_elem.text

        # find and parse the OS name information contained in the actual output string
        output = smb_elem.attrib["output"].strip()
        for stmt in output.split("\n"):
            stmt = stmt.strip()
            key, value = stmt.split(":", 1)
            if key == "OS":
                os_name = value.split("(", 1)[0].strip()

        # only add OS info to host if OS name was found
        if os_name:
            host["os_smb_discv"] = [{"name": os_name}]
            if cpe:
                host["os_smb_discv"][0]["cpe"] = cpe


    ################################################
    #### Main code of Nmap XML parsing function ####
    ################################################

    try:
        nm_xml_tree = ET.parse(filepath)
    except ET.ParseError:
        print("Could not parse file created by Nmap scan. Skipping Nmap scan ...", file=sys.stderr)
        return {}

    nmaprun_elem = nm_xml_tree.getroot()
    hosts = []

    # parse every host element
    for host_elem in nmaprun_elem.findall("host"):
        host = {}
        status_elem = host_elem.find("status")
        if status_elem is not None:
            if "state" in status_elem.attrib:
                if status_elem.attrib["state"] == "down":
                    continue

        parse_addresses()
        parse_osmatches()
        parse_port_information()

        # parse additional script information
        hostscript_elem = host_elem.find("hostscript")
        if hostscript_elem:
            # parse smb-os-discovery information
            smb_elem = hostscript_elem.find(".//script[@id='smb-os-discovery']")
            if smb_elem:
                parse_smb_script_information()

        hosts.append(host)

    return hosts


def transform_to_avain_scan_format(parsed_host: dict):
    """
    Transform the Nmap scan results to the AVAIN scan result format.
    """
    host = {}

    # select one OS out of all OS suggestions from Nmap
    host["os"] = select_os(parsed_host)
    # copy remaining information from the raw parsed host
    host["ip"] = parsed_host["ip"]
    host["mac"] = parsed_host["mac"]
    host["tcp"] = parsed_host["tcp"]
    host["udp"] = parsed_host["udp"]
    adjust_port_info_keys(host)

    return host


def select_os(parsed_host: dict):
    """
    Out of all suggested OSs for the given host from Nmap, select the most
    likely one using cosine similarity string matching. First a string of
    relevant information is created, second the OS whose information is the
    most similar to the matching string is returned.
    """

    global CREATED_FILES, DETECTED_OSS, OS_SIM_SCORES
    # create cosine similarity matching string and store
    matching_string = create_sim_matching_string(parsed_host)
    with open(MATCH_STR_PATH, "w") as file:
        file.write(matching_string)
    CREATED_FILES.append(MATCH_STR_PATH)

    potential_oss = extract_oss(parsed_host)
    # Put vendor name in front of name if not existent
    for pot_os in potential_oss:
        if "cpes" in pot_os:
            cpes = pot_os["cpes"]
            vendor = ""
            # assumption: Nmap does not group two OS CPEs with different vendors
            if cpes:
                cpe_vend = cpes[0][7:]
                vendor = cpe_vend[:cpe_vend.find(":")]

            if vendor and not pot_os["name"].lower().startswith(vendor):
                pot_os["name"] = vendor[0].upper() + vendor[1:] + " " + pot_os["name"]

    DETECTED_OSS[parsed_host["ip"]["addr"]] = potential_oss

    # compute similarities of potential OSs to matching string
    os_sim_scores = []
    is_os, highest_sim, = None, -1
    for pot_os in potential_oss:
        cur_name, sim_sum = "", -1
        for word in pot_os["name"].split(" "):
            cur_name += word.lower()
            cur_sim = util.compute_cosine_similarity(matching_string, cur_name)
            sim_sum += cur_sim
            cur_name += " "
        sim = sim_sum / len(pot_os["name"].split(" "))

        if pot_os.get("cpes", []):
            avg_cpe_sim = sum(util.compute_cosine_similarity(matching_string, cpe[7:].lower())
                              for cpe in pot_os["cpes"]) / len(pot_os["cpes"])
            sim = (sim + avg_cpe_sim) / 2
        sim *= float(pot_os["accuracy"])/100

        # print("%s --> %f with %s%%" % (pot_os["name"], sim, pot_os["accuracy"]))
        os_sim_scores.append((pot_os, sim))

        # iteratively save the OS with the highest similarity to the matching string
        if sim > highest_sim:
            highest_sim = sim
            is_os = pot_os

    # store OS sim scores
    OS_SIM_SCORES[parsed_host["ip"]["addr"]] = os_sim_scores

    if is_os:
        return is_os
    return {"name": "", "cpes": []}


def create_sim_matching_string(parsed_host: dict):
    """
    Fill the matching string with all text that contains information about the OS.
    """

    def add_if_exists(obj: dict, field: str):
        """
        Add a dict value to the matching string if its key exists in the dict.
        """

        nonlocal matching_string
        if field in obj:
            matching_string += obj[field].lower() + " "

    def add_ports_to_matching_string(protocol: str):
        """
        Add the name and product information from the service information to the matching string.
        """

        nonlocal parsed_host
        if protocol in parsed_host:
            for _, portinfo in parsed_host[protocol].items():
                add_if_exists(portinfo, "product")
                add_if_exists(portinfo, "name")

    matching_string = ""

    # add all OS info to matching string
    if "osmatches" in parsed_host:
        for osmatch in parsed_host["osmatches"]:
            add_if_exists(osmatch, "name")
            if "osclasses" in osmatch:
                for osclass in osmatch["osclasses"]:
                    if "cpes" in osclass:
                        for cpe in osclass["cpes"]:
                            matching_string += cpe.lower() + " "

                    add_if_exists(osclass, "osfamily")
                    add_if_exists(osclass, "osgen")
                    add_if_exists(osclass, "vendor")

    # add all service Info OS info to matching string
    if "os_si" in parsed_host:
        for os_si in parsed_host["os_si"]:
            if "cpes" in os_si:
                for cpe in os_si["cpes"]:
                    matching_string += cpe.lower() + " "
            add_if_exists(os_si, "name")

    # add all smb-os-discovery info (if any exists)
    if "os_smb_discv" in parsed_host:
        for os_smb_discv in parsed_host["os_smb_discv"]:
            if "cpe" in os_smb_discv:
                matching_string += os_smb_discv["cpe"].lower() + " "
            add_if_exists(os_smb_discv, "name")

    # add select port infos to matching string
    add_ports_to_matching_string("tcp")
    add_ports_to_matching_string("udp")

    # add mac vendor to matching string
    if "mac" in parsed_host:
        add_if_exists(parsed_host["mac"], "vendor")

    return matching_string


def extract_oss(parsed_host: dict):
    """
    Return a list of potential OSs for the given host. More broad OSs are replaced
    by more concrete ones. E.g. within potential_oss, Windows is replaced by Windows 10.
    """

    ########################################
    #### Definition of helper functions ####
    ########################################

    def add_direct_oss():
        """Add the OSs found in the osmatches to poential_oss"""

        nonlocal parsed_host, potential_oss
        if "osmatches" in parsed_host:
            for osmatch in parsed_host["osmatches"]:
                if "osclasses" in osmatch:
                    for osclass in osmatch["osclasses"]:
                        name = ""
                        if "vendor" in osclass:
                            name += osclass["vendor"] + " "
                        if "osfamily" in osclass:
                            name += osclass["osfamily"] + " "
                        if "osgen" in osclass:
                            name += osclass["osgen"]

                        name = name.strip()

                        if osclass.get("cpes", []):
                            for cpe in osclass["cpes"]:
                                store_os = True
                                replace_accuracy = 0
                                if potential_oss:
                                    for i, pot_os in enumerate(potential_oss):
                                        # if this cpe is substring of another OS's cpe
                                        if any(cpe in pot_cpe for pot_cpe in pot_os["cpes"]):
                                            store_os = False

                                        # if this cpe is a true superstring of another OS's cpe
                                        if any(pot_cpe in cpe and not cpe == pot_cpe for pot_cpe in pot_os["cpes"]):
                                            store_os = True
                                            if int(pot_os["accuracy"]) > int(replace_accuracy):
                                                replace_accuracy = pot_os["accuracy"]
                                            del potential_oss[i]

                                if store_os:
                                    accuracy = str(max([int(osclass["accuracy"]), int(replace_accuracy)]))
                                    potential_oss.append({"name": name, "cpes": osclass["cpes"],
                                                          "accuracy": accuracy, "type": osclass.get("type", "")})
                                    break
                        else:
                            if not any(name in pot_os["name"] for pot_os in potential_oss):
                                potential_oss.append({"name": name, "cpes": [], "accuracy": osclass["accuracy"],
                                                      "type": osclass.get("type", "")})

    def add_potential_oss_from_service(dict_key: str):
        """
        Evaluate nmap Service Info OS information and append result to potential OSs

        :param dict_key: the key that identifies the service field within a host dict
        """

        nonlocal parsed_host, potential_oss
        added_in_service = set()

        if dict_key in parsed_host:
            for service_elem in parsed_host[dict_key]:
                # first check if the OS information of this service contains a more broad OS
                found_supstring = False
                if "cpe" in service_elem:
                    service_elem["cpes"] = [service_elem["cpe"]]
                if "cpes" in service_elem:
                    # check if a CPE of the current service is a prefix of a CPE already saved in potential_oss
                    for cpe in service_elem["cpes"]:
                        for pot_os in potential_oss:
                            if "cpes" in pot_os:
                                if any(cpe in pot_cpe for pot_cpe in pot_os["cpes"]):
                                    found_supstring = True
                                    break
                        if found_supstring:
                            break

                replaced_os = False
                # now check for a substring of name or CPE in potential_oss, i.e. a broad OS
                potential_os_cpy = copy.deepcopy(potential_oss)
                for i, pot_os in enumerate(potential_os_cpy):
                    pot_os_cmp = pot_os["name"].replace(" ", "").lower()
                    service_os_cmp = service_elem["name"].replace(" ", "").lower()
                    # do OS comparison by name
                    if pot_os_cmp != service_os_cmp and pot_os_cmp in service_os_cmp:
                        del potential_oss[i]
                        new_pot_os = {"name": service_elem["name"], "accuracy": "100",
                                      "type": service_elem.get("devicetype", "")}
                        if "cpes" in service_elem:
                            new_pot_os["cpes"] = service_elem["cpes"]

                        if not replaced_os:
                            potential_oss.insert(i, new_pot_os)
                            replaced_os = True
                        break
                    # if this OS of potential_oss has a CPE that is a prefix
                    # of a CPE of the current OS mentioned in the services
                    elif "cpes" in service_elem and "cpes" in pot_os:
                        for cpe in service_elem["cpes"]:
                            if any(pot_cpe in cpe for pot_cpe in pot_os["cpes"]):
                                del potential_oss[i]
                                new_pot_os = {"name": service_elem["name"], "cpes": service_elem["cpes"],
                                              "accuracy": "100", "type": service_elem.get("devicetype", "")}

                                if not replaced_os:
                                    potential_oss.insert(i, new_pot_os)
                                    replaced_os = True
                                break

                    # if the service's OS info is not stored yet, append the
                    # current OS to the list of potential OSs
                    if ((not found_supstring) and (not replaced_os) and
                            (not service_elem["name"] in added_in_service)):
                        potential_oss.append({"name": service_elem["name"], "accuracy": "100",
                                              "type": service_elem.get("devicetype", "")})
                        added_in_service.add(service_elem["name"])
                        if "cpes" in service_elem:
                            potential_oss[-1]["cpes"] = service_elem["cpes"]


    ##############################
    #### Main OS extract code ####
    ##############################

    potential_oss = []
    add_direct_oss()
    add_potential_oss_from_service("os_si")
    add_potential_oss_from_service("os_smb_discv")
    return potential_oss


def adjust_port_info_keys(host: dict):
    """
    Deletes the name, version and product keys of the port dicts of the host and instead adds
    a name describing the likely running software and a service key naming the offered service.

    :param host: the host to change the service keys of
    """

    def adjust_ports(protocol: str):
        """Adjust the information of all ports using the specified transport protocol"""
        nonlocal host

        for _, port in host[protocol].items():
            product, name = port.get("product", ""), port.get("name", "")
            version = port.get("version", "")

            keys = {"product", "name", "version"}
            for k in keys:
                if k in port:
                    del port[k]

            new_name = product
            if version:
                new_name += " " + version

            port["name"] = new_name
            port["service"] = name

    if "tcp" in host:
        adjust_ports("tcp")
    if "udp" in host:
        adjust_ports("udp")
