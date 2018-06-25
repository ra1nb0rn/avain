import copy
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from ... import utility as util

XML_NMAP_OUTPUT_PATH = "raw_nmap_scan_results.xml"
TEXT_NMAP_OUTPUT_PATH = "raw_nmap_scan_results.txt"
POT_OSES_PATH = "potential_oses.json"
NETWORKS_PATH, NETWORKS_OMIT_PATH = "network_add.list", "network_omit.list"

# additional nmap scripts to use
NMAP_SCRIPTS = ["http-headers", "http-title", "smb-os-discovery", "banner"]  

NETWORKS = []  # a list representing the networks to analyze
ADD_NETWORKS = []  # a list of networks as strings to additionally analyze
OMIT_NETWORKS = []  # a list of networks as strings to omit from the analysis
VERBOSE = False  # specifying whether to provide verbose output or not
PORTS = None  # the ports to scan
LOGFILE = ""
CONFIG = {}

DETECTED_OSES = {}

logger = None


def conduct_scan(results: list):
    """
    Scan the specified networks above with the following nmap command:
    sudo nmap -Pn -n -A --osscan-guess -T3 'networks' -sSU --script=${NMAP_SCRIPTS}

    :return: a tuple containing the scan results and a list of created files by writing it into the result list.
    """

    # setup logger
    logger = util.get_logger(__name__, LOGFILE)
    logger.info("Setting up Nmap scan")

    fast_scan = False
    if "FAST" in CONFIG and CONFIG["FAST"] == "True":
        fast_scan = True

    # write the networks to scan into a file to give to nmap
    logger.info("Writing networks to scan into '%s'" % NETWORKS_PATH)
    with open(NETWORKS_PATH, "w") as file:
        for net in NETWORKS:
            file.write(net + "\n")
        for net in ADD_NETWORKS:
            file.write(net + "\n")

    # prepare the base of the nmap call
    if not fast_scan:
        nmap_call = ["nmap", "-Pn", "-n", "-A", "--osscan-guess", "-T3", "-oX", XML_NMAP_OUTPUT_PATH, "-iL", NETWORKS_PATH]
    elif PORTS:
        nmap_call = ["nmap", "-Pn", "-n", "-A", "--osscan-guess", "-T5", "-oX", XML_NMAP_OUTPUT_PATH, "-iL", NETWORKS_PATH]
    else:
        nmap_call = ["nmap", "-Pn", "-n", "-A", "--osscan-guess", "-T5", "-F", "-oX", XML_NMAP_OUTPUT_PATH, "-iL", NETWORKS_PATH]

    # check if process owner is root and change nmap call accordingly
    if os.getuid() == 0:
        nmap_call.insert(0, "sudo")
        nmap_call.append("-sSU")  #  scan for TCP and UDP (UDP requires root privilege)

    if not fast_scan:
        # add nmap scripts to nmap call
        nmap_call.append("--script=%s" % ",".join(NMAP_SCRIPTS))

    # if only specific ports should be scanned, append that to the nmap call
    if PORTS:
        nmap_call.append("-p%s" % PORTS)

    # if nmap output should be verbose
    if VERBOSE:
        nmap_call.append("-v")

    # write the networks to exclude from the scan to an extra file that nmap can take as input
    if OMIT_NETWORKS:
        logger.info("Writing networks to omit into '%s'" % NETWORKS_OMIT_PATH)
        with open(NETWORKS_OMIT_PATH, "w") as file:
            for net in OMIT_NETWORKS:
                file.write(net + "\n")
        nmap_call.append("--excludefile")
        nmap_call.append(NETWORKS_OMIT_PATH)

    
    logger.info("Executing Nmap call '%s'" % " ".join(nmap_call))

    # open file handle to redirect nmap's stderr
    redr_file = open(TEXT_NMAP_OUTPUT_PATH, "w") 

    # call nmap with the created command
    subprocess.call(nmap_call, stdout=redr_file, stderr=subprocess.STDOUT)

    # close redirect file again
    redr_file.close()

    logger.info("Nmap scan done. Stdout and Stderr have been written to '%s'." % TEXT_NMAP_OUTPUT_PATH +
        "The XML output has been written to '%s'" % XML_NMAP_OUTPUT_PATH)

    created_files = [TEXT_NMAP_OUTPUT_PATH, XML_NMAP_OUTPUT_PATH, NETWORKS_PATH, POT_OSES_PATH]
    if OMIT_NETWORKS:
        created_files.append(NETWORKS_OMIT_PATH)

    logger.info("Parsing Nmap XML output")
    result = parse_output_file(XML_NMAP_OUTPUT_PATH), created_files
    with open(POT_OSES_PATH, "w") as f:
        f.write(json.dumps(DETECTED_OSES, ensure_ascii=False, indent=3))
    logger.info("Done")

    results.append(result)

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
    Parse the nmap xml output file into the common dict format for scan results.

    :return: a dict having host IPs as keys and their scan results as values
    """

    parsed_hosts = parse_nmap_xml(filepath)
    final_hosts = {}

    for parsed_host in parsed_hosts:
        host = discard_unuseful_info(parsed_host)
        final_hosts[host["ip"]["addr"]] = host
    return final_hosts


def parse_nmap_xml(filepath: str):
    """
    Parse the XML output file created by Nmap into a python dict for easier processing.
    :return: a dict containing the relevant information of the nmap XML
    """

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
        if os_elem:
            # iterate over all osmatch tags
            for osmatch_elem in os_elem.findall("osmatch"):
                osmatch = {}
                # parse general OS information
                for k, v in osmatch_elem.attrib.items():
                    if k != "line":
                        osmatch[k] = v

                # parse specific OS information contained in the osclass tags
                osclasses = []
                for osclass_elem in osmatch_elem.findall("osclass"):
                    osclass = {}
                    # copy all values contained in the XML to the dict
                    for k, v in osclass_elem.attrib.items():
                        osclass[k] = v

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
        if port_elem:
            # iterate over all port tags
            for port_elem in port_elem.findall("port"):
                port = {}
                # save general port information
                port["portid"], port["protocol"] = port_elem.attrib["portid"], port_elem.attrib["protocol"]
                port["state"] = port_elem.find("state").attrib["state"]
                # if port is not useful, skip it
                if "closed" in port["state"] or "filtered" in port["state"]:
                    continue

                new_os_si_added = False  # save whether the current service revealed any OS information
                service_elem = port_elem.find("service")
                for k, v in service_elem.attrib.items():
                    # if current attribute is useful and unrelated to OS, store it as port information
                    if k != "conf" and k != "method" and k != "ostype" and k != "devicetype":
                        port[k] = v
                    # handle OS information and add as new item to host dict
                    elif k == "ostype":
                        if not "os_si" in host:
                            host["os_si"] = []
                        if not any(os_si["name"] == v for os_si in host["os_si"]):
                            host["os_si"].append({"name": v})
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
        
        # find CPEs
        cpe_elem = smb_elem.find(".//elem[@key='cpe']")
        if cpe_elem is not None:
            # TODO: currently it is assumed, that the script only returns one CPE --> check if True
            cpe = cpe_elem.text

        # parse the OS name information contained in the actual output string
        output = smb_elem.attrib["output"].strip()
        for stmt in output.split("\n"):
            stmt = stmt.strip()
            k, v = stmt.split(":", 1)
            if k == "OS":
                os_name, adds = v.split("(", 1)
                os_name = os_name.strip()

        # only add OS info to host if OS name was found
        if os_name:
            host["os_smb_discv"] = [{"name": os_name}]
            if cpe:
                host["os_smb_discv"][0]["cpe"] = cpe

                # add to os_si directly
                # os_name_added = False
                # if os_name and not any(os_si["name"] == os_name for os_si in host["os_si"]):
                #     host["os_si"].append({"name": os_name})
                #     os_name_added = True

                # if os_name_added and cpe:
                #     host["os_si"][-1]["cpes"] = [cpe]



    ##########################
    #### Parse XML output ####
    ##########################

    try:
        nm_xml_tree = ET.parse(filepath)
    except ET.ParseError as e:
        print("Could not parse file created by Nmap scan. Skipping Nmap scan ...", file=sys.stderr)
        return {}

    nmaprun_elem = nm_xml_tree.getroot()
    hosts = []

    for host_elem in nmaprun_elem.findall("host"):
        host = {}
        status_elem = host_elem.find("status")
        if status_elem is not None:
            if "state" in status_elem.attrib:
                if status_elem.attrib["state"] == "down":
                    continue

        parse_addresses()

        # TODO: Hostnames ?

        # TODO: Hardware hints (in OS section) ?

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


def discard_unuseful_info(parsed_host):
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

        if protocol in parsed_host:
            for portid, portinfo in parsed_host[protocol].items():
                add_if_exists(portinfo, "product")
                add_if_exists(portinfo, "name")

    def fill_matching_string():
        """
        Fill the matching string with all text that contains information about the OS.
        """

        nonlocal matching_string

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

        # add all Service Info OS info to matching string
        if "os_si" in parsed_host:
            for os_si in parsed_host["os_si"]:
                if "cpes" in os_si:
                    for cpe in os_si["cpes"]:
                        matching_string += cpe.lower() + " "
                add_if_exists(os_si, "name")

        # add all smb-os-discovery info (if any)
        if "os_smb_discv" in parsed_host:
            for os_smb_discv in parsed_host["os_smb_discv"]:
                if "cpe" in os_smb_discv:
                    matching_string += os_smb_discv["cpe"].lower() + " "
                add_if_exists(os_smb_discv, "name")

        # add some port infos to matching string
        add_ports_to_matching_string("tcp")
        add_ports_to_matching_string("udp")

        # add mac vendor to matching string
        if "mac" in parsed_host:
            add_if_exists(parsed_host["mac"], "vendor")

            return matching_string

    def add_potential_oses_from_service(dict_key: str):
        """
        Evaluate nmap Service Info OS information and append result to potential oses

        :param dict_key: the key that identifies the service field within a host dict
        """
        added_in_service = set()

        if dict_key in parsed_host:
            for service_elem in parsed_host[dict_key]:
                found_supstring = False
                if "cpe" in service_elem:
                    service_elem["cpes"] = [service_elem["cpe"]]
                if "cpes" in service_elem:
                    # check if a CPE of the current OS is a prefix of a CPE already saved in potential_oses
                    for cpe in service_elem["cpes"]:
                        for pot_os in potential_oses:
                            if "cpes" in pot_os:
                                if any(cpe in pot_cpe for pot_cpe in pot_os["cpes"]):
                                    found_supstring = True
                                    break
                        if found_supstring:
                            break

                replaced_os = False
                # now check for a substring of name or CPE
                potential_os_cpy = copy.deepcopy(potential_oses)
                for i, pot_os in enumerate(potential_os_cpy):
                    pot_os_cmp, service_os_cmp = pot_os["name"].replace(" ", "").lower(), service_elem["name"].replace(" ", "").lower()
                    if pot_os_cmp in service_os_cmp:
                        if pot_os_cmp != service_os_cmp:
                            del potential_oses[i]
                            new_pot_os = {"name": service_elem["name"], "accuracy": "100", "type": service_elem.get("devicetype", "")}
                            if "cpes" in service_elem:
                                new_pot_os["cpes"] = service_elem["cpes"]

                            if not replaced_os:
                                potential_oses.insert(i, new_pot_os)
                                replaced_os = True
                            break
                    # if this OS of potential_oses has a CPE that is a prefix
                    # of a CPE of the current OS mentioned in the services
                    elif "cpes" in service_elem and "cpes" in pot_os:
                        for cpe in service_elem["cpes"]:
                            if any(pot_cpe in cpe for pot_cpe in pot_os["cpes"]):
                                del potential_oses[i]
                                new_pot_os = {"name": service_elem["name"], "cpes": service_elem["cpes"],
                                    "accuracy": "100", "type": service_elem.get("devicetype", "")}

                                if not replaced_os:
                                    potential_oses.insert(i, new_pot_os)
                                    replaced_os = True
                                break

                    # if the CPE is not stored yet in any way, append the current OS to the list of potential OSes
                    if not found_supstring and not replaced_os and not service_elem["name"] in added_in_service:
                        potential_oses.append({"name": service_elem["name"],
                            "accuracy": "100", "type": service_elem.get("devicetype", "")})
                        added_in_service.add(service_elem["name"])
                        if "cpes" in service_elem:
                            potential_oses[-1]["cpes"] = service_elem["cpes"]

    host = {}
    matching_string = ""
    fill_matching_string()


    #################################
    # write down all potential OSes #
    #################################

    potential_oses = []
    # start looking for potential OSes in the nmap osmatch information

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
                            if potential_oses:
                                for i, pot_os in enumerate(potential_oses):
                                    # if this cpe is substring of another OS's cpe
                                    if any(cpe in pot_cpe for pot_cpe in pot_os["cpes"]):
                                        store_os = False

                                    # if this cpe is a true superstring of another OS's cpe
                                    if any(pot_cpe in cpe and not cpe == pot_cpe for pot_cpe in pot_os["cpes"]):
                                        store_os = True
                                        del potential_oses[i]

                            if store_os:
                                potential_oses.append({"name": name, "cpes": osclass["cpes"],
                                    "accuracy": osclass["accuracy"], "type": osclass.get("type", "")})
                                break
                    else:
                        if not any(name in pot_os["name"] for pot_os in potential_oses):
                            potential_oses.append({"name": name, "cpes": [],"accuracy": osclass["accuracy"],
                                "type": osclass.get("type", "")})

    add_potential_oses_from_service("os_si")
    add_potential_oses_from_service("os_smb_discv")

    # Put vendor name in front of name if not existent
    for pot_os in potential_oses:
        if "cpes" in pot_os:
            cpes = pot_os["cpes"]
            vendor = ""
            if len(cpes) == 1:
                cpe_vend = cpes[0][7:]
                vendor = cpe_vend[:cpe_vend.find(":")]
            elif len(cpes) > 1:
                pass  # TODO: implement

            if vendor and not pot_os["name"].lower().startswith(vendor):
                pot_os["name"] = vendor[0].upper() + vendor[1:] + " " + pot_os["name"]

    DETECTED_OSES[parsed_host["ip"]["addr"]] = potential_oses

    # compute similarities of potential OSes to matching string
    is_os, highest_sim, = None, -1
    for pot_os in potential_oses:
        split_os_names, cur_name, sim_sum = [], "", -1
        for word in pot_os["name"].split(" "):
            cur_name += word.lower()
            cur_sim = util.compute_cosine_similarity(matching_string, cur_name)
            sim_sum += cur_sim
            cur_name += " "
        sim = sim_sum / len(pot_os["name"].split(" "))

        if pot_os.get("cpes", []):
            avg_cpe_sim = sum(util.compute_cosine_similarity(matching_string, cpe[7:].lower()) for cpe in pot_os["cpes"]) / len(pot_os["cpes"])
            sim = (sim + avg_cpe_sim) / 2
        sim *= float(pot_os["accuracy"])/100

        # print("%s --> %f with %s%%" % (pot_os["name"], sim, pot_os["accuracy"]))

        # iteratively save the OS with the highest similarity to the matching string
        if sim > highest_sim:
            highest_sim = sim
            is_os = pot_os

    # if a decisiion was made about the OS of the scanned system, store that in the host dict
    if is_os:
        host["os"] = is_os
    else:
        host["os"] = {"name": "", "cpes": []}

    # copy other information from the raw parsed host
    host["ip"] = parsed_host["ip"]
    host["mac"] = parsed_host["mac"]
    host["tcp"] = parsed_host["tcp"]
    host["udp"] = parsed_host["udp"]

    return host
