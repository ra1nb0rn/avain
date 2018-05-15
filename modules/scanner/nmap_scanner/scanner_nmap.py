import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from ... import utility as util

OUTPUT_PATH = "nmap_scan_results.xml"
NETWORKS_PATH, NETWORK_OMIT_PATH = "network_add.list", "network_omit.list"

# additional nmap scripts to use
NMAP_SCRIPTS = ["http-headers", "http-title", "smb-os-discovery", "banner"]  

# what about:
#   !!!!!!!!!!! banner, for banner grabbing? CHECK IF USEFUL
#   banner-plus: https://github.com/hdm/scan-tools/blob/master/nse/banner-plus.nse ???
#   http-enum? aggressive scan ok?
#   http-methods to find "vulnerable" HTTP methods, e.g. maybe put?
#   for mysql servers: mysql-info? But maybe unuseful for automatic scanning?
# NOT http-sitemap-generator but it is interesting for manual recon!

# nmap shows bad cpe for cpe:/a:openbsd:openssh:6.7p1   ?

#### !!!!!!! nmap-vulners script !!!!!!!! ####

# another field for hardware?

# when multiple potential OS and correlating with other info (service, SMB, ...) use similarity metrics (i.e. cosine-similarity)
# or add similarities of all considered fields?

# add a mandatory accuracy field to every set of information (e.g. for every port information set)

# VMs setup and bridged network adapter

# https://github.com/toolswatch/vFeed ???

# correlate accuracy, i.e. more general OS has 100 accuracy and conrecete OS has 96 accuracy


def scan_network(network: str, add_networks: list, omit_networks: list, verbose: bool, ports:str = None):
    """
    Scan the specified networks with the following nmap command:
    sudo nmap -Pn -n -A --osscan-guess -T3 'network' -sSU --script=${NMAP_SCRIPTS}

    :param network: A string representing the network to analyze
    :param add_networks: A list of networks as strings to additionally analyze
    :param omit_networks: A list of networks as strings to omit from the analysis
    :param verbose: Specifying whether to provide verbose output or not
    :param ports: The ports to scan
    :return: a tuple containging the scan results and a list of created files
    """

    # write the networks to scan into a file to give to nmap
    with open(NETWORKS_PATH, "w") as file:
        if network:
            file.write(network + "\n")
        for net in add_networks:
            file.write(net + "\n")

    # prepare the base of the nmap call
    nmap_call = ["nmap", "-Pn", "-n", "-A", "--osscan-guess", "-T3", "-oX", OUTPUT_PATH, "-iL", NETWORKS_PATH]

    # check if process owner is root and change nmap call accordingly
    if os.getuid() == 0:
        nmap_call.insert(0, "sudo")
        nmap_call.append("-sSU")  #  scan for TCP and UDP (UDP requires root privilege)
    else:
        print("Warning: not running this program as root user leads to less effective scanning (e.g. with nmap)", file=sys.stderr)

    # add nmap scripts to nmap call
    nmap_call.append("--script=%s" % ",".join(NMAP_SCRIPTS))

    # if only specific ports should be scanned, append that to the nmap call
    if ports:
        nmap_call.append("-p%s" % ports)

    # if nmap output should be verbose
    if verbose:
        nmap_call.append("-v")

    # write the networks to exclude from the scan to an extra file that nmap can take as input
    if omit_networks:
        with open(NETWORK_OMIT_PATH, "w") as file:
            for net in omit_networks:
                file.write(net + "\n")
        nmap_call.append("--excludefile")
        nmap_call.append(NETWORK_OMIT_PATH)

    if (verbose):
        print("Executing formatted nmap call: " + " ".join(nmap_call))
    
    # create /dev/null file handle to redirect nmap's stderr
    f = open(os.devnull, "w") 

    # call nmap with the created command
    subprocess.check_output(nmap_call, stderr=f)

    # close /dev/null file again
    f.close()

    # cleanup network files
    cleanup()

    return parse_output_file(OUTPUT_PATH), [OUTPUT_PATH]


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
    remove_file(NETWORK_OMIT_PATH)


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
                        if cpe_elem.text.startswith("cpe:/o:"):  # confirm it is an OS CPE
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
        if dict_key in parsed_host:
            for service_elem in parsed_host[dict_key]:
                # check if the name of the current OS is not a prefix of a name already stored in the list of potential oses
                if not any(service_elem["name"].replace(" ", "").lower() in pot_os["name"].replace(" ", "").lower() for pot_os in potential_oses):

                    if "cpes" in service_elem:
                        # check if a CPE of the current OS is a prefix of a CPE already saved in potential_oses
                        found_supstring = False
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
                    for i, pot_os in enumerate(potential_oses):
                        # if there this OS of potential_oses is a prefix of the current OS mentioned in the services
                        if pot_os["name"].replace(" ", "").lower() in service_elem["name"].replace(" ", "").lower():
                            del potential_oses[i]
                            new_pot_os = {"name": service_elem["name"], "accuracy": "100"}
                            if "cpes" in service_elem:
                                new_pot_os["cpes"] = service_elem["cpes"]
                            potential_oses.insert(i, new_pot_os)
                            replaced_os = True
                            break
                        # if there this OS of potential_oses has a CPE that is a prefix
                        # of a CPE of the current OS mentioned in the services
                        elif "cpes" in service_elem and "cpes" in pot_os:
                            for cpe in service_elem["cpes"]:
                                if any(pot_cpe in cpe for pot_cpe in pot_os["cpes"]):
                                    del potential_oses[i]
                                    new_pot_os = {"name": service_elem["name"], "cpes": service_elem["cpes"],
                                        "accuracy": "100", "type": service_elem.get("devicetype", "")}
                                    potential_oses.insert(i, new_pot_os)
                                    replaced_os = True
                                    break
                            if replaced_os:
                                break

                        # if the CPE is not stored yet in any way, append the current OS to the list of potential OSes
                        if not found_supstring and not replaced_one:
                            potential_oses.append({"name": service_elem["name"], "cpes": service_elem[cpes],
                                "accuracy": "100", "type": service_elem.get("devicetype", "")})
                    else:
                        # if there is no CPE, add the OS without a CPE
                        potential_oses.append({"name": service_elem["name"], "accuracy": "100", "type": service_elem.get("devicetype", "")})


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

                    if "cpes" in osclass:
                        for cpe in osclass["cpes"]:
                            found_dupl = False
                            if potential_oses:
                                for pot_os in potential_oses:
                                    if any(cpe == pot_cpe for pot_cpe in pot_os["cpes"]):
                                        found_dupl = True
                                        break

                            if not found_dupl:
                                potential_oses.append({"name": name, "cpes": osclass["cpes"],
                                    "accuracy": osclass["accuracy"], "type": osclass.get("type", "")})
                                break
                    else:
                        if not any(name == pot_os["name"] for pot_os in potential_oses):
                            potential_oses.append({"name": name, "cpes": [],"accuracy": osclass["accuracy"],
                                "type": osclass.get("type", "")})

    add_potential_oses_from_service("os_si")
    add_potential_oses_from_service("os_smb_discv")

    # compute similarities of potential OSes to matching string
    is_os, highest_sim, = None, -1
    for pot_os in potential_oses:
        sim = util.compute_cosine_similarity(matching_string, pot_os["name"].lower())
        if "cpes" in pot_os:
            highest_cpe_sim = max(util.compute_cosine_similarity(matching_string, cpe.lower()) for cpe in pot_os["cpes"])
            sim = (sim + highest_cpe_sim) / 2

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
