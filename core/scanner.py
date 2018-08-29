import copy
import importlib
import inspect
import json
import os
import shutil
import sys
import threading
from typing import Callable

import module_seeker
import utility as util

SCAN_OUT_DIR = "scan_results"
AGGR_GROUP_FILE = "aggregation_groups.json"
AGGR_OPTION_FILE = "aggregation_options.json"
SHOW_PROGRESS_SYMBOLS = ["\u2502", "\u2571", "\u2500", "\u2572", "\u2502", "\u2571", "\u2500", "\u2572"]
SCANNER_JOIN_TIMEOUT = 0.38
DEFAULT_TRUSTWORTHINESS = 3
GROUP_SIM_THRES = 0.95  # barely tested value

class Scanner():

    def __init__(self, networks: list, omit_networks: list, config: dict, ports: list, output_dir: str,
                online_only: bool, verbose: bool, logfile: str, scan_results: list, analysis_only: bool):
        """
        Create a Scanner object with the given networks and output_directory

        :param network: A list of strings representing the networks to analyze
        :param omit_networks: A list of networks as strings to omit from the analysis
        :param config: A dict with config parameters in it
        :param ports: A list of port expressions
        :param output_dir: A string specifying the output directory of the analysis
        :param online_only: Specifying whether to look up information only online (where applicable)
        :param verbose: Specifying whether to provide verbose output or not
        :param logfile: a logfile for logging information
        :param scan_results: additional scan results to include in the final result
        :param analysis_only: Whether to only do an analysis with the specified scan results
        """
        self.networks = networks
        self.omit_networks = omit_networks
        self.config = config
        self.output_dir = output_dir
        self.online_only = online_only
        self.scanner_modules = module_seeker.find_all_scanners_modules()
        self.verbose = verbose
        self.ports = ports
        self.logfile = logfile
        self.logger = util.get_logger(__name__, logfile)
        self.add_scan_results = scan_results
        self.analysis_only = analysis_only

        if "default_trust" in self.config["core"]:
            try:
                self.default_trust = float(self.config["core"]["default_trust"])
            except ValueError:
                self.logger.warning("Default trust value in config is not parseable. Maybe NaN." +
                    "Setting default trust value to %d ." % DEFAULT_TRUSTWORTHINESS)
                self.default_trust = DEFAULT_TRUSTWORTHINESS

    def conduct_module_scans(self):
        """
        Do the different module scans
        """

        if not self.networks:
            self.logger.info("No target networks were specified. Skipping module scanning.")
            return

        # util.hide_cursor()  # hide cursor
        if len(self.networks) == 1:
            self.logger.info("Starting network scans for '%s'" % self.networks[0])
            print(util.BRIGHT_BLUE + "Starting network scans for '%s':" % self.networks[0])
        else:
            self.logger.info("Starting network scans")
            print(util.BRIGHT_BLUE + "Starting network scans:")
        if len(self.scanner_modules) == 1:
            self.logger.info("1 scanner module has been found")
        else:
            self.logger.info("%d scanner modules have been found" % len(self.scanner_modules))
        self.logger.debug("The following scanner modules have been found: %s"
            % ", ".join(self.scanner_modules))

        # iterate over all available scanner modules
        for i, scanner_module_path in enumerate(self.scanner_modules):
            # get scanner module name
            scanner_module = scanner_module_path.replace(os.sep, ".")
            scanner_module = scanner_module.replace(".py", "")
            module_no_prefix = scanner_module.replace("modules.scanner.", "", 1)

            # import the respective python module
            module = importlib.import_module(scanner_module)

            # change into the module's directory
            main_cwd = os.getcwd()
            module_dir = os.path.dirname(scanner_module_path)
            os.chdir(module_dir)

            # set the module's scan parameters (e.g. network, ports, etc.)
            self.set_module_parameters(module)

            # conduct the module's scan
            self.logger.info("Starting scan %d of %d - %s " % (i+1, len(self.scanner_modules), module_no_prefix))
            scan_info = []
            scan_thread = threading.Thread(target=module.conduct_scan, args=(scan_info,))

            scan_thread.start()
            # TODO: Check for TTY (https://www.tutorialspoint.com/python/os_isatty.htm or other)
            show_progress_state = 0
            while scan_thread.is_alive():
                scan_thread.join(timeout=SCANNER_JOIN_TIMEOUT)
                print(util.GREEN + "Conducting scan %d of %d - " % (i+1, len(self.scanner_modules)), end="")
                print(util.SANE + module_no_prefix + "  ", end="")
                print(util.YELLOW + SHOW_PROGRESS_SYMBOLS[show_progress_state])

                util.clear_previous_line()
                if (show_progress_state + 1) % len(SHOW_PROGRESS_SYMBOLS) == 0:
                    show_progress_state = 0
                else:
                    show_progress_state += 1

            if scan_info and len(scan_info[0]) == 2:
                result, created_files = scan_info[0]
            else:
                self.logger.warning("Scanner module '%s' delivered an unprocessable result. " % scanner_module +
                    "Its results have been discarded.")
                result, created_files = {}, []

            # change back into the main directory
            os.chdir(main_cwd)

            # create output directory for this module's scan results
            module_output_dir = os.path.join(self.scan_result_out_dir, os.sep.join(module_no_prefix.split(".")[:-1]))
            os.makedirs(module_output_dir, exist_ok=True)

            # process this module's scan results
            if isinstance(result, str):  # if scanner module provides json output
                # add result file to created_files (in case module has not)
                created_files = set(created_files)
                created_files.add(result)
                result_path = result
                if not os.path.isabs(result_path):
                    result_path = os.path.join(module_dir, result_path)

                # parse the json output into a python dict
                with open(result_path) as f:
                    scan_result = json.load(f)
                    if not "trust" in scan_result:
                        scan_result["trust"] = self.default_trust
                    self.results[scanner_module] = scan_result
            elif isinstance(result, dict):  # if scanner module provides output as python dict
                if not "trust" in result:
                    result["trust"] = self.default_trust
                scan_result_path = os.path.join(module_output_dir, "result.json")
                with open(scan_result_path, "w") as f:  # write dict output to json file
                    f.write(json.dumps(result, ensure_ascii=False, indent=3))
                self.results[scanner_module] = result
            else:  # if result cannot be processed, skip this module
                print(util.RED + "Warning: results of scan from file '%s' could not be used.\n"
                    "Only JSON files or python dicts can be used." % scanner_module_path)

            # move all created files into the output directory of the current module
            if created_files:
                for file in created_files:
                    rel_dir = os.path.dirname(file)
                    if os.path.isabs(rel_dir):
                        rel_dir = path.relpath(rel_dir, os.path.abspath(module_dir))
                    file_out_dir = os.path.join(module_output_dir, rel_dir)
                    os.makedirs(file_out_dir, exist_ok=True)
                    file_out_path = os.path.join(file_out_dir, os.path.basename(file))
                    if os.path.isabs(file) and os.path.isfile(file):
                        shutil.move(file, file_out_path)
                    else:
                        abs_file = os.path.join(module_dir, file)
                        if os.path.isfile(abs_file):
                            shutil.move(abs_file, file_out_path)

            self.logger.info("Scan %d of %d done" % (i+1, len(self.scanner_modules)))

        if len(self.scanner_modules) == 1:
            print(util.GREEN + "Scan completed.")
        else:
            print(util.GREEN + "All %d scans completed." % len(self.scanner_modules))
        print(util.SANE)
        self.logger.info("All scans completed")

    def include_additional_scan_results(self):
        """
        Include additional scan results given by the user
        """

        if self.add_scan_results:
            self.logger.info("Including additional scan results: %s" % ", ".join(self.add_scan_results))
            add_results_dir = os.path.join(self.scan_result_out_dir, "add_scan_results")
            os.makedirs(add_results_dir, exist_ok=True)
            # Iterate over every given file containing a scan result
            for filepath in self.add_scan_results:
                scan_result = None
                if not os.path.isfile(filepath):
                    self.logger.warning("Specified scan result '%s' is not a file" % filepath)
                try:
                    # Find a unique name for the file when it is copied to the result directory
                    copy_name = os.path.basename(filepath)
                    copy_filepath = os.path.join(add_results_dir, os.path.basename(filepath))
                    i = 1
                    while os.path.isfile(copy_filepath):
                        alt_name, ext = os.path.splitext(os.path.basename(copy_filepath))
                        if not alt_name.endswith("_%d" % i):
                            if alt_name.endswith("_%d" % (i-1)):
                                alt_name = alt_name[:alt_name.rfind("_%d" % (i-1))]
                            copy_filepath = os.path.join(add_results_dir, alt_name + "_%d" % i + ext)
                        i += 1
                    # Copy and load the scan result
                    shutil.copyfile(filepath, copy_filepath)
                    with open(copy_filepath) as f:
                        try:
                            scan_result = json.load(f)
                        except json.decoder.JSONDecodeError:
                            self.logger.warning("JSON of scan result stored in '%s' cannot be parsed." % filepath)
                            continue
                except IOError:
                    self.logger.warning("Specified scan result '%s' cannot be opened" % filepath)

                # If the scan result is valid, include it
                if scan_result:
                    if not "trust" in scan_result:
                        scan_result["trust"] = self.default_trust
                    if len(self.networks) == 1:  # not in single network mode
                        util.del_hosts_outside_net(scan_result, self.networks[0])
                    self.results[filepath] = scan_result
            self.logger.info("Done.")

    def conduct_scans(self):
        """
        Conduct all available scans and accumulate potentially conflicting results into one.

        :return: A dict having the host IPs as keys and their scan results as values
        """

        self.results = {}
        self.logger.info("Starting scanning phase")
        # create the output directory for all scan results
        self.scan_result_out_dir = os.path.join(self.output_dir, SCAN_OUT_DIR)
        os.makedirs(self.scan_result_out_dir, exist_ok=True)
        self.include_additional_scan_results()
        if not self.analysis_only:
            self.conduct_module_scans()
        self.logger.info("Aggregating results")
        self.result = self.construct_result()
        self.remove_trust_values()

        # "sort" results by IP
        sorted_result = {}
        for k_ip in sorted(self.result, key=lambda ip: util.ip_str_to_int(ip)):
            sorted_result[k_ip] = self.result[k_ip]
        self.result = sorted_result

        result_file = os.path.join(self.scan_result_out_dir, "results.json")
        with open(result_file, "w") as f:
            f.write(json.dumps(self.result, ensure_ascii=False, indent=3))
        # self.remove_trust_values()
        self.logger.info("Done")
        self.logger.info("Network scans completed")
        # util.show_cursor()  # show cursor again
        return self.result

    def remove_trust_values(self):
        """
        Remove all potential "trust" fields included in the scan result
        stored in "self.result".
        """
        def remove_in_protocol(protocol: str):
            """
            Remove the trust values stored under the given transport protocol.
            """
            if protocol in host:
                if "trust" in host[protocol]:
                    del host[protocol]["trust"]

                for portid, portinfo in host[protocol].items():
                    if "trust" in portinfo:
                        del portinfo["trust"]

        if "trust" in self.result:
            del self.result["trust"]

        for ip, host in self.result.items():
            if "trust" in host:
                del host["trust"]

            if "os" in host and "trust" in host["os"]:
                del host["os"]["trust"]

            remove_in_protocol("tcp")
            remove_in_protocol("udp")


    def set_module_parameters(self, module):
        """
        Set the given modules's scan parameters depening on which parameters it has declared.

        :param module: the module whose scan parameters to set
        """

        # execute the scanning function of the module and save result
        all_module_attributes = [attr_tuple[0] for attr_tuple in inspect.getmembers(module)]

        if "NETWORKS" in all_module_attributes:
            module.NETWORKS = self.networks

        if "OMIT_NETWORKS" in all_module_attributes:
            module.OMIT_NETWORKS = self.omit_networks

        if "VERBOSE" in all_module_attributes:
            module.VERBOSE = self.verbose

        if "PORTS" in all_module_attributes:
            module.PORTS = self.ports

        if "HOSTS" in all_module_attributes:
            if not self.hosts:
                controller.extend_networks_to_hosts()
            module.HOSTS = self.hosts

        if "ONLINE_ONLY" in all_module_attributes:
            module.ONLINE_ONLY = self.online_only

        if "LOGFILE" in all_module_attributes:
            module.LOGFILE = self.logfile

        if "CONFIG" in all_module_attributes:
            module.CONFIG = self.config.get(module.__name__, {})

        if "CORE_CONFIG" in all_module_attributes:
            module.CORE_CONFIG = copy.deepcopy(self.config.get("core", {}))


    def construct_result(self):
        """
        Accumulate the results from all the different scanner modules into one scanning result.

        :return: a dict having host IPs as keys and their scan results as values
        """

        ##############################################################################
        ######## Function definitions before the main construct_result() code ########
        ##############################################################################

        def group_and_reduce():
            """
            First groups all the different OS and port information of every host
            retrieved from the different scanning modules into groups that contain
            similar items. For example, "OS: macOS 10.10 is" grouped together with
            "macOS 10.10.12".
            Next, these groups are reduced / aggregated to one entry each. This
            can be done in several ways. Currently supported are: 1. Reducing
            to the item with the highest trust value; 2. Reducing to the most
            specific entry and giving it an aggregated trust value, based on all
            trust values in its group.
            """

            ####################################################################
            ######## Definition of functions used by group_and_reduce() ########
            ####################################################################

            def group_in(group: list, list_groups: list):
                """
                Check if there exists a group in the second list parameter
                that contains all items in the given group (first list).

                :param group: the group to check whether all its items are already
                in a group contained in list_groups
                :param list_groups: a list of item groups
                :return: True if there is a group in list_groups that contains all
                items in group, False otherwise
                """

                for l_group in list_groups:
                    group_in = True
                    # check if every item of group exists in l_group
                    for item in group:
                        if not item in l_group:
                            group_in = False
                            break
                    if group_in:
                        return True
                return False

            def get_most_specific_entry(group: list):
                """
                Retrieve the most specific entry contained in the given group.

                :param group: the group of which to find its most specific entry
                :return: the given group's most specific entry as a dict
                """

                most_specific_entry = group[0]
                for entry in group[1:]:
                    entry_cpes = entry.get("cpes", [])
                    # Primarily; more specific cpe --> more specific entry 
                    for entry_cpe in entry_cpes:
                        mse_cpes = most_specific_entry.get("cpes", [])
                        if mse_cpes:
                            # if the current most specific entry has a broader cpe
                            if any(util.is_neq_prefix(mse_cpe, entry_cpe) for mse_cpe in mse_cpes):
                                most_specific_entry = entry
                            # if the current most specific entry has the same cpe as the current one ...
                            elif all(entry_cpe == mse_cpe for mse_cpe in mse_cpes):
                                e_name, mse_name = entry.get("name", ""), most_specific_entry.get("name", "")
                                # ... but is broader
                                if util.is_neq_prefix(mse_name, e_name):
                                    most_specific_entry = entry
                        # if current most specific has no cpes ...
                        elif "name" in most_specific_entry:
                            e_name, mse_name = entry.get("name", ""), most_specific_entry["name"]
                            # ... and has a broader name than the current entry (or equal)
                            if mse_name in e_name:
                                most_specific_entry = entry
                        # if current most specific entry has neither cpes nor name
                        else:
                            most_specific_entry = entry

                    # if current entry has no cpes but a name
                    if not entry_cpes and "name" in entry:
                        e_name, mse_name = entry["name"], most_specific_entry.get("name", "")
                        if util.is_neq_prefix(mse_name, e_name):
                            # if current most specific entry does not have only cpes
                            if not (mse_name == "" and "cpes" in most_specific_entry):
                                most_specific_entry = entry
                return most_specific_entry

            def aggregate_group_by_trust_max(group: list):
                """
                Reduce the given group to the item with the highest trust value.

                :param group: the group to reduce
                """

                return max(group, key=lambda member: member["trust"])

            def aggregate_group_by_trust_aggregation(group: list):
                """
                Reduce the given group to its most specific entry and giving it a
                trust value based on all trust values contained in the group.

                :param group: the group to reduce
                """

                most_specific_entry = copy.deepcopy(get_most_specific_entry(group))
                trust_sum = sum([entry["trust"] for entry in group])
                # The following equation is rather preliminary and was created in a way
                # that "it makes sense" for simple cases. 
                aggr_trust = (trust_sum * 0.46 / len(group)) * (1 + (len(group)**0.59))
                most_specific_entry["trust"] = aggr_trust
                return most_specific_entry

            def aggregate_group(group: list):
                """
                Reduce the given group based on the algorithm specified by the
                respective configuration parameter.

                :param group: the group to reduce
                """

                if not group:
                    return {}
                elif len(group) == 1:
                    return group[0]
                else:
                    # Check the config for aggregation scheme
                    if not "scan_aggregation_scheme" in self.config["core"]:
                        # If no config entry available, use trust aggregation scheme
                        return aggregate_group_by_trust_aggregation(group)
                    elif self.config["core"]["scan_aggregation_scheme"] == "TRUST_AGGR":
                        return aggregate_group_by_trust_aggregation(group)
                    elif self.config["core"]["scan_aggregation_scheme"] == "TRUST_MAX":
                        return aggregate_group_by_trust_max(group)
                    else:
                        return aggregate_group_by_trust_aggregation(group)

            def add_trust():
                """
                Add a trust value to every OS and port entry of the current host.
                """

                nonlocal host, module_trust_rating

                def add_to_ports(protocol: str):
                    """
                    Add trust values to the ports used by the given transport protocol.
                    """
                    if protocol in host:
                        for portid, port in host[protocol].items():
                            if "trust" not in port:
                                if "trust" in host[protocol]:
                                    port["trust"] = host[protocol]["trust"]
                                elif "trust" in host:
                                    port["trust"] = host["trust"]
                                else:
                                    port["trust"] = module_trust_rating

                if "os" in host and "trust" not in host["os"]:
                    if "trust" in host:
                        host["os"]["trust"] = host["trust"]
                    else:
                        host["os"]["trust"] = module_trust_rating

                add_to_ports("tcp")
                add_to_ports("udp")

            def group_item(item: dict, dest: dict, dest_key: str, iter_access_func: Callable[[dict], dict]):
                """
                Build a group based on the given item. The group consists of all entries that are similar to
                the given item. The mentioned entries are provided by all modules' scan results.

                :param item: the base item to group other items with
                :param dest: the dictionary to store the resulting group in
                :param dest_key: the key under which to append the resulting group in dest
                :param iter_access_func: a function defining how to access compatible entries
                from other modules.
                """

                nonlocal ip, host, groups, cpy_results, module
                item_group = [item]  # group initially exists of base item
                for module_iter, result_iter in cpy_results.items():  # iterate over every scan result
                    if module_iter == module:  # skip current module
                        continue

                    if ip in result_iter:  # match current host / ip
                        try:
                            # try to access the iterating module's host item that
                            # is equivalent to the base item given as function parameter
                            item_iter = iter_access_func(result_iter[ip])
                        except KeyError:
                            continue

                        addded_to_group = False
                        # check if iter_item has a cpe that is broader than one of the current host's cpes
                        for cpe in item.get("cpes", []):
                            if any(cpe_iter in cpe for cpe_iter in item_iter.get("cpes", [])):
                                item_group.append(item_iter)
                                addded_to_group = True
                                break

                        # if the currently iterating item has not been added yet,
                        # but the base item and current iterating item can be compared by name
                        if not addded_to_group and "name" in item and "name" in item_iter:
                            item_str, item_iter_str = item["name"], item_iter["name"]
                            # if both have a service field, append it to the name for comparison
                            if "service" in item and "service" in item_iter:
                                item_str += " " + item["service"]
                                item_iter_str += " " + item_iter["service"]

                            # if the two items have prefixed names or are otherwise similar enough to each other
                            if item_iter_str in item_str:
                                item_group.append(item_iter)
                            elif util.compute_cosine_similarity(item_str, item_iter_str) > GROUP_SIM_THRES:
                                item_group.append(item_iter)

                # if list of groups already exists, check whether to append to it
                if dest_key in dest:
                    # if all items of the current group are not already existent in another group
                    if not group_in(item_group, dest[dest_key]):
                        # remove existent groups that are more broad, meaning all of its entries
                        # are contained in the current item_group
                        dest[dest_key][:] = [other for other in dest[dest_key] if not all(o_item in item_group for o_item in other)]
                        dest[dest_key].append(item_group)
                # otherwise create it
                else:
                    dest[dest_key] = [item_group]

            def group_os():
                """
                Group the OS entry of the current host (of the current module)
                with similar entries from other modules.
                """
                if "os" not in host:
                    return
                group_item(host["os"], groups[ip], "os", lambda host: host["os"])

            def group_ports(protocol):
                """
                Group the port entries of the current host (of the current module)
                with similar entries from other modules.
                """
                if protocol not in host:
                    return
                if protocol not in groups[ip]:
                    groups[ip][protocol] = {}

                for portid, port in host[protocol].items():
                    group_item(port, groups[ip][protocol], portid, lambda host: host[protocol][portid])


            ##############################################
            ######## Main group_and_reduce() code ########
            ##############################################

            results = {}
            groups = {}
            # create copy to allow for modification of original while iterating
            cpy_results = copy.deepcopy(self.results)

            for module, result in cpy_results.items():
                # discover the trust rating to give this module's results
                if "trust" in result:
                    module_trust_rating = result["trust"]
                    del result["trust"]
                else:
                    module_trust_rating = self.default_trust

                for ip, host in result.items():
                    if ip not in groups:
                        groups[ip] = {}
                    add_trust()

                    if "os" in host:
                        group_os()

                    if "tcp" in host:
                        group_ports("tcp")

                    if "udp" in host:
                        group_ports("udp")

            # store the intermediary result of all created groups in a file
            group_out_file = os.path.join(self.scan_result_out_dir, AGGR_GROUP_FILE)
            with open(group_out_file, "w") as f:
                f.write(json.dumps(groups, ensure_ascii=False, indent=3))
            self.logger.info("Grouped similar scan results and wrote result to %s" % group_out_file)

            # aggregate / reduce groups to single item
            for ip, host in groups.items():
                results[ip] = host

                if "os" in host:
                    os_items = []
                    for os_group in host["os"]:
                        os_items.append(aggregate_group(os_group))
                    results[ip]["os"] = os_items

                for protocol in {"tcp", "udp"}:
                    if protocol in host:
                        for portid, port_groups in host[protocol].items():
                            port_items = []
                            for port_group in port_groups:
                                port_items.append(aggregate_group(port_group))
                            results[ip][protocol][portid] = port_items

            # store the intermediary result of the aggregated groups in a file
            option_out_file = os.path.join(self.scan_result_out_dir, AGGR_OPTION_FILE)
            with open(option_out_file, "w") as f:
                f.write(json.dumps(results, ensure_ascii=False, indent=3))
            self.logger.info("Aggregated the individual groups and wrote result to %s" % option_out_file)

            return results

        def aggregate_results():
            """
            Aggregate the "grouped and reduced" results to one final result. The
            aggregation is done by selecting the entry with the biggest trust value
            as final result.
            """

            def select_port_entries(protocol: str):
                """
                Aggregate the intermediary results of the ports used by the
                given transport protocol to one final result.
                """
                nonlocal host
                if protocol in host:
                    for portid, port_entries in host[protocol].items():
                        host[protocol][portid] = max(port_entries, key=lambda entry: entry["trust"])

            processed_results = group_and_reduce()
            for ip, host in processed_results.items():
                if "os" in host:
                    host["os"] = max(host["os"], key=lambda entry: entry["trust"])
                select_port_entries("tcp")
                select_port_entries("udp")
            return processed_results


        ##############################################
        ######## Main construct_result() code ########
        ##############################################

        if len(self.results) == 0:
            results = {}
        elif len(self.results) == 1:
            results = self.results[list(self.results.keys())[0]]
        else:
            results = aggregate_results()

        # make sure every host contains an "os", "tcp" and "udp" field
        for k, v in results.items():
            if k != "trust":
                if not "os" in v:
                    v["os"] = {}
                if not "tcp" in v:
                    v["tcp"] = {}
                if not "udp" in v:
                    v["udp"] = {}

        return results

    def extend_networks_to_hosts(self):
        """
        Parse the network strings of the main network, the additional networks and the networks
        to omit into an enumeration of all hosts to analyse. 
        """

        def add_to_hosts(network):
            hosts = util.extend_network_to_hosts(network)
            if isinstance(hosts, list):
                self.hosts |= set(hosts)
            else:
                self.hosts.add(hosts)

        for net in self.networks:
            add_to_hosts(net)

        for network in self.omit_networks:
            hosts = util.extend_network_to_hosts(network)
            if isinstance(hosts, list):
                self.hosts = self.hosts - set(hosts)
            else:
                self.hosts.remove(hosts)

        self.hosts = list(self.hosts)