import copy
import inspect
import json
import os
from typing import Callable

import core.utility as util
from core.module_manager_feedback import ModuleManagerFeedback
from core.module_manager import ModuleManager

AGGR_GROUP_FILE = "aggregation_groups.json"
AGGR_OPTION_FILE = "aggregation_options.json"
ADDITIONAL_RESULTS_DIR = "add_scan_results"
SCANNER_JOIN_TIMEOUT = 0.38
DEFAULT_TRUSTWORTHINESS = 3
GROUP_SIM_THRES = 0.95  # barely tested value

class Scanner(ModuleManagerFeedback):

    def __init__(self, output_dir: str, config: dict, logfile: str, verbose: bool,
                 add_results: list, networks: list, omit_networks: list, ports: list,
                 analysis_only: bool, online_only: bool):
        """
        Create a Scanner object with the given networks and output directory

        :param output_dir: A string specifying the output directory of the scan
        :param config: The used config
        :param verbose: Specifies whether to provide verbose output or not
        :param logfile: A logfile for logging information
        :param add_results: Additional result files to include into the result
        :param networks: A list of strings representing the networks to scan
        :param omit_networks: A list of networks as strings to omit from the scan
        :param ports: A list of port expressions
        :param analysis_only: Whether to only do an analysis with the specified scan results
        :param online_only: Specifies whether to look up information only online (where applicable)
        """

        self.networks = networks
        self.hosts = []  # only parse network expressions if necessary
        self.omit_networks = omit_networks
        self.ports = ports
        self.analysis_only = analysis_only
        self.online_only = online_only
        super().__init__(output_dir, config, logfile, verbose, add_results)

        if "default_trust" in self.config["core"]:
            try:
                self.default_trust = float(self.config["core"]["default_trust"])
            except ValueError:
                self.logger.warning("Default trust value in config is not parseable. Maybe NaN." +
                                    "Setting default trust value to %d .", DEFAULT_TRUSTWORTHINESS)
                self.default_trust = DEFAULT_TRUSTWORTHINESS

    def _assign_init_values(self):
        modules = ModuleManager.find_all_prefixed_modules("modules/scanner", "scanner_")
        if len(self.networks) == 1:
            run_title_str = "Starting network scans for '%s'" % self.networks[0]
        else:
            run_title_str = "Starting network scans"

        return (modules, "results.json", "scanning", "conduct_scan", "modules.scanner.",
                SCANNER_JOIN_TIMEOUT, run_title_str, True)

    def _assign_add_results_dir(self):
        return ADDITIONAL_RESULTS_DIR

    def _only_result_files(self):
        return self.analysis_only

    def _sort_results(self):
        super()._sort_results_by_ip()

    def _add_to_results(self, module_id, module_result):
        if not "trust" in module_result:
            module_result["trust"] = self.default_trust
        if len(self.networks) == 1:  # not in single network mode
            util.del_hosts_outside_net(module_result, self.networks[0])
        self.results[module_id] = module_result

    def _cleanup(self):
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

                for _, portinfo in host[protocol].items():
                    if "trust" in portinfo:
                        del portinfo["trust"]

        if "trust" in self.result:
            del self.result["trust"]

        for _, host in self.result.items():
            if "trust" in host:
                del host["trust"]

            if "os" in host and "trust" in host["os"]:
                del host["os"]["trust"]

            remove_in_protocol("tcp")
            remove_in_protocol("udp")

    def _set_extra_module_parameters(self, module):
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

        if "PORTS" in all_module_attributes:
            module.PORTS = self.ports

        if "HOSTS" in all_module_attributes:
            if not self.hosts:
                self.extend_networks_to_hosts()
            module.HOSTS = self.hosts

        if "ONLINE_ONLY" in all_module_attributes:
            module.ONLINE_ONLY = self.online_only

    def _construct_result(self):
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
                            # if the current most specific entry has the same cpe as the current one
                            elif all(entry_cpe == mse_cpe for mse_cpe in mse_cpes):
                                e_name = entry.get("name", "")
                                mse_name = most_specific_entry.get("name", "")
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
                if len(group) == 1:
                    return group[0]

                # Check the config for aggregation scheme
                if not "scan_aggregation_scheme" in self.config["core"]:
                    # If no config entry available, use trust aggregation scheme
                    return aggregate_group_by_trust_aggregation(group)
                if self.config["core"]["scan_aggregation_scheme"] == "TRUST_AGGR":
                    return aggregate_group_by_trust_aggregation(group)
                if self.config["core"]["scan_aggregation_scheme"] == "TRUST_MAX":
                    return aggregate_group_by_trust_max(group)
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
                        for _, port in host[protocol].items():
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

            def group_item(item: dict, dest: dict, dest_key: str,
                           iter_access_func: Callable[[dict], dict]):
                """
                Build a group based on the given item. The group consists of all entries that are
                similar to the given item. The mentioned entries are provided by all modules'
                scan results.

                :param item: the base item to group other items with
                :param dest: the dictionary to store the resulting group in
                :param dest_key: the key under which to append the resulting group in dest
                :param iter_access_func: a function defining how to access compatible entries
                from other modules.
                """

                nonlocal ip, host, groups, cpy_results, module
                item_group = [item]  # group initially exists of base item
                # iterate over every scan result
                for module_iter, result_iter in cpy_results.items():
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
                        # check if iter_item has a cpe that is broader
                        # than one of the current host's cpes
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

                            # if the two items have prefixed names or
                            # are otherwise similar enough to each other
                            if item_iter_str in item_str:
                                item_group.append(item_iter)
                            elif (util.compute_cosine_similarity(item_str, item_iter_str) >
                                  GROUP_SIM_THRES):
                                item_group.append(item_iter)

                # if list of groups already exists, check whether to append to it
                if dest_key in dest:
                    # if all items of the current group are not already existent in another group
                    if not group_in(item_group, dest[dest_key]):
                        # remove existent groups that are more broad, meaning all of its entries
                        # are contained in the current item_group
                        dest[dest_key][:] = [other for other in dest[dest_key] if not
                                             all(o_item in item_group for o_item in other)]
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
                    group_item(port, groups[ip][protocol], portid,
                               lambda host: host[protocol][portid])


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
            group_out_file = os.path.join(self.output_dir, AGGR_GROUP_FILE)
            with open(group_out_file, "w") as f:
                f.write(json.dumps(groups, ensure_ascii=False, indent=3))
            self.logger.info("Grouped similar scan results and wrote result to %s", group_out_file)

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
            option_out_file = os.path.join(self.output_dir, AGGR_OPTION_FILE)
            with open(option_out_file, "w") as f:
                f.write(json.dumps(results, ensure_ascii=False, indent=3))
            self.logger.info("Aggregated the individual groups and wrote result to %s",
                             option_out_file)

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
            for _, host in processed_results.items():
                if "os" in host:
                    host["os"] = max(host["os"], key=lambda entry: entry["trust"])
                select_port_entries("tcp")
                select_port_entries("udp")
            return processed_results


        ##############################################
        ######## Main construct_result() code ########
        ##############################################

        if not self.results:
            results = {}
        elif len(self.results) == 1:
            results = self.results[list(self.results.keys())[0]]
        else:
            results = aggregate_results()

        # make sure every host contains an "os", "tcp" and "udp" field
        for key, val in results.items():
            if key != "trust":
                if not "os" in val:
                    val["os"] = {}
                if not "tcp" in val:
                    val["tcp"] = {}
                if not "udp" in val:
                    val["udp"] = {}

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
