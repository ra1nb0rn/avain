import copy
import json
import os
import pprint
from typing import Callable

import core.utility as util
from core.result_processor import ResultProcessor

AGGR_GROUP_FILE = "aggregation_groups.json"
AGGR_OPTION_FILE = "aggregation_options.json"
DEFAULT_TRUSTWORTHINESS = 3

class ScanResultProcessor(ResultProcessor):

    def __init__(self, output_dir: str, config: dict, results: dict = None):
        super().__init__(output_dir, results)
        self.config = config

        if "default_trust" in self.config["core"]:
            try:
                self.default_trust = float(self.config["core"]["default_trust"])
            except ValueError:
                self.logger.warning("Default trust value in config is not parseable. Maybe NaN." +
                                    "Setting default trust value to %d .", DEFAULT_TRUSTWORTHINESS)
                self.default_trust = DEFAULT_TRUSTWORTHINESS

    def add_to_results(self, result_id: str, result):
        if not "trust" in result:
            result["trust"] = self.default_trust
        self.results[result_id] = result

    @staticmethod
    def print_result(result: dict):
        pprint.pprint(result)

    @staticmethod
    def print_aggr_result(result):
        ScanResultProcessor.print_result(result)

    @staticmethod
    def store_result(result: dict, filepath: str):
        """Store the given result at the specified location"""

        ScanResultProcessor.store_json_convertable_result(result, filepath)

    @staticmethod
    def store_aggregated_result(aggr_result, filepath: str):
        """Store the given aggregated result at the specified location"""

        ScanResultProcessor.store_json_convertable_result(aggr_result, filepath)

    def parse_result_file(self, filepath: str):
        return self.parse_result_from_json_file(filepath)

    def aggregate_results(self):
        """
        Accumulate all retrieved scan results to one scan result.

        :return: a dict having host IPs as keys and their scan results as values
        """

        if not self.results:
            result = {}
        elif len(self.results) == 1:
            result = copy.deepcopy(self.results[list(self.results.keys())[0]])
        else:
            result = self._aggregate_results()

        # make sure every host contains an "os", "tcp" and "udp" field
        for key, val in result.items():
            if key != "trust":
                if not "os" in val:
                    val["os"] = {}
                if not "tcp" in val:
                    val["tcp"] = {}
                if not "udp" in val:
                    val["udp"] = {}

        ScanResultProcessor.remove_trust_values(result)

        # check if OS and port info are separated into lists
        for _, host in result.items():
            if "os" in host:
                if not isinstance(host["os"], list):
                    host["os"] = [host["os"]]
            for protocol in ("tcp", "udp"):
                if protocol in host:
                    for portid, portinfos in host[protocol].items():
                        if not isinstance(portinfos, list):
                            host[protocol][portid] = [portinfos]

        return ResultProcessor.sort_result_by_ip(result)


    def _group_by_product(self, intermediate_results):
        """
        Group the intermediate results by their CPE product value (if it exists). Two items
        are grouped if they have the same part and vendor and the cosine similarity of their
        product strings is greater than 0.45.

        :param intermediate_results: the intermediate results after first group and reduce
        :return: the intermediate results grouped by their CPE product
        """
        # CPE 2.2 notation: cpe:/{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}
        
        def group_item_by_product(item, groups):
            for group in groups:
                for gitem in group:
                    for cpe in item.get("cpes", []):
                        for gcpe in gitem.get("cpes", []):
                            # [5:] to remove leading cpe:/
                            cpe_split, gcpe_split = cpe[5:].split(":"), gcpe[5:].split(":")
                            if len(cpe_split) > 2 and len(gcpe_split) > 2:
                                if cpe_split[0] == gcpe_split[0] and cpe_split[1] == gcpe_split[1]:
                                    if util.compute_cosine_similarity(cpe_split[2], gcpe_split[2], r"[^\W_]+") > 0.45:
                                        group.append(item)
                                        return True
            return False

        def group_protocol(protocol):
            nonlocal ip, host, product_groups

            if protocol in host:
                if protocol not in product_groups:
                    product_groups[ip][protocol] = {}

                for portid, port_nodes in host[protocol].items():
                    port_groups = []
                    for port_node in port_nodes:
                        if not group_item_by_product(port_node, port_groups):
                            port_groups.append([port_node])

                    product_groups[ip][protocol][portid] = port_groups


        product_groups = {}
        for ip, host in intermediate_results.items():
            if ip not in product_groups:
                product_groups[ip] = {}

            if "os" in host:
                os_groups = []
                for os_node in host["os"]:
                    if not group_item_by_product(os_node, os_groups):
                        os_groups.append([os_node])

                product_groups[ip]["os"] = os_groups

            group_protocol("tcp")
            group_protocol("udp")

        return product_groups


    def _aggregate_results(self):
        """
        Aggregate the "grouped and reduced" results to one final result. The
        aggregation is done depending on the config value for "scan_result_aggr_scheme".

        Value "SINGLE"   : the single result with the highest trust rating is chosen
        Value "MULTIPLE" : the results are returned without further processing
        Value "FILTER"   : similar products are filtered out, i.e. out of macOS 10.12
                           and macOS 10.13, only the one with the highest trust rating
                           is returned
        """ 

        processed_results = self._group_and_reduce()

        if self.config["core"].get("scan_result_aggr_scheme", "").upper() == "MULTIPLE":
            return processed_results

        if self.config["core"].get("scan_result_aggr_scheme", "").upper() == "SINGLE":
            for _, host in processed_results.items():
                if "os" in host:
                    host["os"] = [max(host["os"], key=lambda entry: entry["trust"])]

                for protocol in ("tcp", "udp"):
                    if protocol in host:
                        for portid, port_entries in host[protocol].items():
                            host[protocol][portid] = [max(port_entries, key=lambda entry: entry["trust"])]
            return processed_results

        if self.config["core"].get("scan_result_aggr_scheme", "FILTER").upper() == "FILTER":
            product_groups = self._group_by_product(processed_results)

            for _, host in product_groups.items():
                if "os" in host:
                    os_items = []
                    for group in host["os"]:
                        os_items.append(max(group, key=lambda entry: entry["trust"]))
                    host["os"] = os_items

                for protocol in ("tcp", "udp"):
                    if protocol in host:
                        for portid, port_groups in host[protocol].items():
                            port_items = []
                            for group in port_groups:
                                port_items.append(max(group, key=lambda entry: entry["trust"]))
                            host[protocol][portid] = port_items

            return product_groups

        util.printit("Warning: unknown config value for 'scan_result_aggr_scheme'", color=util.RED)
        return {}


    def _group_and_reduce(self):
        """
        First groups all the different OS and port information of every host
        retrieved from the different scanning modules into groups that contain
        similar items. For example, "OS: macOS 10.10 is" grouped together with
        "macOS 10.10.4".
        Next, these groups are reduced / aggregated to one entry each. This
        can be done in several ways. Currently supported are: 1. Reducing
        to the item with the highest trust value; 2. Reducing to the most
        specific entry and giving it an aggregated trust value, based on all
        trust values in its group.
        """

        def group_os():
            """
            Group the OS entry of the current host (of the current module)
            with similar entries from other modules.
            """
            nonlocal ip, host, module
            if "os" not in host:
                return
            if not "os" in groups[ip]:
                groups[ip]["os"] = []

            if isinstance(host["os"], list):
                for item in host["os"]:
                    self._group_item(ip, module, item, groups[ip]["os"], lambda host: host["os"])
            else:
                self._group_item(ip, module, host["os"], groups[ip]["os"], lambda host: host["os"])

        def group_ports(protocol):
            """
            Group the port entries of the current host (of the current module)
            with similar entries from other modules.
            """
            nonlocal ip, host, module
            if protocol not in host:
                return
            if protocol not in groups[ip]:
                groups[ip][protocol] = {}

            for portid, port in host[protocol].items():
                if not portid in groups[ip][protocol]:
                    groups[ip][protocol][portid] = []

                if isinstance(port, list):
                    for item in port:
                        self._group_item(ip, module, item, groups[ip][protocol][portid],
                                         lambda host: host[protocol][portid])
                else:
                    self._group_item(ip, module, port, groups[ip][protocol][portid],
                                     lambda host: host[protocol][portid])


        # create the different groups
        results = {}
        groups = {}
        for module, result in self.results.items():
            # discover the trust rating to give this module's results
            if "trust" in result:
                module_trust_rating = result["trust"]
                del result["trust"]
            else:
                module_trust_rating = self.default_trust

            for ip, host in result.items():
                if ip not in groups:
                    groups[ip] = {}
                ScanResultProcessor._add_trust(host, module_trust_rating)

                if "os" in host:
                    group_os()

                if "tcp" in host:
                    group_ports("tcp")

                if "udp" in host:
                    group_ports("udp")

        # store the intermediary result of all created groups in a file
        group_out_file = os.path.join(self.output_dir, AGGR_GROUP_FILE)
        with open(group_out_file, "w") as file:
            file.write(json.dumps(groups, ensure_ascii=False, indent=3))
        self.logger.info("Grouped similar scan results and wrote result to %s", group_out_file)

        # aggregate / reduce groups to single item
        for ip, host in groups.items():
            results[ip] = host

            if "os" in host:
                os_items = []
                for os_group in host["os"]:
                    os_items.append(self._aggregate_group(os_group))
                results[ip]["os"] = os_items

            for protocol in {"tcp", "udp"}:
                if protocol in host:
                    for portid, port_groups in host[protocol].items():
                        port_items = []
                        for port_group in port_groups:
                            port_items.append(self._aggregate_group(port_group))
                        results[ip][protocol][portid] = port_items

        # store the intermediary result of the aggregated groups in a file
        option_out_file = os.path.join(self.output_dir, AGGR_OPTION_FILE)
        with open(option_out_file, "w") as file:
            file.write(json.dumps(results, ensure_ascii=False, indent=3))
        self.logger.info("Aggregated the individual groups and wrote result to %s",
                         option_out_file)

        return results

    @staticmethod
    def _add_trust(host: dict, trust_value: float):
        """
        Add a trust value to every OS and port entry of the current host.
        """

        def add_to_ports(protocol: str):
            """
            Add trust values to the ports used by the given transport protocol.
            """
            if protocol in host:
                for portid, portitems in host[protocol].items():
                    if not isinstance(portitems, list):
                        portitems = [portitems]

                    for port in portitems:
                        if "trust" not in port:
                            if "trust" in host[protocol][portid]:
                                port["trust"] = host[protocol][portid]["trust"]
                            if "trust" in host[protocol]:
                                port["trust"] = host[protocol]["trust"]
                            elif "trust" in host:
                                port["trust"] = host["trust"]
                            else:
                                port["trust"] = trust_value

        if "os" in host:
            ositems = host["os"] if isinstance(host["os"], list) else [host["os"]]

            for ositem in ositems:
                if "trust" not in ositem:
                    if "trust" in host["os"]:
                        ositem["trust"] = host["os"]["trust"]
                    if "trust" in host:
                        ositem["trust"] = host["trust"]
                    else:
                        ositem["trust"] = trust_value

        add_to_ports("tcp")
        add_to_ports("udp")

    @staticmethod
    def remove_trust_values(result: dict):
        """
        Remove all potential "trust" fields stored in the given scan result
        """

        def remove_in_protocol(protocol: str):
            """
            Remove the trust values stored under the given transport protocol.
            """
            if protocol in host:
                if "trust" in host[protocol]:
                    del host[protocol]["trust"]

                for _, portinfos in host[protocol].items():
                    for portinfo in portinfos:
                        if "trust" in portinfo:
                            del portinfo["trust"]

        if "trust" in result:
            del result["trust"]

        for _, host in result.items():
            if "trust" in host:
                del host["trust"]

            if "os" in host:
                for osinfo in host["os"]:
                    if "trust" in osinfo:
                        del osinfo["trust"]

            remove_in_protocol("tcp")
            remove_in_protocol("udp")

    def _group_item(self, ip: str, module, item: dict, dest: dict,
                    iter_access_func: Callable[[dict], dict]):
        """
        Build a group based on the given item. The group consists of all entries that are
        similar to the given item. The mentioned entries are provided by all modules'
        scan results.

        :param item: the base item to group other items with
        :param dest: the dictionary to store the resulting group in
        :param iter_access_func: a function defining how to access compatible entries
        from other modules.
        """

        item_group = [item]  # group initially exists of base item
        # iterate over every scan result
        for module_iter, result_iter in self.results.items():
            if module_iter == module:  # skip current module
                continue

            if ip in result_iter:  # match current host / ip
                try:
                    # try to access the iterating module's host item that
                    # is equivalent to the base item given as function parameter
                    items_iter = iter_access_func(result_iter[ip])
                except KeyError:
                    continue

                if not isinstance(items_iter, list):
                    items_iter = [items_iter]

                for item_iter in items_iter:
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

                        # if the two items have prefixed names
                        if item_iter_str in item_str:
                            item_group.append(item_iter)

        # if all items of the current group are not already existent in another group
        if not ScanResultProcessor._group_in(item_group, dest):
            # remove existent groups that are more broad, meaning all of its entries
            # are contained in the current item_group
            dest[:] = [other for other in dest if not
                       all(o_item in item_group for o_item in other)]
            dest.append(item_group)

    @staticmethod
    def _get_most_specific_group_entry(group: list):
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
                    if any(util.neq_in(mse_cpe, entry_cpe) for mse_cpe in mse_cpes):
                        most_specific_entry = entry
                    # if the current most specific entry has the same cpe as the current one
                    elif all(entry_cpe == mse_cpe for mse_cpe in mse_cpes):
                        e_name = entry.get("name", "")
                        mse_name = most_specific_entry.get("name", "")
                        # ... but is broader
                        if util.neq_in(mse_name, e_name):
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
                if util.neq_in(mse_name, e_name):
                    # if current most specific entry does not have only cpes
                    if not (mse_name == "" and "cpes" in most_specific_entry):
                        most_specific_entry = entry
        return most_specific_entry

    @staticmethod
    def _group_in(group: list, list_groups: list):
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
                if item not in l_group:
                    group_in = False
                    break
            if group_in:
                return True
        return False

    def _aggregate_group(self, group: list):
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
        if not "scan_trust_aggr_scheme" in self.config["core"]:
            # If no config entry available, use trust aggregation scheme
            return ScanResultProcessor._aggregate_group_by_trust_aggregation(group)
        if self.config["core"]["scan_trust_aggr_scheme"] == "TRUST_AGGR":
            return ScanResultProcessor._aggregate_group_by_trust_aggregation(group)
        if self.config["core"]["scan_trust_aggr_scheme"] == "TRUST_MAX":
            return ScanResultProcessor._aggregate_group_by_trust_max(group)
        return ScanResultProcessor._aggregate_group_by_trust_aggregation(group)

    ################################################
    #### Different group aggregation algorithms ####
    ################################################

    @staticmethod
    def _aggregate_group_by_trust_max(group: list):
        """
        Reduce the given group to the item with the highest trust value.

        :param group: the group to reduce
        """

        return max(group, key=lambda member: member["trust"])

    @staticmethod
    def _aggregate_group_by_trust_aggregation(group: list):
        """
        Reduce the given group to its most specific entry and giving it a
        trust value based on all trust values contained in the group.

        :param group: the group to reduce
        """
        grouping_strength = 0.675
        most_specific_entry = copy.deepcopy(ScanResultProcessor._get_most_specific_group_entry(group))
        trust_sum = sum([entry["trust"] for entry in group])
        # The following equation is rather preliminary and was created in a way
        # that "it makes sense" for simple cases.
        aggr_trust = trust_sum / (len(group)**grouping_strength)
        most_specific_entry["trust"] = aggr_trust
        return most_specific_entry


    def is_valid_result(result):
        def check_name(node: dict):
            if "name" in node and (not isinstance(node["name"], str)):
                return False
            return True

        def check_cpes(node: dict):
            if "cpes" in node:
                if (not isinstance(node["cpes"], list)):
                    return False
                for cpe in node["cpes"]:
                    if not isinstance(cpe, str):
                        return False
            return True

        def check_protocol(protocol: str):
            nonlocal value

            if protocol in value:
                if not isinstance(value, dict):
                    return False

                for portid, port_node in value[protocol].items():
                    if (not isinstance(portid, str)) and (not isinstance(portid, int)):
                        return False

                    if isinstance(port_node, list):
                        items = port_node
                    else:
                        items = [port_node]

                    for port in items:
                        if not isinstance(port, dict):
                            return False
                        if not check_name(port):
                            return False
                        if not check_cpes(port):
                            return False
                        if "service" in port and not isinstance(port["service"], str):
                            return False
            return True

        if not isinstance(result, dict):
            return False

        for key, value in result.items():
            if (not util.is_ipv4(key)) and (not util.is_ipv6) and (not key == "trust"):
                return False

            if (key == "trust" and (not isinstance(value, float)) and (not isinstance(value, float))
                and (not isinstance(value, str))):
                return False
            else:
                if not isinstance(value, dict):
                    return False

                if "os" in value:
                    if isinstance(value["os"], list):
                        items = value["os"]
                    else:
                        items = [value["os"]]

                    for item in items:
                        if not isinstance(item, dict):
                            return False
                        if not check_name(item):
                            return False
                        if not check_cpes(item):
                            return False

                if not check_protocol("tcp"):
                    return False

                if not check_protocol("udp"):
                    return False

        return True
