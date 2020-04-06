import copy
import json
import os
import pprint

from core.result_processor import ResultProcessor
import core.utility as util

DISCOVERED_URLS_OUTFILE = "discovered_urls.txt"


class WebserverMapProcessor(ResultProcessor):

    def __init__(self, output_dir: str, results: dict = None):
        super().__init__(output_dir, results)

    @staticmethod
    def is_valid_result(result):
        if not isinstance(result, dict):
            return False

        # check every entry for every IP
        for key, value in result.items():
            if (not util.is_ipv4(key)) and (not util.is_ipv6(key)):
                return False

            if not isinstance(value, dict):
                return False

            # check all hosts for every port
            for portid_str, host_group in value.items():
                if not isinstance(portid_str, str):
                    return False
                # check validity of port number
                try:
                    portid = int(portid_str)
                except ValueError:
                    return False
                if not (1 <= portid <= 65535):
                    return False

                if not isinstance(host_group, dict):
                    return False

                # check all pages available for every host, indexed by status codes
                for webhost, node in host_group.items():
                    for status_code_str, pages in node.items():
                        # check validity of status code
                        if not isinstance(status_code_str, str):
                            return False
                        try:
                            status_code = int(status_code_str)
                        except ValueError:
                            return False
                        if not (100 <= status_code < 600):
                            return False

                        # check validity of every web page node
                        for path, page_info in pages.items():
                            if not path.startswith("/"):
                                return False

                            # check validity of keys and their node structure
                            for page_key in page_info:
                                if page_key in ("GET", "POST", "cookies", "instances"):
                                    if not isinstance(page_info[page_key], list):
                                        return False
                                elif not page_key.startswith("misc_info"):
                                    return False

                            # check validity of every instance
                            if "instances" in page_info:
                                for instance in page_info["instances"]:
                                    # check validity of keys and their node structure
                                    if any(ikey not in ("GET", "POST", "cookies") for ikey in instance):
                                        return False
                                    for param_key in ("GET", "POST", "cookies"):
                                        if param_key in instance and not isinstance(instance[param_key], dict):
                                            return False
                                        for k, v in instance[param_key].items():
                                            if not isinstance(k, str):
                                                return False
                                            if not isinstance(v, str):
                                                return False

        return True

    @staticmethod
    def print_result(result: dict):
        pprint.pprint(result)

    @staticmethod
    def print_aggr_result(result):
        WebserverMapProcessor.print_result(result)

    @staticmethod
    def store_result(result: dict, filepath: str):
        """Store the given result at the specified location"""

        WebserverMapProcessor.store_json_convertible_result(result, filepath)

    @staticmethod
    def store_aggregated_result(aggr_result, filepath: str):
        """Store the given aggregated result at the specified location"""

        result = aggr_result
        WebserverMapProcessor.store_json_convertible_result(result, filepath)

    def parse_result_file(self, filepath: str):
        return self.parse_result_from_json_file(filepath)

    def aggregate_results(self):
        """
        Accumulate the results from all the different webserver map analyzers into one.
        Results are aggregated by uniting all the different results.

        :return: the aggregated results
        """

        if not self.results:
            return {}

        if len(self.results) == 1:
            webserver_map = copy.deepcopy(self.results[list(self.results.keys())[0]])
            self.store_discovered_urls(webserver_map)
            return webserver_map

        # unite all webserver map results
        webserver_map = {}
        for _, result in self.results.items():
            for host, port_nodes in result.items():
                if host not in webserver_map:
                    webserver_map[host] = {}

                for portid, domain_nodes in port_nodes.items():
                    if portid not in webserver_map[host]:
                        webserver_map[host][portid] = {}

                    # iterate over different webhosts (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host)
                    for webhost, status_code_nodes in domain_nodes.items():
                        if webhost not in webserver_map[host][portid]:
                            webserver_map[host][portid][webhost] = {}

                        # iterate over status codes and their associated pages
                        for status_code, page_nodes in status_code_nodes.items():
                            if status_code not in webserver_map[host][portid][webhost]:
                                webserver_map[host][portid][webhost][status_code] = {}

                            cur_aggr_node = webserver_map[host][portid][webhost][status_code]
                            for path, page_info in page_nodes.items():
                                # handle non-existent / empty page_info node in aggregation webserver_map
                                if path not in cur_aggr_node:
                                    cur_aggr_node[path] = {}
                                if not cur_aggr_node[path]:
                                    cur_aggr_node[path] = page_info
                                    continue

                                # unite the GET and POST parameters and cookies
                                for ptype in ("GET", "POST", "cookies"):
                                    if ptype in page_info:
                                        if ptype in cur_aggr_node[path]:
                                            cur_aggr_node[path][ptype] = list(set(page_info[ptype] +
                                                                                  cur_aggr_node[path][ptype]))
                                        else:
                                            cur_aggr_node[path][ptype] = page_info[ptype]

                                # unite instances of the path
                                if "instances" in page_info:
                                    # handle non-existent / empty instances node in aggregation webserver_map
                                    if "instances" not in cur_aggr_node[path]:
                                        cur_aggr_node[path]["instances"] = []
                                    if not cur_aggr_node[path]["instances"]:
                                        cur_aggr_node[path]["instances"] = page_info["instances"]
                                        continue

                                    for cur_instance in page_info["instances"]:
                                        get_params = cur_instance.get("GET", {})
                                        post_params = cur_instance.get("POST", {})
                                        cookies = cur_instance.get("cookies", {})

                                        # skip empty instances
                                        if (not get_params) and (not post_params) and (not cookies):
                                            continue
                                        if ((not any(val for val in get_params.values())) and
                                                (not any(val for val in post_params.values())) and
                                                (not any(val for val in cookies.values()))):
                                            continue

                                        if not any((inst.get("GET", {}) == get_params and
                                                    inst.get("POST", {}) == post_params and
                                                    inst.get("cookies", {}) == cookies)
                                                   for inst in cur_aggr_node[path]["instances"]):
                                            cur_aggr_node[path]["instances"].append(cur_instance)

                                # safely copy over any miscellaneous info
                                for key, val in page_info.items():
                                    if key.startswith("misc_info"):
                                        if "misc_info" not in cur_aggr_node[path]:
                                            cur_aggr_node[path]["misc_info"] = val
                                        elif not any(val == aggr_val for aggr_val in cur_aggr_node[path].values()):
                                            for i in range(10):
                                                alt_name = "misc_info_%d" % i
                                                if alt_name not in cur_aggr_node[path]:
                                                    cur_aggr_node[path][alt_name] = val
                                                    break

        self.store_discovered_urls(webserver_map)
        return webserver_map

    def store_discovered_urls(self, webserver_map):
        """ write discovered locations in webserver_map to separate file for easy reading"""

        outpath = os.path.join(self.output_dir, DISCOVERED_URLS_OUTFILE)
        with open(outpath, "w") as f:
            for ip, ip_node in webserver_map.items():
                for portid, port_node in ip_node.items():
                    protocol_prefix = ""
                    if str(portid) == "80":
                        protocol_prefix = "http://"
                    elif str(portid) == "443":
                        protocol_prefix = "https://"

                    for host, host_node in port_node.items():
                        header = "**** %s:%s - %s ****" % (ip, str(portid), host)
                        full_header = "*" * len(header) + "\n" + header + "\n" + "*" * len(header) + "\n"
                        f.write(full_header)
                        for status_code, pages_node in host_node.items():
                            f.write("-" * 60 + "\n")
                            if protocol_prefix:
                                f.write(" [+] URLs with '%s' HTTP response:\n" % str(status_code))
                            else:
                                f.write(" [+] Locations with '%s' HTTP response:\n" % str(status_code))
                            f.write("-" * 60 + "\n")

                            for path in pages_node:
                                f.write("    " + protocol_prefix + host + path + "\n")

                            f.write("\n")
                        f.write("\n")
