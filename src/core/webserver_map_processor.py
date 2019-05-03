import copy
import json
import os
import pprint

from core.result_processor import ResultProcessor
import core.utility as util


class WebserverMapProcessor(ResultProcessor):

    def __init__(self, output_dir: str, results: dict = None):
        super().__init__(output_dir, results)

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
                        try:
                            status_code = int(status_code_str)
                        except ValueError:
                            return False

                        if not (100 <= status_code < 600):
                            return False

                        for page in pages:
                            if "PATH" not in page:
                                return False

                            if not path.startswith("/"):
                                return False

                            for key in ("GET", "POST", "COOKIES"):
                                if key in page and not isinstance(page[key], list):
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

        WebserverMapProcessor.store_json_convertable_result(result, filepath)

    @staticmethod
    def store_aggregated_result(aggr_result, filepath: str):
        """Store the given aggregated result at the specified location"""

        result = [aggr_result]
        WebserverMapProcessor.store_json_convertable_result(result, filepath)

    def parse_result_file(self, filepath: str):
        return self.parse_result_from_json_file(filepath)

    def aggregate_results(self):
        """
        Accumulate the results from all the different webserver map analyzers into one.
        Results are aggregated by uniting all the different results.

        :return: the aggregated results
        """

        if not self.results:
            return "N/A"

        if len(self.results) == 1:
            return copy.deepcopy(self.results[list(self.results.keys())[0]])

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
                            if not status_code in webserver_map[host][portid][webhost]:
                                webserver_map[host][portid][webhost][status_code] = []

                            aggr_cur_node = webserver_map[host][portid][webhost][status_code]

                            for page in page_nodes:
                                append = True  # stores whether this page is completely new in the aggregation
                                for aggr_page in aggr_cur_node:
                                    if page["PATH"] == aggr_page["PATH"]:
                                        # unite the GET and POST parameters and cookies
                                        for param in ("GET", "POST", "COOKIES"):
                                            if param in page:
                                                if param in aggr_page:
                                                    aggr_page[param] = list(set(page[param] + aggr_page[param]))
                                                else:
                                                    aggr_page[param] = page[param]

                                        # attempt to copy all other existing dictionary keys
                                        for other, value in page.items():
                                            if other in ("GET", "POST", "COOKIES"):
                                                continue
                                            if other not in aggr_page:
                                                aggr_page[other] = value
                                            elif value != aggr_page[other]:
                                                other = other + "_1"
                                                for i in range(2, 10):
                                                    if other not in aggr_page:
                                                        aggr_page[other] = value
                                                        break
                                                    if value == aggr_page[other]:
                                                        break
                                                    other = other[:-1] + str(i)

                                        append = False

                                if append:
                                    aggr_cur_node.append(page)
                                    break

        return webserver_map
