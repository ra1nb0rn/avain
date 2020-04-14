import json
import os
import pprint

from core.result_processor import ResultProcessor
import core.utility as util

HOST_SCORES_FILE = "host_scores.json"
MODULE_SCORES_FILE = "module_scores.json"

class VulnScoreProcessor(ResultProcessor):

    def __init__(self, output_dir: str, results: dict = None):
        super().__init__(output_dir, results)

    def is_valid_result(result):
        if not isinstance(result, dict):
            return False

        for key, value in result.items():
            if (not util.is_ipv4(key)) and (not util.is_ipv6(key)):
                return False

            if ((not isinstance(value, float)) and (not isinstance(value, int))
                    and (not isinstance(value, str))):
                return False
        return True

    @staticmethod
    def print_result(result: dict):
        pprint.pprint(result)

    @staticmethod
    def store_result(result: dict, filepath: str):
        """Store the given result at the specified location"""

        VulnScoreProcessor.store_json_convertible_result(result, filepath)

    @staticmethod
    def store_aggregated_result(aggr_result, filepath: str):
        """Store the given aggregated result at the specified location"""

        result = {}
        if aggr_result:
            result = [aggr_result]
        VulnScoreProcessor.store_json_convertible_result(result, filepath)

    def parse_result_file(self, filepath: str):
        return self.parse_result_from_json_file(filepath)

    def _save_module_scores(self, hosts: list):
        """
        Save the module scores in a JSON file. In the file, for every host it is stored which
        module rated it with which score.
        """

        def add_module_result():
            nonlocal module_scores, host, module, score

            if host not in module_scores:
                module_scores[host] = {module: score}
            else:
                module_scores[host][module] = score

        module_scores = {}

        for module, result in self.results.items():
            if isinstance(result, list):
                continue

            # save existent scores
            for host, score in result.items():
                add_module_result()

            # put N/A for hosts that are not in the module's result
            score = "N/A"
            for host in hosts:
                if host not in result.keys():
                    add_module_result()

        # dump module scores to file
        module_scores = ResultProcessor.sort_result_by_ip(module_scores)
        module_scores_file = os.path.join(self.output_dir, MODULE_SCORES_FILE)
        with open(module_scores_file, "w") as file:
            file.write(json.dumps(module_scores, ensure_ascii=False, indent=3))

    def aggregate_results(self):
        """
        Accumulate the results from all the different vuln_score modules into one
        vulnerabiltiy score per network.

        :return: the network's score as 0 <= score <= 10
        """

        def aggregate_module_scores(module_results: dict):
            """
            Aggregate all module results into one dict having host IPs as
            key and their analysis score as value.
            """

            host_scores = {}
            for _, module_result in module_results.items():
                # if result is already aggregated, continue
                if not isinstance(module_result, dict):
                    continue
                for host, score in module_result.items():
                    try:  # catch potential 'N/A' or other conversion exception
                        score = float(score)
                    except ValueError:
                        if host in host_scores:
                            continue
                        else:
                            host_scores[host] = "N/A"

                    if host not in host_scores:
                        host_scores[host] = score
                    else:
                        try:
                            if score > host_scores[host]:
                                host_scores[host] = score
                        except:
                            host_scores[host] = score

            return host_scores

        def aggregate_host_scores(host_scores: dict):
            """
            Aggregate all host scores into one final network score.
            """

            weights, weight_sum = {}, 0
            for host, score in host_scores.items():
                try:
                    score = float(score)
                except ValueError:
                    continue

                weight = (1 / (10.01 - score))**0.8
                weights[host] = weight
                weight_sum += weight

            if weight_sum > 0:
                numerator = sum([weights[host] * host_scores[host] for host in weights])
                net_score = numerator / weight_sum
                net_score = max(0, net_score)  # ensure score is >= 0
                net_score = min(10, net_score) # ensure score is <= 10
            else:
                net_score = ""
            return net_score

        if not self.results:
            return ""

        if len(self.results) == 1:
            host_scores = self.results[list(self.results.keys())[0]]
        else:
            host_scores = ResultProcessor.sort_result_by_ip(aggregate_module_scores(self.results))

        # if only list of scores without IPs is available, transform it to a dict
        if isinstance(host_scores, list):
            host_scores = {str(i): host_scores[i] for i in range(len(host_scores))}

        result = aggregate_host_scores(host_scores)
        if host_scores and isinstance(host_scores, dict):
            self._save_module_scores(host_scores.keys())

        # dump host scores to file
        host_scores_file = os.path.join(self.output_dir, HOST_SCORES_FILE)
        with open(host_scores_file, "w") as file:
            file.write(json.dumps(host_scores, ensure_ascii=False, indent=3))

        return result
