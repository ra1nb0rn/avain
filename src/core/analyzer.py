import copy
import inspect
import json
import os

from core.module_manager_feedback import ModuleManagerFeedback
from core.module_manager import ModuleManager

ADDITIONAL_RESULTS_DIR = "add_analysis_results"
HOST_SCORES_FILE = "host_scores.json"
MODULE_SCORES_FILE = "module_scores.json"
ANALYZER_JOIN_TIMEOUT = 0.38

class Analyzer(ModuleManagerFeedback):

    def __init__(self, output_dir: str, config: dict, verbose: bool,
                 add_results: list, hosts: dict, online_only: bool):
        """
        Create an Analyzer object to analyze the given hosts.

        :param output_dir: A string specifying the output directory of the analysis
        :param config: The used config
        :param verbose: Specifies whether to provide verbose output or not
        :param add_results: additional result files to include into the result
        :param hosts: The hosts to analyze for vulnerabilities
        :param online_only: Specifies whether to look up information only online (where applicable)
        """

        super().__init__(output_dir, config, verbose, add_results)
        self.hosts = hosts
        self.online_only = online_only

    def _assign_init_values(self):
        modules = ModuleManager.find_all_prefixed_modules("modules/analyzer", "analyzer_")
        return (modules, "results.json", "analysis", "conduct_analysis", "modules.analyzer.",
                ANALYZER_JOIN_TIMEOUT, "Starting host analyses", True)

    def _assign_add_results_dir(self):
        return ADDITIONAL_RESULTS_DIR

    def _only_result_files(self):
        return False

    def _sort_results(self):
        pass

    def _cleanup(self):
        pass

    def _add_to_results(self, module_id, module_result):
        self.results[module_id] = module_result

    def _set_extra_module_parameters(self, module):
        """
        Set the given modules's analysis parameters depening on which parameters it has declared.

        :param module: the module whose analysis parameters to set
        """

        all_module_attributes = [attr_tuple[0] for attr_tuple in inspect.getmembers(module)]

        if "HOSTS" in all_module_attributes:
            module.HOSTS = copy.deepcopy(self.hosts)

        if "ONLINE_ONLY" in all_module_attributes:
            module.ONLINE_ONLY = self.online_only

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
            # assume file prefix "modules/analyzer/" and extension ".py"
            module = module[len("modules/analyzer/"):]
            module = module[:-len(".py")]
            module = module.replace("/", ".")

            # save existent scores
            for host, score in result.items():
                add_module_result()

            # put N/A for hosts that are not in the module's result
            score = "N/A"
            for host in hosts:
                if host not in result.keys():
                    add_module_result()

        # dump module scores to file
        module_scores_file = os.path.join(self.output_dir, MODULE_SCORES_FILE)
        with open(module_scores_file, "w") as f:
            f.write(json.dumps(module_scores, ensure_ascii=False, indent=3))

    def _construct_result(self):
        """
        Accumulate the results from all the different analysis modules into one analysis result.

        :return: the network's score as 0 <= score <= 10
        """

        def aggregate_module_scores(module_results: dict):
            """
            Aggregate all module results into one dict having host IPs as
            key and their analysis score as value.
            """

            host_scores = {}
            for _, module_result in module_results.items():
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
                net_score = "N/A"
            return net_score

        if not self.results:
            return "N/A"

        if len(self.results) == 1:
            host_scores = self.results[list(self.results.keys())[0]]
        else:
            host_scores = aggregate_module_scores(self.results)

        result = aggregate_host_scores(host_scores)

        self._save_module_scores(host_scores.keys())

        # dump host scores to file
        host_scores_file = os.path.join(self.output_dir, HOST_SCORES_FILE)
        with open(host_scores_file, "w") as f:
            f.write(json.dumps(host_scores, ensure_ascii=False, indent=3))

        return result
