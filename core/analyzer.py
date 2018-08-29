import copy
import importlib
import inspect
import json
import os
import shutil
import sys
import threading

import module_seeker
import utility as util

ANALYSIS_OUT_DIR = "analyis_results"
HOST_SCORES_FILE = "host_scores.json"
SHOW_PROGRESS_SYMBOLS = ["\u2502", "\u2571", "\u2500", "\u2572", "\u2502", "\u2571", "\u2500", "\u2572"]
ANALYZER_JOIN_TIMEOUT = 0.38

class Analyzer():

    def __init__(self, hosts: dict, config: dict, output_dir: str, online_only: bool, verbose: bool, logfile: str):
        """
        Create an Analyzer object to analyze the given hosts.

        :param hosts: The hosts to analyze for vulnerabilities
        :param config: The used config
        :param output_dir: A string specifying the output directory of the analysis
        :param online_only: Specifying whether to look up information only online (where applicable) 
        :param verbose: Specifying whether to provide verbose output or not
        :param logfile: a logfile for logging information
        """

        self.hosts = hosts
        self.config = config
        self.output_dir = output_dir
        self.online_only = online_only
        self.analysis_modules = module_seeker.find_all_analyzer_modules()
        self.verbose = verbose
        self.logfile = logfile
        self.logger = util.get_logger(__name__, logfile)

    def conduct_analyses(self):
        """
        Enter analysis phase to obtain a security score for the network.

        :return: The score as string
        """
        
        self.run_module_analyses()
        if len(self.analysis_modules) == 1:
            print(util.GREEN + "Analysis completed.")
        else:
            print(util.GREEN + "All %d analyses completed." % len(self.analysis_modules))
        print(util.SANE)
        self.logger.info("All analyses completed")
        self.logger.info("Aggregating results")
        self.result = self.construct_result()
        self.logger.info("Done")
        self.logger.info("Hosts analyses completed")
        # util.show_cursor()  # show cursor again
        return str(self.result)

    def run_module_analyses(self):
        """
        Conduct all avaulable analyses to retrieve for every module a dict with "host->score" entries.
        """

        self.results = {}
        # create the output directory for all analyses results
        self.analysis_out_dir = os.path.join(self.output_dir, ANALYSIS_OUT_DIR)
        os.makedirs(self.analysis_out_dir, exist_ok=True)

        # util.hide_cursor()  # hide cursor
        self.logger.info("Starting host analyses")
        print(util.BRIGHT_BLUE + "Starting host analyses:")
        if len(self.analysis_modules) == 1:
            self.logger.info("1 analysis module has been found")
        else:
            self.logger.info("%d analysis modules have been found" % len(self.analysis_modules))
        self.logger.debug("The following analysis modules have been found: %s"
            % ", ".join(self.analysis_modules))

        # iterate over all available analysis modules
        for i, analysis_module_path in enumerate(self.analysis_modules):
            # get analyzer module name
            analysis_module = analysis_module_path.replace(os.sep, ".")
            analysis_module = analysis_module.replace(".py", "")
            module_no_prefix = analysis_module.replace("modules.analyzer.", "", 1)

            # import the respective python module
            module = importlib.import_module(analysis_module)

            # change into the module's directory
            main_cwd = os.getcwd()
            module_dir = os.path.dirname(analysis_module_path)
            os.chdir(module_dir)

            # set the module's analysis parameters (e.g. network, ports, etc.)
            self.set_module_parameters(module)

            # conduct the module's analyis
            self.logger.info("Starting analysis %d of %d - %s" % (i+1, len(self.analysis_modules), module_no_prefix))
            analysis_result = []
            analysis_thread = threading.Thread(target=module.conduct_analysis, args=(analysis_result,))

            analysis_thread.start()
            # TODO: Check for TTY (https://www.tutorialspoint.com/python/os_isatty.htm or other)
            show_progress_state = 0
            while analysis_thread.is_alive():
                analysis_thread.join(timeout=ANALYZER_JOIN_TIMEOUT)
                print(util.GREEN + "Conducting analysis %d of %d - " % (i+1, len(self.analysis_modules)), end="")
                print(util.SANE + module_no_prefix + "  ", end="")
                print(util.YELLOW + SHOW_PROGRESS_SYMBOLS[show_progress_state])

                util.clear_previous_line()
                if (show_progress_state + 1) % len(SHOW_PROGRESS_SYMBOLS) == 0:
                    show_progress_state = 0
                else:
                    show_progress_state += 1

            if analysis_result and len(analysis_result[0]) == 2:
                result, created_files = analysis_result[0]
            else:
                self.logger.info("Analysis module '%s' delivered an unprocessable result. " % analysis_module +
                    "Its results have been discarded.")
                result, created_files = {}, []

            # change back into the main directory
            os.chdir(main_cwd)

            # create output directory for this module's analysis results
            module_output_dir = os.path.join(self.analysis_out_dir, os.sep.join(module_no_prefix.split(".")[:-1]))
            os.makedirs(module_output_dir, exist_ok=True)

            # process this module's analysis results
            if isinstance(result, str):  # if analysis module provides json output file
                # add result file to created_files (in case module has not)
                created_files = set(created_files)
                created_files.add(result)
                result_path = result
                if not os.path.isabs(result_path):
                    result_path = os.path.join(module_dir, result_path)

                # parse the json output into a python dict
                with open(result_path) as f:
                    self.results[analysis_module] = json.load(f)
            elif isinstance(result, dict):  # if analysis module provides output as python dict
                analysis_result_path = os.path.join(module_output_dir, "result.json")
                with open(analysis_result_path, "w") as f:  # write dict output to json file
                    f.write(json.dumps(result, ensure_ascii=False, indent=3))
                self.results[analysis_module] = result
            else:  # if result cannot be processed, skip this module
                print(util.RED + "Warning: results of analysis from file '%s' could not be used.\n"
                    "Only JSON files or python dicts can be used." % analysis_module_path)

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

            self.logger.info("Analysis %d of %d done" % (i+1, len(self.analysis_modules)))


    def set_module_parameters(self, module):
        """
        Set the given modules's analysis parameters depening on which parameters it has declared.

        :param module: the module whose analysis parameters to set
        """
        # execute the analysis function of the module and save result
        all_module_attributes = [attr_tuple[0] for attr_tuple in inspect.getmembers(module)]

        if "VERBOSE" in all_module_attributes:
            module.VERBOSE = self.verbose

        if "HOSTS" in all_module_attributes:
            module.HOSTS = copy.deepcopy(self.hosts)

        if "ONLINE_ONLY" in all_module_attributes:
            module.ONLINE_ONLY = self.online_only

        if "LOGFILE" in all_module_attributes:
            module.LOGFILE = self.logfile

        if "CONFIG" in all_module_attributes:
            module.CONFIG = self.config.get(module.__name__, {})

        if "CORE_CONFIG" in all_module_attributes:
            module.CONFIG = copy.deepcopy(self.config.get("core", {}))

    def construct_result(self):
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
            for module_name, module_result in module_results.items():
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
                    elif score > host_scores[host]:
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
                weight = (1 / (10 - score))**0.8
                weights[host] = weight
                weight_sum += weight

            numerator = sum([weights[host] * host_scores[host] for host in weights])
            net_score = numerator / weight_sum
            net_score = max(0, net_score)  # ensure score is >= 0
            net_score = min(10, net_score) # ensure score is <= 10
            return net_score

        if len(self.results) == 0:
            return "N/A"
        
        if len(self.results) == 1:
            host_scores = self.results[list(self.results.keys())[0]]
        else:
            host_scores = aggregate_module_scores(self.results)

        result = aggregate_host_scores(host_scores)

        # dump host scores to file
        host_scores_file = os.path.join(self.analysis_out_dir, HOST_SCORES_FILE)
        with open(host_scores_file, "w") as f:
            f.write(json.dumps(host_scores, ensure_ascii=False, indent=3))

        return result
