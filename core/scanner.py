import importlib
import inspect
import json
import os
import shutil
import sys
import threading

import module_seeker
import utility as util

SCAN_OUT_DIR = "scan_results"
SHOW_PROGRESS_SYMBOLS = ["\u2502", "\u2571", "\u2500", "\u2572", "\u2502", "\u2571", "\u2500", "\u2572"]
SCANNER_JOIN_TIMEOUT = 0.38

class Scanner():

    def __init__(self, networks: list, add_networks: list, omit_networks: list, config: dict, ports: list, output_dir: str,
                online_only: bool, verbose: bool, logfile: str, scan_results: list, analysis_only: bool):
        """
        Create a Scanner object with the given networks and output_directory

        :param network: A string representing the network to analyze
        :param add_networks: A list of networks as strings to additionally analyze
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
        self.add_networks = add_networks
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

    def conduct_module_scans(self):
        """
        Do the different module scans
        """

        # util.hide_cursor()  # hide cursor
        self.logger.info("Starting network scan(s)")
        print(util.BRIGHT_BLUE + "Starting network scans:")
        self.logger.info("%d scanner module(s) have been found" % len(self.scanner_modules))
        self.logger.debug("The following scanner modules have been found: %s"
            % ", ".join(self.scanner_modules))

        # iterate over all available scanner modules
        for i, scanner_module_path in enumerate(self.scanner_modules):
            # get scanner module name
            scanner_module = scanner_module_path.replace(os.sep, ".")
            scanner_module = scanner_module.replace(".py", "")

            # import the respective python module
            module = importlib.import_module(scanner_module)

            # change into the module's directory
            main_cwd = os.getcwd()
            module_dir = os.path.dirname(scanner_module_path)
            os.chdir(module_dir)

            # set the module's scan parameters (e.g. network, ports, etc.)
            self.set_module_parameters(module)

            # conduct the module's scan
            self.logger.info("Starting scan %d of %d" % (i+1, len(self.scanner_modules)))
            scan_info = []
            scan_thread = threading.Thread(target=module.conduct_scan, args=(scan_info,))

            scan_thread.start()
            # TODO: Check for TTY (https://www.tutorialspoint.com/python/os_isatty.htm or other)
            show_progress_state = 0
            while scan_thread.is_alive():
                scan_thread.join(timeout=SCANNER_JOIN_TIMEOUT)
                print(util.GREEN + "Conducting scan %d of %d  " % (i+1, len(self.scanner_modules)), end="")
                print(util.YELLOW + SHOW_PROGRESS_SYMBOLS[show_progress_state])
                util.clear_previous_line()
                if (show_progress_state + 1) % len(SHOW_PROGRESS_SYMBOLS) == 0:
                    show_progress_state = 0
                else:
                    show_progress_state += 1

            if scan_info:
                result, created_files = scan_info[0]
            else:
                result, created_files = {}, []

            # change back into the main directory
            os.chdir(main_cwd)

            # create output directory for this module's scan results
            module_dir_no_prefix = scanner_module.replace("modules.scanner.", "", 1)
            module_output_dir = os.path.join(self.scan_result_out_dir, ".".join(module_dir_no_prefix.split(".")[:-1]))
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
                    self.results[scanner_module] = json.load(f)
            elif isinstance(result, dict):  # if scanner module provides output as python dict
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
                    if os.path.isabs(file):
                        shutil.move(file, file_out_path)
                    else:
                        shutil.move(os.path.join(module_dir, file), file_out_path)

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
            add_results_dir = os.path.join(os.path.join(self.output_dir, SCAN_OUT_DIR), "add_scan_results")
            os.makedirs(add_results_dir)
            for filepath in self.add_scan_results:
                scan_result = None
                if not os.path.isfile(filepath):
                    self.logger.warning("Specified scan result '%s' is not a file" % filepath)
                try:
                    copy_filepath = os.path.join(add_results_dir, os.path.basename(filepath))
                    shutil.copyfile(filepath, copy_filepath)
                    with open(copy_filepath) as f:
                        scan_result = json.load(f)
                except IOError:
                    self.logger.warning("Specified scan result '%s' cannot be opened" % filepath)

                if scan_result:
                    self.results[filepath] = scan_result
            self.logger.info("Done.")

    def conduct_scans(self):
        """
        Conduct all available scans and accumulate potentially conflicting results into one.

        :return: A dict having the host IPs as keys and their scan results as values
        """

        self.results = {}
        # create the output directory for all scan results
        self.scan_result_out_dir = os.path.join(self.output_dir, SCAN_OUT_DIR)
        os.makedirs(self.scan_result_out_dir, exist_ok=True)
        if not self.analysis_only:
            self.conduct_module_scans()
        self.include_additional_scan_results()
        self.logger.info("Aggregating results")
        self.result = self.construct_result()
        self.logger.info("Done")
        self.logger.info("Network scans completed")
        # util.show_cursor()  # show cursor again
        return self.result


    def set_module_parameters(self, module):
        """
        Set the given modules's scan parameters depening on which parameters it has declared.

        :param module: the module whose scan parameters to set
        """
        # execute the scanning function of the module and save result
        all_module_attributes = [attr_tuple[0] for attr_tuple in inspect.getmembers(module)]

        if "NETWORKS" in all_module_attributes:
            module.NETWORKS = self.networks

        if "ADD_NETWORKS" in all_module_attributes:
            module.ADD_NETWORKS = self.add_networks

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
            module.CONFIG = copy.deepcopy(self.config.get("core", {}))

    def construct_result(self):
        """
        Accumulate the results from all the different scanner modules into one scanning result.

        :return: a dict having host IPs as keys and their scan results as values
        """
        
        if len(self.results) == 0:
            return {}
        elif len(self.results) == 1:
            return self.results[list(self.results.keys())[0]]
        else:
            results = {}
            for result in self.results.values():
                for ip, host in result.items():
                    if not ip in results:
                        results[ip] = host
                    else:
                        ...  # TODO: implement
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

        for network in self.add_networks:
            add_to_hosts(network)

        for network in self.omit_networks:
            hosts = util.extend_network_to_hosts(network)
            if isinstance(hosts, list):
                self.hosts = self.hosts - set(hosts)
            else:
                self.hosts.remove(hosts)

        self.hosts = list(self.hosts)