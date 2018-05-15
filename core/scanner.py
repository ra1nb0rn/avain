import importlib
import inspect
import os
import shutil
import sys

import module_seeker

SCAN_OUT_DIR = "scan_results"

class Scanner():

    def __init__(self, network: str, add_networks: list, omit_networks: list, output_dir: str, verbose: bool):
        """
        Create a Scanner object with the given networks and output_directory

        :param network: A string representing the network to analyze
        :param add_networks: A list of networks as strings to additionally analyze
        :param omit_networks: A list of networks as strings to omit from the analysis
        :param output_dir: A string specifying the output directory of the analysis
        :param verbose: Specifying whether to provide verbose output or not
        """

        self.network = network
        self.add_networks = add_networks
        self.omit_networks = omit_networks
        self.output_dir = output_dir
        self.scanner_modules = module_seeker.find_all_scanners_modules()
        self.analysis_modules = module_seeker.find_all_analyzer_modules()
        self.verbose = verbose

    def conduct_scans(self):
        """
        Conduct all available scans and accumulate potentially conflicting results into one.

        :return: A dict having the host IPs as keys and their scan results as values
        """

        self.results = {}

        # create the output directory for all scan results
        scan_result_out_dir = os.path.join(self.output_dir, SCAN_OUT_DIR)
        os.makedirs(scan_result_out_dir, exist_ok=True)

        # iterate over all available scanner modules
        for scanner_module_path in self.scanner_modules:
            # get scanner module name
            scanner_module = scanner_module_path.replace(os.sep, ".")
            scanner_module = scanner_module.replace(".py", "")

            # import the respective python module
            module = importlib.import_module(scanner_module)

            # change into the module's directory
            main_cwd = os.getcwd()
            module_dir = os.path.dirname(scanner_module_path)
            os.chdir(module_dir)

            # execute the scanning function of the module and save result
            all_module_functions = [func_tuple[0] for func_tuple in inspect.getmembers(module, inspect.isfunction)]
            if "scan_network" in all_module_functions:
                result, created_files = module.scan_network(self.network, self.add_networks, self.omit_networks, self.verbose)
            elif "scan_hosts" in all_module_functions:
                if not self.hosts:
                    controller.extend_networks_to_hosts()
                result, created_files = module.scan_hosts(self.hosts, self.verbose)
            else:
                print("Warning couldn't conduct scan with module '%s'" % scanner_module_path, file=sys.stderr)
                print("Reason: neither function 'scan_network' nor function 'scan_hosts' is present.", file=sys.stderr)
                continue

            # change back into the main directory
            os.chdir(main_cwd)

            # create output directory for this module's scan results
            module_output_dir = os.path.join(scan_result_out_dir, scanner_module)
            os.makedirs(module_output_dir, exist_ok=True)

            # process this module's scan results
            if isinstance(result, str):  # if scanner module provides XML output
                # add result file to created_files (in case module has not)
                created_files = set(created_files)
                created_files.add(result)
                result_path = result
                if not os.path.isabs(result_path):
                    result_path = os.path.join(module_dir, result_path)

                # parse the XML output into a python dict
                self.results[scanner_module] = self.parse_xml_scan_result_to_dict(result_path)
            elif isinstance(result, dict):  # if scanner module provides output as python dict
                self.write_scan_result_to_xml(result, os.path.join(module_output_dir, scanner_module + "_result.xml"))  # write the dict to XML
                self.results[scanner_module] = result
            else:  # if result cannot be processed, skip this module
                print("Warning: results of scan from file '%s' could not be used.\nOnly XML files or python dicts can be used." % scanner_module_path)

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

        self.result = self.construct_result()
        return self.result

    def parse_xml_scan_result_to_dict(self, xml_file: str):
        pass

    def write_scan_result_to_xml(self, result: dict, out_name: str):
        pass

    def construct_result(self):
        """
        Accumulate the results from all the different scanner modules into one scanning result.

        :return: a dict having host IPs as keys and their scan results as values
        """
        
        if len(self.results) == 0:
            return {}
        elif len(self.results) == 1:
            return self.results[list(self.results.keys())[0]]

        # TODO: implement
        else:
            return {}

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

        add_to_hosts(self.network)
        for network in self.add_networks:
            add_to_hosts(network)

        for network in self.omit_networks:
            hosts = util.extend_network_to_hosts(network)
            if isinstance(hosts, list):
                self.hosts = self.hosts - set(hosts)
            else:
                self.hosts.remove(hosts)

        self.hosts = list(self.hosts)