import os

from scanner import Scanner
import utility as util
import visualizer

class Controller():

    def __init__(self, network: str, add_networks: list, omit_networks: list, output_dir: str, scan_results: list,
                analysis_results: list, time: bool, verbose: bool):
        """
        Create a Controller object.

        :param network: A string representing the network to analyze
        :param add_networks: A list of networks as strings to additionally analyze
        :param omit_networks: A list of networks as strings to omit from the analysis
        :param output_dir: A string specifying the output directory of the analysis
        :param scan_results: A list of filenames whose files contain additional scan results
        :param analysis_results: A list of filenames whose files contain additional analysis results
        :param time: A boolean specifying whether to measure the required ananlysis time
        :param vebose: Specifying whether to provide verbose output or not
        """

        self.network = network
        self.add_networks = add_networks
        self.omit_networks = omit_networks
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = "avain_output-" + util.get_current_timestamp()
            # self.output_dir = "avain_output"  # for debugging purposes
        self.scan_results = scan_results
        self.analysis_results = analysis_results
        self.time = time
        self.verbose = verbose
        self.hosts = set()

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

    def do_analysis(self):
        """
        First conduct network reconnaissance and then analyze the hosts
        of the specified network for vulnerabilities.
        """

        scanner = Scanner(self.network, self.add_networks, self.omit_networks, self.output_dir, self.verbose)
        print("Scanning ...")
        hosts = scanner.conduct_scans()
        print("Done.")
        print("Results:")
        visualizer.visualize_scan_results(hosts)
        print("All created files have been written to: %s" % self.output_dir)

    def print_arguments(self):
        print("Network: %s" % self.network)
        print("Additional networks: {}".format(self.add_networks))
        print("Omitted networks: {}".format(self.omit_networks))
        print("Output: %s" % self.output)
        print("Additional scan results: {}".format(self.scan_results))
        print("Additional analysis results: {}".format(self.analysis_results))
        print("Time: %r" % self.time)
        print("Verbose: %r" % self.verbose)
