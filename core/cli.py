#!/usr/bin/env python3

import argparse
import sys
import os
import sys

from controller import Controller
import utility as util

# TODO: time modifiers like in nmap as parameters?
# TODO: is_valid_net_addr improvements!

class Cli():

    def __init__(self):
        """
        Create a Cli object.
        """
        self.args = None

    def parse_arguments(self, args: list):
        """
        Parse the command line arguments using ArgumentParser

        :param args: the raw program arguments as a list (e.g. sys.argv)
        """

        parser = argparse.ArgumentParser(description="Automated Vulnerability Analysis (in) IoT Networks - A toolkit for automatically assessing the securtiy level of an IoT network", prog="avain")
        optional_args = parser._action_groups.pop()
        required_args = parser.add_argument_group("required arguments")
        parser._action_groups.append(optional_args)

        required_args.add_argument("-n", "--networks", nargs="+", help="Specify networks to scan in CIDR or wildcard notation. If given argument does not contain a CIDR "
                                                           "or wildcard, the host at the given IP is scanned.")
        required_args.add_argument("-nL", "--network-list", help="A list that specifies networks/hosts to add to or omit from the scan.")


        optional_args.add_argument("-aR", "--analysis-results", nargs="+", help="Addtional analysis results to include into the analysis result. "
                                                                                      "Multiple files or folders can be specified.")
        optional_args.add_argument("-o", "--output", help="Specify the output file name. If name collisions occur, the output files are prefixed "
                                                          "with the specified output file name.")
        optional_args.add_argument("-sR", "--scan-results", nargs="+", help="Addtional scan results to include into the scanning result. "
                                                                            "Multiple files or folders can be specified.")
        optional_args.add_argument("-t", "--time", action="store_true", help="Specifies whether to time the scan or not.")
        optional_args.add_argument("-p", "--ports", help="Specifies which ports to scan on every host.")
        optional_args.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")


        self.args = parser.parse_args()
        if (not self.args.networks) and (not self.args.network_list):
            parser.error("at least one of the following arguments is required: -n/--network or -nL/--network-list")

        self.parse_network_list(parser)
        self.validate_input(parser)

    def validate_input(self, parser: argparse.ArgumentParser):
        """
        Validate the program arguments of the given ArgumentParser.

        :param parser: an ArgumentParser with input arguments
        """

        if self.args.networks:
            for net in self.args.networks:
                if not util.is_valid_net_addr(net):
                    parser.error("%s is not a valid network address" % net)

        if self.args.network_list:
            for ip in self.args.add_networks:
                if not util.is_valid_net_addr(ip):
                    parser.error("network %s on network list is not a valid network address" % ip)
            for ip in self.args.omit_networks:
                if not util.is_valid_net_addr(ip):
                    parser.error("network %s on network omit list is not a valid network address" % ip)

        if self.args.analysis_results:
            for r in self.args.analysis_results:
                if not os.path.isfile(r):
                    parser.error("analysis result %s does not exist" % r)

        if self.args.output:
            pass  # so far no limitation on output name

        if self.args.scan_results:
            for r in self.args.scan_results:
                if not os.path.isfile(r):
                    parser.error("scan result %s does not exist" % r)

        if self.args.ports:
            def check_port(port_expr: str):
                try:
                    port_int = int(port_expr)
                    if port_int < 0 or port_int > 65535:
                        raise ValueError
                except ValueError:
                    parser.error("port %s is not a valid port" % port_expr)

            for port_expr in self.args.ports.split(","):
                if ":" in port_expr:
                    port_expr = port_expr[port_expr.find(":")+1:]
                if "-" in port_expr:
                    p1, p2 = port_expr.split("-")
                    check_port(p1)
                    check_port(p2)
                    if int(p1) > int(p2):
                        parser.error("port range %s is not a valid port range" % port_expr)
                else:
                    check_port(port_expr)

    def process_arguments(self):
        """
        Parse the program arguments and initiate the vulnerability analysis.
        """

        controller = Controller(self.args.networks, self.args.add_networks, self.args.omit_networks, self.args.ports, self.args.output, 
                                self.args.scan_results, self.args.analysis_results, self.args.time, self.args.verbose)
        controller.do_analysis()

    def parse_network_list(self, parser: argparse.ArgumentParser):
        """
        Parse the network list contained in the given ArgumentParser (if it exists).

        :param parser: an ArgumentParser processing program arguments
        """

        self.args.add_networks, self.args.omit_networks = [], []
        if not self.args.network_list:
            return

        if not os.path.isfile(self.args.network_list):
            parser.error("network list %s does not exist" % self.args.network_list)

        with open(self.args.network_list) as file:
            for line in file:
                line = line.strip()
                if line.startswith("+"):
                    self.args.add_networks.append(line[1:].strip())
                elif line.startswith("-"):
                    self.args.omit_networks.append(line[1:].strip())
                else:
                    self.args.add_networks.append(line)


#########################################
### Entry point for the AVAIN program ###
#########################################
if __name__ == "__main__":
    # Extend search path for modules
    module_dir = os.path.dirname("modules")
    sys.path.append(module_dir)

    # Start program
    cli = Cli()
    cli.parse_arguments(sys.argv)
    cli.process_arguments()
