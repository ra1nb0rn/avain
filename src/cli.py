#!/usr/bin/env python3

import argparse
import sys
import os

from core.controller import Controller
import core.utility as util

class Cli():

    def __init__(self):
        """
        Create a Cli object.
        """
        self.args = None

    def parse_arguments(self):
        """
        Parse the command line arguments using ArgumentParser

        :param args: the raw program arguments as a list (e.g. sys.argv)
        """

        parser = argparse.ArgumentParser(description="Automated Vulnerability Analysis (in) IoT " +
                                         "Networks - A toolkit for automatically assessing " +
                                         "the securtiy level of an IoT network", prog="avain")
        optional_args = parser._action_groups.pop()
        required_args = parser.add_argument_group("required arguments")
        parser._action_groups.append(optional_args)

        required_args.add_argument("-n", "--networks", nargs="+", help="specify networks to scan " +
                                   "as plain IP or IP in CIDR, range or wildcard notation")
        required_args.add_argument("-nL", "--network-list", help="a list that specifies networks " +
                                   "to include into or exclude from the scan")
        required_args.add_argument("-uM", "--update-modules", action="store_true", help="make " +
                                   "the modules that have an update mechanism update")
        required_args.add_argument("-aO", "--analysis-only", action="store_true", help="skip scanning " +
                                   "phase. Only do an analysis with the user provided scan results")
        optional_args.add_argument("-c", "--config", help="specify a config file to use")
        optional_args.add_argument("-o", "--output", help="specify the output folder name")
        optional_args.add_argument("-p", "--ports", help="specify which ports to scan on every host")
        optional_args.add_argument("-sN", "--single-network", action="store_true", help="operate " +
                                   "in single network mode meaning that all specified networks " +
                                   "are considered to be a subnet of one common supernet")
        optional_args.add_argument("-sR", "--scan-results", nargs="+", help="specify additional " +
                                   "scan results to include into the final scan result")
        optional_args.add_argument("-aR", "--analysis-results", nargs="+", help="specify additional " +
                                   "analysis results to include into the final analysis result")
        optional_args.add_argument("-sO", "--scan-only", action="store_true", help="only do a " +
                                   "network scan and omit the analysis phase")
        optional_args.add_argument("-oO", "--online-only", action="store_true", help="only look " +
                                   "up information online (where applicable)")
        optional_args.add_argument("-v", "--verbose", action="store_true", help="enable verbose output")

        self.args = parser.parse_args()
        if (not self.args.networks) and (not self.args.network_list) and (not self.args.scan_results) \
                and (not self.args.update_modules) and (not self.args.analysis_only):
            parser.error("at least one of the following arguments is required: -n/--network," +
                         "-nL/--network-list, -uD/--update-modules or -aO/--analysis-only")

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
            for res_file in self.args.analysis_results:
                if not os.path.isfile(res_file):
                    parser.error("analysis result %s does not exist" % res_file)

        if self.args.output:
            pass  # so far no limitation on output name

        if self.args.scan_results:
            for res_file in self.args.scan_results:
                if not os.path.isfile(res_file):
                    parser.error("scan result %s does not exist" % res_file)

        if self.args.config:
            if not os.path.isfile(self.args.config):
                parser.error("config %s does not exist" % self.args.config)

        if self.args.analysis_only:
            if not self.args.scan_results:
                parser.error("existing scan results are required to do only an analysis")

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
                    port_1, port_2 = port_expr.split("-")
                    check_port(port_1)
                    check_port(port_2)
                    if int(port_1) > int(port_2):
                        parser.error("port range %s is not a valid port range" % port_expr)
                else:
                    check_port(port_expr)

    def process_arguments(self):
        """
        Parse the program arguments and initiate the vulnerability analysis.
        """

        controller = Controller(self.args.networks, self.args.add_networks, self.args.omit_networks,
                                self.args.update_modules, self.args.config, self.args.ports,
                                self.args.output, self.args.scan_results, self.args.analysis_results,
                                self.args.single_network, self.args.verbose, self.args.scan_only,
                                self.args.analysis_only)
        controller.run()

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


def banner():
    print("|" + "-" * 78 + "|")
    print(
"""\
|                                                                              |
|                         ___  _    __ ___     ____ _   __                     |
|                        /   || |  / //   |   /  _// | / /                     |
|                       / /| || | / // /| |   / / /  |/ /                      |
|                      / ___ || |/ // ___ | _/ / / /|  /                       |
|                     /_/  |_||___//_/  |_|/___//_/ |_/                        |
|                                                                              |\
""")
    print("|" + " " * 25 + "[ Created by - Dustin Born ]" + " " * 25 + "|")
    print("|" + "-" * 78 + "|")
    print()


#########################################
### Entry point for the AVAIN program ###
#########################################
if __name__ == "__main__":
    banner()
    # Extend search path for modules
    MODULE_DIR = os.path.dirname("modules")
    sys.path.append(MODULE_DIR)

    # Start program
    CLI = Cli()
    CLI.parse_arguments()
    CLI.process_arguments()
