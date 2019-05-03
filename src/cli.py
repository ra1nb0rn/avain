#!/usr/bin/env python3

import argparse
import sys
import os

from core.controller import Controller
from core.result_types import ResultType
import core.utility as util

USER_RESULT_ARGS = {ResultType.SCAN: ("-sR", "--scan-results"),
                    ResultType.VULN_SCORE: ("-vS", "--vulnerability-scores"),
                    ResultType.WEBSERVER_MAP: ("-wM", "--webserver-map")}

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

        parser = argparse.ArgumentParser(description="Automated Vulnerability Analysis (in) IP-based " +
                                         "Networks - A toolkit for automatically assessing " +
                                         "the securtiy level of an IP-based network", prog="avain")
        optional_args = parser._action_groups.pop()
        required_args = parser.add_argument_group("required arguments (at least one)")
        parser._action_groups.append(optional_args)

        required_args.add_argument("-n", "--networks", nargs="+", help="specify networks to scan " +
                                   "as plain IP address or IP address in CIDR, range or wildcard notation")
        required_args.add_argument("-nL", "--network-list", help="a list that specifies networks " +
                                   "to include into or exclude from the scan")
        required_args.add_argument("-uM", "--update-modules", action="store_true", help="make " +
                                   "the modules that have an update mechanism update")
        for rtype, args in USER_RESULT_ARGS.items():
            required_args.add_argument(args[0], args[1], nargs="+", help="specify additional " +
                                       "%s results to include into the final scan result" %
                                       rtype.value)

        optional_args.add_argument("-c", "--config", help="specify a config file to use")
        optional_args.add_argument("-o", "--output", help="specify the output folder name")
        optional_args.add_argument("-p", "--ports", help="specify which ports to scan on every host")
        optional_args.add_argument("-sN", "--single-network", action="store_true", help="operate " +
                                   "in single network mode meaning that all specified networks " +
                                   "are considered to be a subnet of one common supernet")
        optional_args.add_argument("-v", "--verbose", action="store_true", help="enable verbose output")

        self.args = parser.parse_args()
        self.parse_user_results(parser)
        if (not self.args.networks) and (not self.args.network_list) and (not self.user_results) \
                and (not self.args.update_modules):
            parser.error("at least one of the following arguments is required: -n/--network," +
                         "-nL/--network-list, -uD/--update-modules or any one of [%s]" %
                         ", ".join("%s/%s" % rarg for rarg in USER_RESULT_ARGS.values()))

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

        if self.args.output:
            pass  # so far no limitation on output name

        if self.user_results:
            for rtype in ResultType:
                if rtype in self.user_results:
                    filepaths = self.user_results[rtype]
                    for filepath in filepaths:
                        if not os.path.isfile(filepath):
                            parser.error("specified %s result %s is not a file" % (rtype.value, filepath))

        if self.args.config:
            if not os.path.isfile(self.args.config):
                parser.error("config %s does not exist" % self.args.config)

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
                                self.args.output, self.user_results, self.args.single_network,
                                self.args.verbose)
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

    def parse_user_results(self, parser: argparse.ArgumentParser):
        self.user_results = {}
        for rtype, args in USER_RESULT_ARGS.items():
            filepaths = vars(self.args).get(args[1][2:].replace("-", "_"), None)
            if filepaths:
                for filepath in filepaths:
                    if not filepath:
                        parser.error("%s results specified, by no filepath was found" % rtype.value)
                    else:
                        if rtype not in self.user_results:
                            self.user_results[rtype] = []
                        self.user_results[rtype].append(filepath)


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
