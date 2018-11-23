import json
import logging
import os
import sys

from core.module_updater import ModuleUpdater
from core.scanner import Scanner
from core.analyzer import Analyzer
import core.utility as util
import core.visualizer as visualizer

LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGFILE = "avain.log"
SHOW_PROGRESS_SYMBOLS = ["\u2502", "\u2571", "\u2500", "\u2572",
                         "\u2502", "\u2571", "\u2500", "\u2572"]
UPDATER_JOIN_TIMEOUT = 0.38
DEFAULT_CONFIG_PATH = "%s%sconfig/default_config.txt" % (os.environ["AVAIN_DIR"], os.sep)
SCANNER_OUTPUT_DIR = "scan_results"
ANALYZER_OUTPUT_DIR = "analysis_results"
UPDATE_OUTPUT_DIR = "update_output"
NET_DIR_MAP_FILE = "net_dir_map.json"

class Controller():

    def __init__(self, networks: list, add_networks: list, omit_networks: list, update_modules: bool,
                 config_path: str, ports: list, output_dir: str, scan_results: list, analysis_results: list,
                 single_network: bool, verbose: bool, scan_only: bool, analysis_only: bool):
        """
        Create a Controller object.

        :param networks: A list of strings specifying the networks to analyze
        :param add_networks: A list of networks as strings to additionally analyze
        :param omit_networks: A list of networks as strings to omit from the analysis
        :param update_modules: Whether modules should be updated or initialized
        :param config_path: The path to a config file
        :param ports: A list of port expressions
        :param output_dir: A string specifying the output directory of the analysis
        :param scan_results: A list of filenames whose files contain additional scan results
        :param analysis_results: A list of filenames whose files contain additional analysis results
        :param single_network: A boolean specifying whether all given networks are to be considered
                               hosts in one single network
        :param vebose: Specifying whether to provide verbose output or not
        :param scan_only: Whether to only do a network scan
        :param analysis_only: Whether to only do an analysis with the specified scan results
        """

        self.networks = networks if networks is not None else []
        self.add_networks = add_networks
        self.omit_networks = omit_networks

        # determine output directory
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = "avain_output-" + util.get_current_timestamp()
        self.orig_out_dir = self.output_dir
        self.output_dir = os.path.abspath(self.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        # check for user scan and analysis results
        self.scan_results = None
        self.analysis_results = None

        if scan_results:
            self.scan_results = [os.path.abspath(scan_result) for scan_result in scan_results]
        if analysis_results:
            self.analysis_results = [os.path.abspath(analysis_result) for analysis_result in analysis_results]

        # store absolute config path
        if config_path:
            config_path = os.path.abspath(config_path)

        # change into AVAIN directory
        self.original_cwd = os.getcwd()
        core_dir = os.path.dirname(os.path.join(os.path.realpath(__file__)))
        avain_dir = os.path.abspath(os.path.join(core_dir, os.pardir))
        os.chdir(avain_dir)

        # parse default and user configs
        self.config = {}
        if os.path.isfile(DEFAULT_CONFIG_PATH):
            try:
                self.config = util.parse_config(DEFAULT_CONFIG_PATH, self.config)
            except Exception as excpt:
                print(util.MAGENTA + ("Warning: Could not parse default config file. " +
                                      "Proceeding without default config.\n") + util.SANE, file=sys.stderr)
                util.print_exception_and_continue(excpt)
        elif not config_path:
            print(util.MAGENTA + "Warning: Could not find default config.\n" + util.SANE, file=sys.stderr)

        if config_path:
            try:
                self.config = util.parse_config(config_path, self.config)
            except Exception as excpt:
                print(util.MAGENTA + ("Warning: Could not parse custom config file. " +
                                      "Proceeding without custom config.\n") + util.SANE, file=sys.stderr)
                util.print_exception_and_continue(excpt)

        # set remaining variables
        self.single_network = single_network
        self.verbose = verbose
        self.hosts = set()
        self.ports = ports
        self.update_modules = update_modules
        self.scan_only = scan_only
        self.analysis_only = analysis_only

        # setup logging
        self.setup_logging()
        self.logger.info("Starting the AVAIN program")
        self.logger.info("Executed call: avain %s", " ".join(sys.argv[1:]))

        # inform user about not being root
        if (networks or add_networks) and os.getuid() != 0:
            print(util.MAGENTA + "Warning: not running this program as root user leads"
                  " to less effective scanning (e.g. with nmap)\n" + util.SANE, file=sys.stderr)

    def setup_logging(self):
        """
        Setup logging by deleting potentially old log and specifying logging format
        """
        self.logfile = os.path.abspath(os.path.join(self.output_dir, LOGFILE))
        if os.path.isfile(self.logfile):
            os.remove(self.logfile)  # delete log file if it already exists (from a previous run)
        logging.basicConfig(format=LOGGING_FORMAT, filename=self.logfile, level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def run(self):
        """
        Execute the main program depending on the given program parameters.
        """
        if self.update_modules:
            updater = ModuleUpdater(os.path.join(self.output_dir, UPDATE_OUTPUT_DIR),
                                    self.config, self.verbose)
            updater.run()

        if self.networks or self.add_networks or self.scan_only or self.analysis_only:
            self.do_assessment()

        # change back to original directory
        os.chdir(self.original_cwd)

    def do_assessment(self):
        """
        Conduct the vulnerability assessment either in "normal" or "single network mode".
        """

        def do_assessment_helper(networks: list, out_dir: str):
            # First conduct network reconnaissance and then analyze the hosts
            # of the specified network(s) for vulnerabilities.
            scanner = Scanner(os.path.join(out_dir, SCANNER_OUTPUT_DIR), self.config,
                              self.verbose, self.scan_results, networks, self.omit_networks,
                              self.ports, self.analysis_only)
            hosts = scanner.run()

            if not self.scan_only:
                analyzer = Analyzer(os.path.join(out_dir, ANALYZER_OUTPUT_DIR), self.config,
                                    self.verbose, self.analysis_results, hosts)
                net_score = analyzer.run()
                return hosts, net_score
            return hosts, None

        networks = self.networks + self.add_networks
        network_scores = {}
        scan_results = {}
        net_dir_map = {}

        if self.single_network or len(networks) <= 1 or self.analysis_only:
            # if there is only one or no scan
            hosts, score = do_assessment_helper(networks, self.output_dir)
            if self.single_network or self.analysis_only:
                scan_results = hosts
                if score is not None:
                    network_scores["assessed_network"] = score
            else:
                if (not networks) or util.is_ipv4(networks[0]) or util.is_ipv6(networks[0]):
                    scan_results = hosts
                else:
                    scan_results[networks[0]] = hosts
                if score is not None:
                    network_scores[networks[0]] = score
        else:
            # if there are multiple scans, place results into separate directory
            for i, net in enumerate(networks):
                net_dir_map[net] = "network_%d" % (i + 1)
                hosts, score = do_assessment_helper([net], os.path.join(self.output_dir, net_dir_map[net]))
                scan_results[net] = hosts
                network_scores[net] = score
            if net_dir_map:
                net_dir_map_out = os.path.join(self.output_dir, NET_DIR_MAP_FILE)
                with open(net_dir_map_out, "w") as file:
                    file.write(json.dumps(net_dir_map, ensure_ascii=False, indent=3))

        # visualize results
        results = network_scores if not self.scan_only else scan_results
        if results is not None:
            outfile = os.path.join(self.output_dir, "results.json")
            outfile_orig = os.path.join(self.orig_out_dir, "results.json")

            visualizer.visualize_dict_results(results, outfile)
            self.logger.info("The main output file is called '%s'", outfile)
            print("The main output file is called: %s" % outfile_orig)

        self.logger.info("All created files have been written to '%s'", self.output_dir)  # use absolute path
        print("All created files have been written to: %s" % self.orig_out_dir)  # use relative path
