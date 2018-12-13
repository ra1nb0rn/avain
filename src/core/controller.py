import json
import logging
import os
import sys

from core.module_manager import ModuleManager
from core.scan_result_processor import ScanResultProcessor
from core.vuln_score_processor import VulnScoreProcessor
import core.utility as util
import core.visualizer as visualizer

LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGFILE = "avain.log"
DEFAULT_CONFIG_PATH = "%s%sconfig/default_config.txt" % (os.environ["AVAIN_DIR"], os.sep)
NET_DIR_MAP_FILE = "net_dir_map.json"

class Controller():

    def __init__(self, networks: list, add_networks: list, omit_networks: list, update_modules: bool,
                 config_path: str, ports: list, output_dir: str, user_results: dict,
                 single_network: bool, verbose: bool):
        """
        Create a Controller object.

        :param networks: A list of strings specifying the networks to analyze
        :param add_networks: A list of networks as strings to additionally analyze
        :param omit_networks: A list of networks as strings to omit from the analysis
        :param update_modules: Whether modules should be updated or initialized
        :param config_path: The path to a config file
        :param ports: A list of port expressions
        :param output_dir: A string specifying the output directory of the analysis
        :param user_results: A list of filenames whose files contain user provided results
        :param single_network: A boolean specifying whether all given networks are to be considered
                               hosts in one single network
        :param vebose: Specifying whether to provide verbose output or not
        """

        self.networks = networks if networks is not None else []
        self.networks += add_networks if add_networks is not None else []
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
        self.user_results = {}

        if user_results:
            for rtype, filenames in user_results.items():
                if rtype not in self.user_results:
                    self.user_results[rtype] = []
                for filename in filenames:
                    self.user_results[rtype] = (filename, os.path.abspath(filename))

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
        self.ports = ports
        self.update_modules = update_modules

        # setup module_manager
        self.module_manager = ModuleManager(self.networks, self.output_dir, self.omit_networks, self.ports,
                                            self.user_results, self.config, self.verbose)

        # setup logging
        self.setup_logging()
        self.logger.info("Starting the AVAIN program")
        self.logger.info("Executed call: avain %s", " ".join(sys.argv[1:]))

        # inform user about not being root
        if networks and os.getuid() != 0:
            print(util.MAGENTA + "Warning: not running this program as root user leads"
                  " to a less effective assessment (e.g. with nmap)\n" + util.SANE, file=sys.stderr)

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
            self.module_manager.update_modules()
            self.module_manager.reset_results()

        if self.networks or self.user_results:
            self.do_assessment()

        self.logger.info("All created files have been written to '%s'", self.output_dir)  # use absolute path
        print("All created files have been written to: %s" % self.orig_out_dir)  # use relative path

        # change back to original directory
        os.chdir(self.original_cwd)


    def do_assessment(self):
        """
        Conduct the vulnerability assessment either in "normal" or "single network mode".
        """

        networks = self.networks
        net_dir_map = {}
        network_vuln_scores = {}

        def do_network_assessment(networks: list, out_dir: str):
            nonlocal network_vuln_scores
            self.module_manager.set_networks(networks)
            self.module_manager.set_output_dir(out_dir)
            self.module_manager.run()
            self.module_manager.create_results()
            self.module_manager.store_results()
            self.module_manager.print_results()
            net_score = self.module_manager.get_network_vuln_score()
            self.module_manager.reset_results()
            return net_score

        if self.single_network or len(networks) <= 1:
            # if there is only one assessment
            score = do_network_assessment(networks, self.output_dir)
            if self.single_network or not self.networks:
                if score is not None:
                    network_vuln_scores["assessed_network"] = score
            else:
                if score is not None:
                    network_vuln_scores[networks[0]] = score
        else:
            # if there are multiple scans, place results into separate directory
            for i, net in enumerate(networks):
                util.printit("Assessment of network %s" % net, color=util.YELLOW)
                util.printit("===========================================", color=util.YELLOW)
                net_dir_map[net] = "network_%d" % (i + 1)
                score = do_network_assessment([net], os.path.join(self.output_dir, net_dir_map[net]))
                network_vuln_scores[net] = score
            if net_dir_map:
                net_dir_map_out = os.path.join(self.output_dir, NET_DIR_MAP_FILE)
                with open(net_dir_map_out, "w") as file:
                    file.write(json.dumps(net_dir_map, ensure_ascii=False, indent=3))

        # visualize results
        if not all((not score) or score == "N/A" for score in network_vuln_scores):
            outfile = os.path.join(self.output_dir, "network_vulnerability_ratings.json")
            outfile_orig = os.path.join(self.orig_out_dir, "network_vulnerability_ratings.json")

            visualizer.visualize_dict_results(network_vuln_scores, outfile)
            self.logger.info("The main output file is called '%s'", outfile)
            print("The main output file is called: %s" % outfile_orig)
