import importlib
import inspect
import os
import sys
import threading

from analyzer import Analyzer
import module_seeker
from scanner import Scanner
import utility as util
import visualizer

SHOW_PROGRESS_SYMBOLS = ["\u2502", "\u2571", "\u2500", "\u2572", "\u2502", "\u2571", "\u2500", "\u2572"]
UPDATER_JOIN_TIMEOUT = 0.38
DEFAULT_CONFIG_PATH = "default_config.txt"

class Controller():

    def __init__(self, networks: list, add_networks: list, omit_networks: list, update_databases: bool, config_path: str,
                ports: list, output_dir: str, online_only: bool, scan_results: list, analysis_results: list, time: bool,
                verbose: bool, scan_only: bool, analysis_only: bool):
        """
        Create a Controller object.

        :param network: A string representing the network to analyze
        :param add_networks: A list of networks as strings to additionally analyze
        :param omit_networks: A list of networks as strings to omit from the analysis
        :param update_databases: Whether databases should be upgraded or created if they do not exist
        :param config_path: The path to a config file
        :param ports: A list of port expressions
        :param output_dir: A string specifying the output directory of the analysis
        :param online_only: Specifying whether to look up information only online (where applicable) 
        :param scan_results: A list of filenames whose files contain additional scan results
        :param analysis_results: A list of filenames whose files contain additional analysis results
        :param time: A boolean specifying whether to measure the required ananlysis time
        :param vebose: Specifying whether to provide verbose output or not
        :param scan_only: Whether to only do a network scan
        :param analysis_only: Whether to only do an analysis with the specified scan results
        """

        self.networks = networks
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

        # change into AVAIN directory
        self.original_cwd = os.getcwd()
        core_dir = os.path.dirname(os.path.join(os.path.realpath(__file__)))
        avain_dir = os.path.abspath(os.path.join(core_dir, os.pardir))
        os.chdir(avain_dir)

        # parse configs
        if os.path.isfile(DEFAULT_CONFIG_PATH):
            try:
                self.config = util.parse_config(DEFAULT_CONFIG_PATH)
            except:
                print(util.MAGENTA + "Warning: Could not parse default config file. Proceeding without default config.\n" + util.SANE, file=sys.stderr)
        elif not config_path:
            print(util.MAGENTA + "Warning: Could not find default config.\n" + util.SANE, file=sys.stderr)

        if config_path:
            try:
                util.upgrade_config(config_path, self.config)
            except:
                print(util.MAGENTA + "Warning: Could not parse custom config file. Proceeding without custom config.\n" + util.SANE, file=sys.stderr)

        # set variables
        self.online_only = online_only
        self.scan_results = scan_results
        self.analysis_results = analysis_results
        self.time = time
        self.verbose = verbose
        self.hosts = set()
        self.ports = ports
        self.update_databases = update_databases
        self.scan_only = scan_only
        self.analysis_only = analysis_only

        # setup logging
        self.logfile = os.path.abspath(os.path.join(self.output_dir, "avain.log"))
        if os.path.isfile(self.logfile):
            os.remove(self.logfile)  # delete logging file if it already exists (from a previous run)
        self.logger = util.get_logger(__name__, self.logfile)
        self.logger.info("Starting the AVAIN program")

        # inform user about not being root
        if (networks or add_networks) and os.getuid() != 0:
            print(util.MAGENTA + "Warning: not running this program as root user leads"
                " to less effective scanning (e.g. with nmap)\n" + util.SANE, file=sys.stderr)

    def run(self):
        """
        Execute the main program depending on the given program parameters.
        """

        if self.update_databases:
            self.start_database_updates()

        if self.networks or self.add_networks or self.analysis_only:
            self.do_analysis()

        # change back to original directory
        os.chdir(self.original_cwd)

    def start_database_updates(self):
        """
        Update all databases by finding the responsible modules and calling their update method.
        """

        def set_module_parameters(module):
            """
            Set a modules update parameters
            """
            all_module_attributes = [attr_tuple[0] for attr_tuple in inspect.getmembers(module)]
            if "VERBOSE" in all_module_attributes:
                module.VERBOSE = self.verbose
            if "LOGFILE" in all_module_attributes:
                module.LOGFILE = self.logfile

        update_modules = module_seeker.find_all_database_updater_modules()
        # util.hide_cursor()  # hide cursor
        self.logger.info("Starting database update(s)")
        print(util.BRIGHT_BLUE + "Starting database updates:")
        self.logger.info("%d database update module(s) have been found" % len(update_modules))
        self.logger.debug("The following database update modules have been found: %s"
            % ", ".join(update_modules))

        # iterate over all available update modules
        for i, update_module_path in enumerate(update_modules):
            # get update module name
            update_module = update_module_path.replace(os.sep, ".")
            update_module = update_module.replace(".py", "")

            # import the respective python module
            module = importlib.import_module(update_module)

            # change into the module's directory
            main_cwd = os.getcwd()
            module_dir = os.path.dirname(update_module_path)
            os.chdir(module_dir)

            # set the module's scan parameters (e.g. network, ports, etc.)
            set_module_parameters(module)

            # initiate the module's update procedure
            self.logger.info("Starting database update %d of %d" % (i+1, len(update_modules)))
            update_thread = threading.Thread(target=module.update_database)

            update_thread.start()
            # TODO: Check for TTY (https://www.tutorialspoint.com/python/os_isatty.htm or other)
            show_progress_state = 0
            while update_thread.is_alive():
                update_thread.join(timeout=UPDATER_JOIN_TIMEOUT)
                print(util.GREEN + "Conducting update %d of %d  " % (i+1, len(update_modules)), end="")
                print(util.YELLOW + SHOW_PROGRESS_SYMBOLS[show_progress_state])
                util.clear_previous_line()
                if (show_progress_state + 1) % len(SHOW_PROGRESS_SYMBOLS) == 0:
                    show_progress_state = 0
                else:
                    show_progress_state += 1

            # change back into the main directory
            os.chdir(main_cwd)
            self.logger.info("Database update %d of %d done" % (i+1, len(update_modules)))

        if len(update_modules) == 1:
            print(util.GREEN + "Update completed.")
        else:
            print(util.GREEN + "All %d updates completed." % len(update_modules))
        print(util.SANE)
        self.logger.info("All database update(s) completed")

    def do_analysis(self):
        """
        First conduct network reconnaissance and then analyze the hosts
        of the specified network for vulnerabilities.
        """

        scanner = Scanner(self.networks, self.add_networks, self.omit_networks, self.config, self.ports, self.output_dir,
                            self.online_only, self.verbose, self.logfile, self.scan_results, self.analysis_only)
        hosts = scanner.conduct_scans()

        if not self.scan_only:
            analyzer = Analyzer(hosts, self.config, self.output_dir, self.online_only, self.verbose, self.logfile) 
            scores = analyzer.conduct_analyses()
            outfile = os.path.join(self.output_dir, "results.txt")
            visualizer.visualize_dict_results(scores, outfile)
            self.logger.info("The main output file is called '%s'" % outfile)

        self.logger.info("All created files have been written to '%s'" % self.output_dir)
        print("All created files have been written to: %s" % self.orig_out_dir)
        if not self.scan_only:
            outfile = os.path.join(self.orig_out_dir, "results.txt")
            print("The main output file is called: %s" % outfile)
