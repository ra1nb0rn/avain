import copy
import hashlib
import importlib
import inspect
import logging
import os
import shutil
import threading

import core.utility as util
from core.result_types import ResultType
from core.result_processor import InvalidResultException
from core.scan_result_processor import ScanResultProcessor
from core.vuln_score_processor import VulnScoreProcessor

SHOW_PROGRESS_SYMBOLS = ["\u2502", "\u2571", "\u2500", "\u2572",
                         "\u2502", "\u2571", "\u2500", "\u2572"]
PRINT_LOCK_ACQUIRE_TIMEOUT = 1  # in s
DEFAULT_JOIN_TIMEOUT = 0.38
MODULE_DIR_PREFIX = "modules"
MODULE_FUNCTION = "run"
USER_RESULT_DIR = "user_results"
UPDATE_OUT_DIR = "update_output"

RESULT_AGGR_DIRS = {ResultType.SCAN: "scan_result_aggregation",
                    ResultType.VULN_SCORE: "vuln_score_aggregation"}

class ModuleManager():

    def __init__(self, networks: list, output_dir: str, omit_networks: list, ports: list,
                 user_results: dict, config: dict, verbose: bool):
        """ Construct a module manager instance"""

        self.networks = networks
        self.omit_networks = omit_networks
        self.ports = ports
        self.user_results = user_results
        self.config = config
        self.verbose = verbose
        self.output_dir = output_dir

        self.hosts = set()
        self.logger = logging.getLogger(self.__module__)
        self.join_timeout = DEFAULT_JOIN_TIMEOUT
        self.results = {}
        self._set_modules()
        self._setup_result_processors()
        self._add_user_results()

    def _set_modules(self):
        """Assign the modules to use for the assessment"""

        # actual assessment modules
        config_modules = self.config["core"].get("modules", None)
        if config_modules is None:
            util.printit("Warning: No modules specified in config file(s)\n" +
                         "Did you modify the default config file?", color=util.RED)

        self.modules = []
        for module in config_modules.split(","):
            module_path = os.path.join(MODULE_DIR_PREFIX, module.strip()).replace(".", os.sep)
            self.modules.append(module_path + ".py")

    def _add_user_results(self):
        for rtype, result_file in self.user_results.items():
            relpath, abspath = result_file
            basename = os.path.basename(abspath)
            user_result_dir = os.path.join(self.output_dir, USER_RESULT_DIR)
            copy_path = os.path.join(os.path.join(user_result_dir, rtype.value.lower()), basename)
            copy_path = ModuleManager.save_copy_file(abspath, copy_path)
            try:
                result = self.result_processors[rtype].parse_result_file(copy_path)
                self.result_processors[rtype].add_to_results(relpath, result)
            except InvalidResultException as e:
                util.printit(e, color=util.RED)

    def _setup_result_processors(self):
        """Setup the different result processors"""
        self.result_processors = {
            ResultType.SCAN: ScanResultProcessor(os.path.join(self.output_dir,
                                                 RESULT_AGGR_DIRS[ResultType.SCAN]), self.config),
            ResultType.VULN_SCORE: VulnScoreProcessor(os.path.join(self.output_dir,
                                                      RESULT_AGGR_DIRS[ResultType.VULN_SCORE]))
        }

    def set_output_dir(self, directory: str):
        """Change output directory of the module manager (and thereby its result processors)"""
        self.output_dir = directory
        for rtype, result_processor in self.result_processors.items():
            result_processor.set_output_dir(os.path.join(self.output_dir, RESULT_AGGR_DIRS[rtype]))

    @staticmethod
    def _get_module_name(module_path: str):
        """Return the name of the module specified by the filepath"""

        module_name = module_path.replace(os.sep, ".")
        return module_name.replace(".py", "")

    def set_networks(self, networks):
        self.networks = networks

    def update_modules(self):
        self.update_modules = ModuleManager.find_all_prefixed_modules("%s/" % MODULE_DIR_PREFIX, "module_updater")
        self.run_modules(self.update_modules, mtype="update")

    def run(self):
        self.run_modules(self.modules)

    def run_modules(self, modules, mtype=""):
        """
        Run the given modules
        """

        def get_created_files(module):
            """ Retrieve all files created by the module """

            created_files = []
            for attr, val in inspect.getmembers(module):
                if attr == "CREATED_FILES":
                    created_files = val
                    break
            return created_files


        # create the output directory for all module results
        os.makedirs(self.output_dir, exist_ok=True)

        if mtype:
            self.logger.info("Invoking the available %s-modules" % mtype)
            print(util.BRIGHT_BLUE + "Running the available %s-modules:" % mtype)
        else:
            self.logger.info("Invoking the available modules")
            print(util.BRIGHT_BLUE + "Running the available modules:")

        if len(modules) == 1:
            self.logger.info("1 module was found")
        else:
            self.logger.info("%d modules were found", len(modules))
        self.logger.debug("The following modules have been found: %s" % ", ".join(modules))

        # iterate over all available modules
        for i, module_path in enumerate(modules):
            # get module name
            module_name = self._get_module_name(module_path)
            module_name_no_prefix = module_name.replace("%s." % MODULE_DIR_PREFIX, "", 1)

            # import the respective python module
            module = importlib.import_module(module_name)

            # change into the module's directory
            main_cwd = os.getcwd()
            os.chdir(os.path.dirname(module_path))

            # set the module's parameters (e.g. config, verbosity, ...)
            self._set_module_parameters(module)

            # setup execution of module with its specific function to run
            self.logger.info("Invoking module %d of %d - %s", i+1,
                             len(modules), module_name_no_prefix)
            module_results = []
            module_func = getattr(module, MODULE_FUNCTION, None)
            if not module_func:
                self.logger.warning("Module '%s' does not have a '%s' function. Module is skipped.",
                                    module_name, MODULE_FUNCTION)
                os.chdir(main_cwd)
                continue

            module_thread = threading.Thread(target=module_func, args=(module_results,))

            # run module
            module_thread.start()
            show_progress_state = 0
            while module_thread.is_alive():
                module_thread.join(timeout=self.join_timeout)

                if not util.PRINT_MUTEX.acquire(timeout=PRINT_LOCK_ACQUIRE_TIMEOUT):
                    continue

                print(util.GREEN + "Running module %d of %d - " % (i+1, len(modules)), end="")
                print(util.SANE + module_name_no_prefix + "  ", end="")
                print(util.YELLOW + SHOW_PROGRESS_SYMBOLS[show_progress_state])
                print(util.SANE, end="")  # cleanup colors
                util.clear_previous_line()

                util.PRINT_MUTEX.release()

                if (show_progress_state + 1) % len(SHOW_PROGRESS_SYMBOLS) == 0:
                    show_progress_state = 0
                else:
                    show_progress_state += 1

            # change back into the main directory
            os.chdir(main_cwd)

            created_files = get_created_files(module)
            if mtype != "update" and module_results:
                for i, res in enumerate(module_results):
                    if not isinstance(res, tuple):
                        self.logger.warning("Warning - module '%s' returned a non-tuple result: %s", module_name, type(res))
                        util.printit("Warning - module '%s' returned a non-tuple result: %s\n" %
                                     (module_name, type(res)), color=util.RED)
                        del module_results[i]
                self._process_module_results(module_path, module_results, created_files)
            elif mtype == "update":
                update_output_dir = os.path.join(self.output_dir, UPDATE_OUT_DIR)
                module_output_dir = os.path.join(update_output_dir, os.sep.join(module_name_no_prefix.split(".")[:-1]))
                os.makedirs(module_output_dir, exist_ok=True)
                ModuleManager.move_files_to_outdir(created_files, os.path.dirname(module_path), module_output_dir)
            else:
                self.logger.info("Module %s did not return any results" % module_name)

            self.logger.info("Module %d of %d completed", i+1, len(modules))

        if len(modules) == 1:
            print(util.GREEN + "The one module has completed.")
        else:
            print(util.GREEN + "All %d modules have completed." % len(modules))
        print(util.SANE)
        self.logger.info("All modules have been executed")

    def _process_module_results(self, module_path: str, results: list, created_files: list):
        """
        Process the given modules results, i.e. move all result files and parse the main results
        """

        # create output directory for the module's results
        module_name = self._get_module_name(module_path)
        module_name_short = module_name.replace("%s." % MODULE_DIR_PREFIX, "", 1)
        module_output_dir = os.path.join(self.output_dir, MODULE_DIR_PREFIX)
        module_output_dir = os.path.join(module_output_dir,
                                         os.sep.join(module_name_short.split(".")[:-1]))
        os.makedirs(module_output_dir, exist_ok=True)

        for rtype, result in results:
            if rtype in ResultType:
                # if module provides result as file, parse it to a python data structure
                is_valid_result, is_file_result = True, False
                if isinstance(result, str):
                    try:
                        result = self.result_processors[rtype].parse_result(result)
                        is_file_result = True
                    except InvalidResultException as e:
                        is_valid_result = False
                else:
                    is_valid_result = self.result_processors[rtype].__class__.is_valid_result(result)

                # if result is valid, store it
                if is_valid_result:
                    # if not in single network mode, delete hosts outside of the network
                    if len(self.networks) == 1:
                        util.del_hosts_outside_net(result, self.networks[0])

                    if not is_file_result:
                        result_path = os.path.join(module_output_dir, "%s_result.json" % rtype.value.lower())
                        if os.path.isfile(result_path):
                            base, ext = os.path.splitext(result_path)
                            name_hash = hashlib.sha256(module_name_short.encode()).hexdigest()[:5]
                            result_path = base + name_hash + ext
                        self.result_processors[rtype].store_result(result, result_path)
                        if not result_path in created_files:
                            created_files.append(result_path)

                    self.result_processors[rtype].add_to_results(module_path, result)
                else:
                    self.logger.warning("Warning - module '%s' returned an unprocessable %s result: %s\n",
                                        module_name, rtype.value, result)
                    util.printit("Warning - module '%s' returned an unprocessable %s result: %s\n" %
                                 (module_name, rtype.value, result), color=util.RED)
            else:
                self.logger.warning("Warning - module '%s' returned a result with unknown type: %s\n",
                                    module_name, rtype.value)
                util.printit("Warning - module '%s' returned a result with unknown type: %s\n" %
                             (module_name, rtype.value), color=util.RED)

        # move all created files into the output directory of the current module
        ModuleManager.move_files_to_outdir(created_files, os.path.dirname(module_path),
                                           module_output_dir)


    @staticmethod
    def move_files_to_outdir(created_files: list, module_dir: str, module_output_dir: str):
        """ Move all files in created_files from module_dir to module_output_dir. """

        for file in created_files:
            if os.path.isabs(module_output_dir):
                file_out_dir = module_output_dir
            else:
                rel_dir = os.path.dirname(file)
                if os.path.isabs(rel_dir):
                    rel_dir = os.path.relpath(rel_dir, os.path.abspath(module_dir))
                file_out_dir = os.path.join(module_output_dir, rel_dir)
            os.makedirs(file_out_dir, exist_ok=True)
            file_out_path = os.path.join(file_out_dir, os.path.basename(file))
            if os.path.isabs(file) and os.path.isfile(file):
                shutil.move(file, file_out_path)
            else:
                abs_file = os.path.join(module_dir, file)
                if os.path.isfile(abs_file):
                    shutil.move(abs_file, file_out_path)

    @staticmethod
    def save_copy_file(infile: str, outfile: str):
        # Find a unique name for the file when it is copied to the result directory
        i = 1
        while os.path.isfile(outfile):
            outname, ext = os.path.splitext(os.path.basename(outfile))
            outdir = os.path.dirname(outfile)
            if not outname.endswith("_%d" % i):
                # remove number from last iteration if exists
                if outname.endswith("_%d" % (i-1)):
                    outname = outname[:outname.rfind("_%d" % (i-1))]
                outfile = os.path.join(outdir, outname + "_%d" % i + ext)
            i += 1
        # Copy and load the file result
        os.makedirs(os.path.dirname(outfile), exist_ok=True)
        shutil.copyfile(infile, outfile)
        return outfile

    def get_network_vuln_score(self):
        if ResultType.VULN_SCORE in self.results:
            return self.results[ResultType.VULN_SCORE]
        return "N/A"

    def store_results(self):
        # store results in files
        for rtype, result in self.results.items():
            filename = os.path.join(self.result_processors[rtype].output_dir,
                                    rtype.value.lower() + "_result.json")
            self.result_processors[rtype].store_aggregated_result(result, filename)

    def create_results(self):
        for rtype, result_processor in self.result_processors.items():
            self.results[rtype] = result_processor.aggregate_results()

    def get_results(self):
        return copy.deepcopy(self.results)

    def print_results(self):
        rtypes = [rtype.strip() for rtype in self.config["core"].get("print_result_types", "").split(",")]
        for rtype, result in self.results.items():
            if rtype.value in rtypes:
                util.printit("%s Result:" % rtype.value, color=util.BRIGHT_BLUE)
                self.result_processors[rtype].print_aggr_result(result)
                print()

    def reset_results(self):
        for _, result_processor in self.result_processors.items():
            result_processor.reset()
            if os.path.isdir(result_processor.output_dir):
                if not os.listdir(result_processor.output_dir):
                    shutil.rmtree(result_processor.output_dir)
        self.results = {}

    def _set_module_parameters(self, module):
        """
        Set the given modules's parameters depening on which parameters it has declared.

        :param module: the module whose parameters to set
        """
        all_module_attributes = [attr_tuple[0] for attr_tuple in inspect.getmembers(module)]

        # "normal" parameters
        if "VERBOSE" in all_module_attributes:
            module.VERBOSE = self.verbose

        if "CONFIG" in all_module_attributes:
            module_name = module.__name__.replace("modules.", "", 1)
            module.CONFIG = self.config.get(module_name, {})

        if "CORE_CONFIG" in all_module_attributes:
            module.CONFIG = copy.deepcopy(self.config.get("core", {}))

        if "NETWORKS" in all_module_attributes:
            module.NETWORKS = copy.deepcopy(self.networks)

        if "OMIT_NETWORKS" in all_module_attributes:
            module.OMIT_NETWORKS = copy.deepcopy(self.omit_networks)

        if "PORTS" in all_module_attributes:
            module.PORTS = copy.deepcopy(self.ports)

        if "HOSTS" in all_module_attributes:
            self._extend_networks_to_hosts()
            module.HOSTS = copy.deepcopy(self.hosts)

        # intermediate results
        if "PUT_RESULT_TYPES" in all_module_attributes:
            intermediate_results = {}
            for rtype in module.PUT_RESULT_TYPES:
                if rtype in ResultType or rtype in ResultType.values():
                    intermediate_results[rtype] = copy.deepcopy(self.result_processors[rtype].aggregate_results())
                else:
                    util.printit("Warning - module '%s' requested an intermediate result " % module_name +
                                 "with an unknown type: %s\n" % rtype, color=util.RED)
            if "PUT_RESULTS" in all_module_attributes:
                module.PUT_RESULTS = intermediate_results

    def _extend_networks_to_hosts(self):
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

        if not self.hosts:
            for net in self.networks:
                add_to_hosts(net)

            for network in self.omit_networks:
                hosts = util.extend_network_to_hosts(network)
                if isinstance(hosts, list):
                    self.hosts = self.hosts - set(hosts)
                else:
                    self.hosts.remove(hosts)

            self.hosts = list(self.hosts)

    @staticmethod
    def find_all_prefixed_modules(start_dir: str, prefix: str):
        """
        Recursively find all modules/files prefixed with the specified prefix
        located in the specified subdirectory.

        :param start_dir: The base directory of the search
        :param prefix: The prefix to look for in filenames
        """

        all_prefixed_files = []
        for root, _, files in os.walk(start_dir):
            for file in files:
                if "__pycache__" in root:
                    continue
                if file.startswith(prefix) and file.endswith(".py"):
                    all_prefixed_files.append(root + os.sep + file)
        return all_prefixed_files
