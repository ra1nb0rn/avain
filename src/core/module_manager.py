from abc import ABCMeta, abstractmethod
import copy
import importlib
import inspect
import json
import logging
import os
import shutil
import threading

import core.utility as util

SHOW_PROGRESS_SYMBOLS = ["\u2502", "\u2571", "\u2500", "\u2572",
                         "\u2502", "\u2571", "\u2500", "\u2572"]
PRINT_LOCK_ACQUIRE_TIMEOUT = 1  # in s
DEFAULT_JOIN_TIMEOUT = 0.38

class ModuleManager(metaclass=ABCMeta):

    def __init__(self, output_dir: str, config: dict, verbose: bool):
        # assign subclass independent variables directly
        self.output_dir = output_dir
        self.config = config
        self.logger = logging.getLogger(self.__module__)
        self.verbose = verbose
        self.join_timeout = DEFAULT_JOIN_TIMEOUT
        self.results = {}
        self.result = {}

        (self.modules, self.result_filename, self.mgmt_type,
         self.module_call_func, self.module_dir_prefix,
         self.run_title_str, self.require_result) = self._assign_init_values()

    @abstractmethod
    def run(self):
        """Call to invoke a module manager"""
        raise NotImplementedError

    @abstractmethod
    def _assign_init_values(self):
        """
        Have subclasses initialize the following instance variables:

        :return: a tuple as (modules, result_filename, mgmt_type, module_call_func,
                             module_dir_prefix, run_title_str, require_result) with
                 modules           : the modules to invoke
                 result_filename   : filename of the module manager's final result
                 mgmt_type         : the management type to print (e.g. scan or analysis)
                 module_call_func  : the function for the manager to call when invoking a module
                 module_dir_prefix : the prefix to strip off a module's (python) path when naming it
                 run_title_str     : the common title of the status messages printed when running
                                     modules
                 require_result    : whether modules need to return a result for success
        """

        raise NotImplementedError

    @abstractmethod
    def _set_extra_module_parameters(self, module):
        """Set more specific parameters for the given module"""

        raise NotImplementedError

    def _handle_results(self, module_id, module_result):
        """What to do if a module returns a result"""
        pass

    def _get_call_func(self, module):
        """Get the given module's signature call function"""

        return getattr(module, self.module_call_func, None)

    def _run_modules(self):
        """
        Run the modules stored in self.modules
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

        self.logger.info(self.run_title_str)
        print(util.BRIGHT_BLUE + self.run_title_str + ":")
        if len(self.modules) == 1:
            self.logger.info("1 %s module has been found", self.mgmt_type)
        else:
            self.logger.info("%d %s modules have been found",
                             len(self.modules), self.mgmt_type)
        self.logger.debug("The following %s modules have been found: %s",
                          self.mgmt_type, ", ".join(self.modules))

        # iterate over all available modules
        for i, module_path in enumerate(self.modules):
            # get module name
            module_name = module_path.replace(os.sep, ".")
            module_name = module_name.replace(".py", "")
            module_name_no_prefix = module_name.replace(self.module_dir_prefix, "", 1)

            # import the respective python module
            module = importlib.import_module(module_name)

            # change into the module's directory
            main_cwd = os.getcwd()
            os.chdir(os.path.dirname(module_path))

            # set the module's parameters (e.g. logfile, config, ... + mgmt-type specific params)
            self._set_module_parameters(module)

            # setup execution of module with its specific function to run
            self.logger.info("Starting %s %d of %d - %s",
                             self.mgmt_type, i+1, len(self.modules), module_name_no_prefix)
            module_result = []
            module_func = self._get_call_func(module)
            if not module_func:
                self.logger.warning("Module '%s' does not have a '%s' function. Module is skipped.",
                                    module_name, self.module_call_func)
                continue

            module_thread = threading.Thread(target=self._get_call_func(module),
                                             args=(module_result,))

            # run module
            module_thread.start()
            show_progress_state = 0
            while module_thread.is_alive():
                module_thread.join(timeout=self.join_timeout)

                if not util.PRINT_MUTEX.acquire(timeout=PRINT_LOCK_ACQUIRE_TIMEOUT):
                    continue

                print(util.GREEN + "Conducting %s %d of %d - " %
                      (self.mgmt_type, i+1, len(self.modules)), end="")
                print(util.SANE + module_name_no_prefix + "  ", end="")
                print(util.YELLOW + SHOW_PROGRESS_SYMBOLS[show_progress_state])
                print(util.SANE, end="")  # cleanup colors, if module would like to print
                util.clear_previous_line()

                util.PRINT_MUTEX.release()

                if (show_progress_state + 1) % len(SHOW_PROGRESS_SYMBOLS) == 0:
                    show_progress_state = 0
                else:
                    show_progress_state += 1

            if module_result and isinstance(module_result[0], dict) == 1:
                result = module_result[0]
            else:
                self.logger.info("%s module '%s' delivered an unprocessable result. %s",
                                 self.mgmt_type.capitalize(), module_name,
                                 "Its results have been discarded.")
                result = {}

            created_files = get_created_files(module)

            # change back into the main directory
            os.chdir(main_cwd)

            self._process_module_result(module_name, result, created_files, module_path)

            self.logger.info("%s %d of %d done",
                             self.mgmt_type.capitalize(), i+1, len(self.modules))

        if len(self.modules) == 1:
            print(util.GREEN + "The %s module has completed." % self.mgmt_type)
        else:
            print(util.GREEN + "All %d %s modules have completed." %
                  (len(self.modules), self.mgmt_type))
        print(util.SANE)
        self.logger.info("All %s modules have been executed", self.mgmt_type)

    def _process_module_result(self, module_name, result, created_files, module_path):
        # create output directory for the module's results
        module_name_short = module_name.replace(self.module_dir_prefix, "", 1)
        module_output_dir = os.path.join(self.output_dir,
                                         os.sep.join(module_name_short.split(".")[:-1]))
        os.makedirs(module_output_dir, exist_ok=True)

        module_dir = os.path.dirname(module_path)
        # process the module's potential result
        if isinstance(result, str):  # if module provides json output file
            # add result file to created_files (in case module has not)
            if result not in created_files:
                created_files.add(result)

            # parse the json output into a python dict
            result_path = result
            if not os.path.isabs(result_path):
                result_path = os.path.join(module_dir, result_path)
            try:
                with open(result_path) as file:
                    self._handle_results(module_path, json.load(file))
            except Exception as excpt:
                print(util.RED + "Warning: %s result from module '%s' could not be used.\n" %
                      (self.mgmt_type, module_name) +
                      "Only JSON files or python dicts can be used.")
                print("Exception: %s" % str(excpt))
                print(util.SANE)
        elif isinstance(result, dict):  # if module provides output as python dict
            module_result_path = os.path.join(module_output_dir, "result.json")
            with open(module_result_path, "w") as file:  # write dict output to json file
                file.write(json.dumps(result, ensure_ascii=False, indent=3))
            self._handle_results(module_path, result)
        elif self.require_result:  # if result cannot be processed, skip this module
            print(util.RED + "Warning: %s results from module '%s' could not be used.\n" %
                  (self.mgmt_type, module_name) + "Only JSON files or python dicts can be used.")
            print(util.SANE)

        # move all created files into the output directory of the current module
        ModuleManager.move_files_to_outdir(created_files, os.path.dirname(module_path),
                                           module_output_dir)

    def _set_module_parameters(self, module):
        """
        Set the given modules's parameters depening on which parameters it has declared.

        :param module: the module whose parameters to set
        """
        all_module_attributes = [attr_tuple[0] for attr_tuple in inspect.getmembers(module)]

        if "VERBOSE" in all_module_attributes:
            module.VERBOSE = self.verbose

        if "CONFIG" in all_module_attributes:
            module.CONFIG = self.config.get(module.__name__, {})

        if "CORE_CONFIG" in all_module_attributes:
            module.CONFIG = copy.deepcopy(self.config.get("core", {}))

        self._set_extra_module_parameters(module)

    @staticmethod
    def move_files_to_outdir(created_files: list, module_dir: str, module_output_dir: str):
        """ Move all files in created_files from module_dir to module_output_dir. """
        for file in created_files:
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
