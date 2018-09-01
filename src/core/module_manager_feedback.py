from abc import abstractmethod
import json
import os
import shutil

import core.utility as util
from core.module_manager import ModuleManager

class ModuleManagerFeedback(ModuleManager):
    def __init__(self, output_dir: str, config: dict, logfile: str, verbose: bool,
                 add_results: list):
        super().__init__(output_dir, config, logfile, verbose)
        self.add_results = add_results
        self.classname = self.__class__.__name__.lower()
        self.add_results_dir = self._assign_add_results_dir()

    @abstractmethod
    def _only_result_files(self):
        """{}"""
        raise NotImplementedError

    @abstractmethod
    def _construct_result(self):
        """{}"""
        raise NotImplementedError

    @abstractmethod
    def _sort_results(self):
        """{}"""
        raise NotImplementedError 
        
    @abstractmethod
    def _cleanup(self):
        """{}"""
        raise NotImplementedError

    @abstractmethod
    def _assign_add_results_dir(self):
        """{}"""
        raise NotImplementedError

    def _sort_results_by_ip(self):
        """ "sort" results by IP """
        sorted_result = {}
        for k_ip in sorted(self.result, key=lambda ip: util.ip_str_to_int(ip)):
            sorted_result[k_ip] = self.result[k_ip]
        self.result = sorted_result

    def run(self):
        """
        Run all of the modules, aggregate their feedback / results and return it as dict

        :return: A dict with the aggregated module results
        """

        self.logger.info("Starting %s phase", self.mgmt_type)
        os.makedirs(self.output_dir, exist_ok=True)
        if self.add_results:
            self._include_additional_results()
        if not self._only_result_files():
            self._run_modules()
        self._sort_results()
        self.logger.info("Aggregating results")
        self.result = self._construct_result()

        self._cleanup()
        self._store_results()
        self.logger.info("%s phase completed", self.mgmt_type.capitalize())
        return self.result

    def _include_additional_results(self):
        """
        Include additional results provided by the user
        """

        self.logger.info("Including additional %s result(s): %s",
                         self.classname, ", ".join(self.add_results))
        add_results_dir = os.path.join(self.output_dir, self.add_results_dir)
        os.makedirs(add_results_dir, exist_ok=True)
        # Iterate over every given file containing a result
        for filepath in self.add_results:
            if not os.path.isfile(filepath):
                self.logger.warning("Specified %s result '%s' is not a file",
                                    self.classname, filepath)
            try:
                # Find a unique name for the file when it is copied to the result directory
                copy_filepath = os.path.join(add_results_dir, os.path.basename(filepath))
                i = 1
                while os.path.isfile(copy_filepath):
                    alt_name, ext = os.path.splitext(os.path.basename(copy_filepath))
                    if not alt_name.endswith("_%d" % i):
                        if alt_name.endswith("_%d" % (i-1)):
                            alt_name = alt_name[:alt_name.rfind("_%d" % (i-1))]
                        copy_filepath = os.path.join(add_results_dir, alt_name + "_%d" % i + ext)
                    i += 1
                # Copy and load the file result
                shutil.copyfile(filepath, copy_filepath)
                with open(copy_filepath) as f:
                    try:
                        result = json.load(f)
                    except json.decoder.JSONDecodeError:
                        self.logger.warning("JSON of %s result stored in '%s' cannot be parsed.",
                                            self.classname, filepath)
                        continue
            except IOError:
                self.logger.warning("Specified %s result '%s' cannot be opened",
                                    self.classname, filepath)

            # If the result is valid, include it
            if result:
                self._add_to_results(filepath, result)
        self.logger.info("Done.")
