from abc import ABCMeta, abstractmethod
import json
import logging
import math
import os

import core.utility as util

class ResultProcessor(metaclass=ABCMeta):

    def __init__(self, output_dir: str, results: dict = None):
        if results is None:
            results = {}
        self.output_dir = output_dir
        self.results = results
        self.logger = logging.getLogger(self.__module__)

    def add_to_results(self, result_id: str, result):
        """Add the given result identified by its ID to the list of results"""

        self.results[result_id] = result

    def reset(self):
        """Return the name of the subdirectory the results should be put in"""

        self.results = {}

    def set_output_dir(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def parse_result_from_json_file(self, filepath: str):
        if not os.path.isfile(filepath):
            self.logger.warning("Specified result '%s' is not a file", filepath)
            raise InvalidResultException(filepath, "File does not exist")

        try:
            with open(filepath) as file:
                try:
                    return json.load(file)
                except json.decoder.JSONDecodeError:
                    self.logger.warning("JSON of custom result stored in '%s' cannot be parsed",
                                        filepath)
                    raise InvalidResultException(filepath, "Json file cannot be parsed")
        except IOError:
            self.logger.warning("Specified custom result '%s' cannot be opened", filepath)
            raise InvalidResultException(filepath, "File cannot be opened")

    @abstractmethod
    def aggregate_results(self):
        """Aggregate the given results to one (representative) result"""

        raise NotImplementedError

    @abstractmethod
    def parse_result_file(self, filepath: str):
        """Return the type of results the processor class handles"""

        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def is_valid_result(result):
        """Return True if the result is valid"""
        
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def store_result(filepath: str):
        """Return the type of results the processor class handles"""

        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def store_aggregated_result(filepath: str):
        """Return the type of results the processor class handles"""

        raise NotImplementedError

    @staticmethod
    def print_result(result):
        print(result)

    @staticmethod
    def print_aggr_result(result):
        print(result)

    @staticmethod
    def sort_result_by_ip(result):
        """ "sort" results by IP """
        def sort_func(ip: str):
            try:
                return util.ip_str_to_int(ip)
            except:
                return math.inf

        sorted_result = {}
        for k_ip in sorted(result, key=sort_func):
            sorted_result[k_ip] = result[k_ip]
        return sorted_result

    @staticmethod
    def store_json_convertable_result(result: dict, filepath: str):
        """Store the given result at the specified location"""

        with open(filepath, "w") as file:
            file.write(json.dumps(result, ensure_ascii=False, indent=3))

class InvalidResultException(Exception):
    """Exception class to signal an invalid result"""

    def __init__(self, result, message: str):
        self.result = result
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.message, self.result)
