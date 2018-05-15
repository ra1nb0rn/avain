from collections import Counter
import logging
import math
import re

LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

def compute_cosine_similarity(text_1: str, text_2: str):
    """
    Compute the cosine similarity of two text strings.
    :param text_1: the first text
    :param text_2: the second text
    :return: the cosine similarity of the two text strings
    """

    def text_to_vector(text: str):
        """
        Get the vector representation of a text. It stores the word frequency
        of every word contained in the given text.
        :return: a Counter object that stores the word frequencies in a dict with the respective word as key
        """
        word = re.compile(r'\w+')
        words = word.findall(text)
        return Counter(words)

    text_vector_1, text_vector_2 = text_to_vector(text_1), text_to_vector(text_2)

    intersecting_words = set(text_vector_1.keys()) & set(text_vector_2.keys())
    inner_product = sum([text_vector_1[w] * text_vector_2[w] for w in intersecting_words])

    abs_1 = math.sqrt(sum([cnt**2 for cnt in text_vector_1.values()]))
    abs_2 = math.sqrt(sum([cnt**2 for cnt in text_vector_2.values()]))
    normalization_factor = abs_1 * abs_2

    if not normalization_factor:  # avoid divison by 0
        return 0.0
    else:
        return float(inner_product)/float(normalization_factor) 


def get_logger(module_name: str, logfile: str):
    """
    Create a logger with the given module name logging to the given logfile.

    :param module_name: the name of the module the logger is for
    :param logile: filepath to the logfile
    :return: a logger with the specified attributes
    """
    
    logger = logging.getLogger(module_name)
    logger.setLevel(logging.INFO)

    # create log file handler
    handler = logging.FileHandler(logfile, encoding="utf-8")
    handler.setLevel(logging.INFO)

    # create logging format
    formatter = logging.Formatter(LOGGING_FORMAT)
    handler.setFormatter(formatter)

    # add the handler to the logger
    logger.addHandler(handler)

    return logger