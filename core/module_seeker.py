import os

def find_all_scanners_modules():
    """
    Find all modules/files prefixed with 'scanner_' located in the subdirectory 'modules/scanner'.
    
    :return: all filenames of scanner modules
    """

    return find_all_prefixed_modules("modules/scanner", "scanner_")

def find_all_analyzer_modules():
    """
    Find all modules/files prefixed with 'analyzer_' located in the subdirectory 'modules/analyzer'.

    :return: all filenames of analyzer modules
    """

    return find_all_prefixed_modules("modules/analyzer", "analyzer_")

def find_all_module_updater_modules():
    """
    Find all modules/files prefixed with 'module_updater' located in the subdirectory 'modules'.

    :return: all filenames of module updater modules
    """

    return find_all_prefixed_modules("modules", "module_updater")

def find_all_prefixed_modules(start_dir: str, prefix: str):
    """
    Recursively find all modules/files prefixed with the specified prefix
    located in the specified subdirectory.

    :param start_dir: The base directory of the search
    :param prefix: The prefix to look for in filenames
    """

    all_prefixed_files = []
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if "__pycache__" in root:
                continue
            if file.startswith(prefix) and file.endswith(".py"):
                all_prefixed_files.append(root + os.sep + file)
    return all_prefixed_files