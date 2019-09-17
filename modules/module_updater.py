#!/usr/bin/env python3

import logging
import os
import re
import shutil
import subprocess
import zipfile

import requests

if __name__ != "__main__":
    import core.utility as util

"""
This module updates the resources that are potentially
shared among all modules.
"""

CPE_DICT_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip"
RESOURCES_DIR = "resources"
CPE_DICT_FILE = "official-cpe-dictionary_v2.2.xml"
CPE_DICT_BACKUP_FILE = "official-cpe-dictionary_v2.2.xml.bak"
VERBOSE = False


def run(results: list):
    """Update resources"""

    # setup CPE dict download
    if __name__ == "__main__" or VERBOSE:
        print("[+] Updating CPE dictionary")

    cwd = os.getcwd()
    os.makedirs(RESOURCES_DIR, exist_ok=True)
    os.chdir(RESOURCES_DIR)
    if os.path.isfile(CPE_DICT_FILE):
        shutil.move(CPE_DICT_FILE, CPE_DICT_BACKUP_FILE)
    
    # download CPE dict and unzip
    with open(os.devnull, "w") as file:
        zipfiles = []
        return_code = subprocess.call("wget %s -O %s" % (CPE_DICT_URL, CPE_DICT_FILE + ".zip"),
                                      stdout=file, stderr=subprocess.STDOUT, shell=True)
        if return_code != 0:
            if os.path.isfile(CPE_DICT_BACKUP_FILE):
                print_msg("Download of CPE dict failed, rolling back.")
                shutil.move(CPE_DICT_BACKUP_FILE, CPE_DICT_FILE)
            else:
                print_msg("Download of CPE dict failed, please install manually.")
            if os.path.isfile(CPE_DICT_FILE + ".zip"):
                os.remove(CPE_DICT_FILE + ".zip")
        else:
            try:
                zip_ref = zipfile.ZipFile(CPE_DICT_FILE + ".zip", "r")
                zip_ref.extractall()  # extract archive contents to CWD
                zip_ref.close()
                os.remove(CPE_DICT_FILE + ".zip")
            except:
                if os.path.isfile(CPE_DICT_BACKUP_FILE):
                    print_msg("Unzipping CPE dict failed, rolling back.")
                    shutil.move(CPE_DICT_BACKUP_FILE, CPE_DICT_FILE)
                else:
                    print_msg("Unzipping CPE dict failed, please do so manually.")

    if os.path.isfile(CPE_DICT_BACKUP_FILE):
        os.remove(CPE_DICT_BACKUP_FILE)

    os.chdir(cwd)


def print_msg(msg: str):
    """Communicate warning via logger or stdout"""
    if VERBOSE:
        util.printit(msg)
    elif __name__ == "__main__":
        print(msg)


if __name__ == "__main__":
    run([])
