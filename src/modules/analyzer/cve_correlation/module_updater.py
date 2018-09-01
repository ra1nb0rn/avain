#!/usr/bin/env python3

import os
import re
import requests
import shutil
import subprocess
import sys
import zipfile

NVD_DATAFEED_DIR = "nvd_data_feeds"
WGET_OUTFILE = "wget_download_output.txt"
CREATE_DB_OUTFILE = "db_creation.txt"
DB_FILE = "nvd_db.db3"
DB_BACKUP_FILE = "nvd_db_bak.db3"

if __name__ != "__main__":
    from core import utility as util

LOGFILE = None

def update_module(results: list):
    global logger
    if __name__ != "__main__" and LOGFILE:
        logger = util.get_logger(__name__, LOGFILE)
    else:
        logger = None

    if os.path.isfile(DB_FILE):
        shutil.move(DB_FILE, DB_BACKUP_FILE)

    if os.path.exists(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)
    
    os.makedirs(NVD_DATAFEED_DIR)

    if __name__ == "__main__":
        print("Downloading NVD data feeds ...")

    try:
        nvd_response = requests.get("https://nvd.nist.gov/vuln/data-feeds", timeout=20)
    except:
        communicate_warning("An error occured when trying to download webpage: https://nvd.nist.gov/vuln/data-feeds")
        rollback()
        return
    if nvd_response.status_code != requests.codes.ok:
        communicate_warning("An error occured when trying to download webpage: https://nvd.nist.gov/vuln/data-feeds")
        rollback()
        return

    nvd_nist_datafeed_html = nvd_response.text
    jfeed_expr = re.compile("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-\d\d\d\d.json.zip")
    nvd_feed_urls = re.findall(jfeed_expr, nvd_nist_datafeed_html)

    if not nvd_feed_urls:
        communicate_warning("No data feed links available on https://nvd.nist.gov/vuln/data-feeds")
        rollback()
        return

    with open(WGET_OUTFILE, "w") as f:
        zipfiles = []
        for nvd_feed_url in nvd_feed_urls:
            outname = os.path.join(NVD_DATAFEED_DIR, nvd_feed_url.split("/")[-1])
            return_code = subprocess.call("wget %s -O %s" % (nvd_feed_url, outname), stdout=f, stderr=subprocess.STDOUT, shell=True)
            if return_code != 0:
                communicate_warning("Getting NVD data feed %s failed" %  nvd_feed_url)
                rollback()
                return
            zipfiles.append(outname)


    created_files = [WGET_OUTFILE]

    if os.path.isfile("wget-log"):
        os.remove("wget-log")

    if __name__ == "__main__":
        print("Unzipping data feeds ...")

    for file in zipfiles:
        try:
            zip_ref = zipfile.ZipFile(file, "r")
            zip_ref.extractall(NVD_DATAFEED_DIR)
            zip_ref.close()
            os.remove(file)
        except:
            communicate_warning("Unzipping data feed %s failed")
            rollback()
            return

    if __name__ == "__main__":
        print("Done.")

    create_db_call = ["./create_db", NVD_DATAFEED_DIR, DB_FILE]
    if __name__ == "__main__":
        return_code = subprocess.call(create_db_call)
    else:
        with open(CREATE_DB_OUTFILE, "w") as f:
            return_code = subprocess.call(create_db_call, stdout=f, stderr=subprocess.STDOUT)

    if return_code != 0:
        communicate_warning("Building NVD database failed")
        rollback()
        return

    created_files.append(CREATE_DB_OUTFILE)
    shutil.rmtree(NVD_DATAFEED_DIR)
    if os.path.isfile(DB_BACKUP_FILE):
        os.remove(DB_BACKUP_FILE)

    results.append((None, created_files))

def rollback():
    communicate_warning("An error occured, rolling back database update")
    if os.path.isfile(DB_FILE):
        os.remove(DB_FILE)
    if os.path.isfile(DB_BACKUP_FILE):
        shutil.move(DB_BACKUP_FILE, DB_FILE)
    if os.path.isdir(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)

def communicate_warning(msg: str):
    if logger:
        logger.warning(msg)
    elif __name__ == "__main__":
        print("Warning: " + msg)

if __name__ == "__main__":
    update_module([])