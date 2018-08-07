#!/usr/bin/env python3

import os
import re
import requests
import shutil
import subprocess
import zipfile

CVE_DATAFEED_DIR = "cve_data_feeds"
WGET_OUTFILE = "wget_download_output.txt"
CREATE_DB_OUTFILE = "db_creation.txt"

def update_database(created_files: list):
    # Remove old database to refresh CreationDate
    if os.path.isfile("cve_db.db3"):
        os.remove("cve_db.db3")

    cve_data_feeds_dir = CVE_DATAFEED_DIR
    if os.path.exists(CVE_DATAFEED_DIR):
        shutil.rmtree(CVE_DATAFEED_DIR)
    
    os.makedirs(CVE_DATAFEED_DIR)

    if __name__ == "__main__":
        print("Downloading CVE data feeds ...")

    nvd_nist_datafeed_html = requests.get("https://nvd.nist.gov/vuln/data-feeds").text
    jfeed_expr = re.compile("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-\d\d\d\d.json.zip")
    cve_feed_urls = re.findall(jfeed_expr, nvd_nist_datafeed_html)

    with open(WGET_OUTFILE, "w") as f:
        zipfiles = []
        for cve_feed_url in cve_feed_urls:
            outname = os.path.join(CVE_DATAFEED_DIR, cve_feed_url.split("/")[-1])
            subprocess.call("wget %s -O %s" % (cve_feed_url, outname), stdout=f, stderr=subprocess.STDOUT, shell=True)
            zipfiles.append(outname)

    created_files.append(WGET_OUTFILE)

    if os.path.isfile("wget-log"):
        os.remove("wget-log")

    if __name__ == "__main__":
        print("Unzipping data feeds ...")
    
    for file in zipfiles:
        zip_ref = zipfile.ZipFile(file, "r")
        zip_ref.extractall(CVE_DATAFEED_DIR)
        zip_ref.close()
        os.remove(file)
    
    if __name__ == "__main__":
        print("Done.")

    create_db_call = ["./create_db", CVE_DATAFEED_DIR, "cve_db.db3"]
    if __name__ == "__main__":
        subprocess.call(create_db_call)
    else:
        with open(CREATE_DB_OUTFILE, "w") as f:
            subprocess.call(create_db_call, stdout=f, stderr=subprocess.STDOUT)

    created_files.append(CREATE_DB_OUTFILE)
    shutil.rmtree(CVE_DATAFEED_DIR)


if __name__ == "__main__":
    update_database()