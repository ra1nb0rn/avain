
# AVAIN - Automated Vulnerability Analyis (in) IoT Networks </B>
A toolkit for automatically assessing the securtiy level of an IoT network

## About
{...}

## Features
* **Automated installation** on macOS and Linux (Ubuntu / Kali)
* **Fully automated program execution**
* **Various levels of detail** for ouput:
    * Highly detailed output: All intermediate files are kept, even the ones from modules.
    * Less detailed ouput: Aggregated intermediate results and host / network scores.
* **Easily extensible** using Python
* **Logging** for core and modules
* Separation in phases enables the user to **skip an undesired phase** or **provide custom intermediate results.**
* Provided modules:
    * (Post-processed) **Nmap receconaissance**
    * **Correlation** of discovered [**CPEs**](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe/ "About CPE") with **[CVE](https://cve.mitre.org "About CVE") / [NVD](https://nvd.nist.gov "About NVD")** entries
    * [**Mirai**](https://www.grahamcluley.com/mirai-botnet-password/ "About Mirai") Credential Check for **SSH** services
    * [**Mirai**](https://www.grahamcluley.com/mirai-botnet-password/ "About Mirai") Credential Check for **Telne**t services


## Installation
As of now, this tool only works on macOS and Linux (Ubuntu / Kali). Before installing, make sure to read the OS specific requirements below. To install AVAIN and all of its required software automatically, run ``./install.sh``. A list of all required/installed packages is also listed below. Software packages are installed with a platform specific package manager and ``pip3``. For more detailed information have a look at the ``install.sh`` script directly.

So far this software has been successfully installed and run on:
* macOS High Sierra (10.13.4, 10.13.6)
* Ubuntu 18.04 LTS
* Kali Linux 2018.3

### Common Software Requirements
The following list provides an overview of the software used by AVAIN for both macOS and Linux. The versions listed below have shown to work. Other versions may work as well. To install the Git submodules manually, run ``git submodule init && git submodule update``.

* Homebrew / Apt
    * Python 3 (3.7.0) with pip3
    * wget (1.19.5)
    * cmake (3.12.1)
    * nmap (7.7.0)
    * sqlite (3.24.0)
    * hydra (8.6_2) with libssh
* Pip3
    * vulners >= 1.1.1
    * requests >= 2.18.4
    * beautifulsoup4 >= 4.6.0
    * cvsslib >= 0.5.5
    * packaging >= 17.1
* Git submodules
    * [SRombauts/SQLiteCpp](https://github.com/SRombauts/SQLiteCpp "SQLiteCpp GitHub Page")
    * [nlohmann/json](https://github.com/nlohmann/json "json GitHub Page")
* [The official CPE v2.2 dictionary](https://nvd.nist.gov/products/cpe), stored as ``resources/official-cpe-dictionary_v2.2.xml`` in AVAIN's base directory.

### Specfic macOS Requirements
On macOS a running version of Homebrew is required for the automated installation. Look [here](https://brew.sh/index_de) for instructions on how to install Homebrew. Additionally, Homebrew's ``coreutils`` package has to be installed.

### Installation on Linux
On Linux the package manager ``apt`` is used for installing software. Therefore, the installation script has to be run as root.

## Usage
To execute AVAIN, run ``./avain``. Also, during the installation AVAIN is symlinked to ``/usr/local/bin`` and can therefore be called from anywhere with just ``avain``. Calling AVAIN without any arguments displays the usage information:
```
usage: avain [-h] [-n NETWORKS [NETWORKS {...}]] [-nL NETWORK_LIST] [-uM] [-aO]
             [-c CONFIG] [-o OUTPUT] [-p PORTS] [-sN]
             [-sR SCAN_RESULTS [SCAN_RESULTS {...}]]
             [-aR ANALYSIS_RESULTS [ANALYSIS_RESULTS {...}]] [-sO] [-oO] [-v]
avain: error: at least one of the following arguments is required: -n/--network,-nL/--network-list, -uD/--update-modules or -aO/--analysis-only
```
The different program arguments are described as follows:
* **-h / --help:** Prints AVAIN's help message and exits.
* **-n / --networks:** Specify one or more networks to scan. A network can be a single IP, an IP range expression, a wildcard expression or a CIDR expression. This is identical to Nmap's concept of a network expression (see [here](https://nmap.org/book/nping-man-target-specification.html) "Specification and Examples"). To specify multiple networks, separate them with a space.
* **-nL / --network-list:** Specify a file containing networks to include into or exclude from the scan. The file has to be a text file containing one network expression per line. If a network expression is prefixed with a ``+`` or has no prefix at all, the network is included into the scan. If a network expression is prefixed with a ``-``, the network is excluded from the scan.
* **-uM / --update-modules:** A flag that signals AVAIN to update all of its modules.
* **-aO / --analysis-only:** Instruct AVAIN to skip the scanning phase and only do an analysis. This flag requires the user to specify scan results for AVAIN to work with [(see below)](#expl_scan_results).
* **-c / --config:** Specify a [configuration file](#config_expl) for AVAIN to use. The specified configuration overwrites AVAIN's default configuration.
* **-o / --output:** Specify the name of the output directory. If the directory does not exist, AVAIN creates it.
* **-p / --ports:** Set the ports that should be scanned on every host. As of now, it is not possible to set a custom setting per host. The port expressions are very similar to Nmap's port expressions (see [here](https://nmap.org/book/man-port-specification.html "Nmap Port Specification")). Multiple port expressions are separated by a comma.
* **-sN / --single-network:** Instruct AVAIN to operate in single network mode meaning that all specified networks are considered to be a subnet of one common supernet. As a result, in the end there will only be one score that represents the security level of the specified networks all together. This argument is especially helpful, if the user would like to specify single hosts placed in the same network.
* **-sR / --scan-results:** <a id="expl_scan_results"></a> Have AVAIN include additional scan results from one or more JSON files.
* **-aR / --analysis-results:** Have AVAIN include additional analysis results from one or more JSON files.
* **-sO / --scan-only:** Instruct AVAIN to only do a network scan and thereby omit the analysis phase.
* **-v / --verbose:** A flag to make AVAIN's output more verbose.

Out of the above arguments, required is at least one of **-n/--network**, **-nL/--network-list**, **-uD/--update-modules** or **-aO/--analysis-only**.

Once called, AVAIN runs automatically without the need for further user interaction. If the user specified a certain output directory, the results are put into that directory. Otherwise they are put into a directory named similarly to ``avain_output-20180824_235333``, where the numbers are a (unique) timestamp of the current day and time.

### Output
{...}

## AVAIN File Formats
AVAIN uses JSON as a common exchange format for (intermediate) results. This allows for human-readable, but also computationally processable information.

### Scan Module Results
{...}

### Analysis Module Results
{...}

### Core Results
{...}

## Configuration Files <a id="config_expl"></a>
{...}


## Adding New Modules
{...}

## Examples
{...}

## Authors
* **Rolf Egert** - *AVAIN idea, guidance and suggestions during development*
* **Dustin Born** - *development of first release as part of his Bachelor Thesis*
