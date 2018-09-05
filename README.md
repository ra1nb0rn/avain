
# AVAIN - Automated Vulnerability Analysis (in) IoT Networks </B>
A toolkit for automatically assessing the security level of an IoT network

## About
AVAIN can automatically *assess* and *quantify* the security level of an (IoT) network. AVAIN's final output is a *score* between 0 and 10, where the higher the score, the more vulnerable / insecure the network. Additionally, AVAIN keeps all of the intermediate result files to empower the user in *investigating* the network's security state *in more detail*. As IT and IoT security is a continuously evolving field, AVAIN was designed to be *modular* and thereby *easily extensible*. AVAIN separates the network's security assessment into two phases: the *scanning*, i.e. reconnaissance phase and the actual vulnerability *analysis* phase. The module structure is based upon this concept, i.e. there are *scanner* and *analysis* modules. As of now, AVAIN only supports the assessment of IPv4 enables (IoT) devices. As IoT devices often have special networking capabilities, AVAIN may need to be extended in the future to support IoT specific protocols like 6LoWPAN (or just IPv6) or ZigBee.

## Features
* **Automated installation** on macOS and Linux (Ubuntu / Kali)
* **Fully automated program execution**
* **Various levels of detail** for output:
    * Highly detailed output: All intermediate files are kept, even the ones from modules.
    * Less detailed output: Aggregated intermediate results and host / network scores.
* **Easily extensible** using Python
* **Logging** for core and modules
* Partitioning the assessment into different phases enables the user to **skip an undesired phase** or **provide custom intermediate results.**
* Provided modules:
    * (Post-processed) **Nmap reconnaissance**
    * **Correlation** of discovered [**CPEs**](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe/ "About CPE") with **[CVE](https://cve.mitre.org "About CVE") / [NVD](https://nvd.nist.gov "About NVD")** entries
    * [**Mirai**](https://www.grahamcluley.com/mirai-botnet-password/ "About Mirai") Credential Check for **SSH** services
    * [**Mirai**](https://www.grahamcluley.com/mirai-botnet-password/ "About Mirai") Credential Check for **Telnet** services


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

### Specific macOS Requirements
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

### Output Structure
AVAIN puts its output into a directory that generally looks like the following:
```
avain_output-20180905_005831/
├── analysis_results
│   ├── cve_correlation
│   │   ├── cve_summary.json
│   │   ├── found_cves.json
│   │   └── result.json
│   ├── host_scores.json
│   ├── login_bruteforce
│   │   ├── mirai_ssh
│   │   └── mirai_telnet
│   └── results.json
├── avain.log
├── results.json
└── scan_results
    ├── add_scan_results
    │   └── results.json
    ├── nmap
    │   ├── networks.list
    │   ├── potential_oses.json
    │   ├── raw_nmap_scan_results.txt
    │   ├── raw_nmap_scan_results.xml
    │   └── result.json
    └── results.json
```

AVAIN's log ``avain.log`` and the final results as ``results.json`` are clearly visible on the first directory level. The remaining files are dissected into scan / analysis results and further subdirectories that reflect the module structure. As discussed above, AVAIN keeps all output, as can be seen with the raw Nmap results or all of the found CVEs by the ``cve_correlation`` module.

If the user specifies more than one network to assess, the results are put into different subdirectories, each containing its own results. This could look like the following:
```
avain_output-20180905_011115/
├── avain.log
├── net_dir_map.json
├── network_1
│   ├── analysis_results
│   └── scan_results
├── network_2
│   ├── analysis_results
│   └── scan_results
└── results.json
```
Here, the different networks are listed as ``network_1`` and ``network_2``. This is because a directory on Unix cannot be named like e.g. the network expression ``192.168.0.0/24``. The directories are order in the way the user provided them. Still, a translation between the output directories and given network expressions is available in the file ``net_dir_map.json``.

## AVAIN File Formats
AVAIN uses JSON as a common exchange format for (intermediate) results. This allows for human-readable, but also computationally processable information. Modules can on the one hand have their own output files, but they also have to deliver a result to the AVAIN core. The result shared with AVAIN's core has to abide by the common exchange formats detailed below. Furthermore, modules always work in the scope of one network, i.e. if the user would like four networks to be assessed, every module is called four times, not just once. Therefore, an intermediate result generally lists hosts with their results and not networks.

### Scan Module Results
An example intermediate result for a scanner module could look like to following (as JSON):
```
{
   "192.168.178.36": {
      "os": {
         "name": "Apple OS X 10.10.X",
         "cpes": [
            "cpe:/o:apple:mac_os_x:10.10"
         ],
         "accuracy": "97"
      },
      "ip": {
         "addr": "192.168.178.36",
         "type": "ipv4"
      },
      "tcp": {
         "80": {
            "portid": "80",
            "protocol": "tcp",
            "cpes": [
               "cpe:/a:apache:http_server:2.4.33"
            ],
            "name": "Apache httpd 2.4.33",
            "service": "http"
         }
      }
   }
}
```
For brevity, only one host is shown above. All hosts are indexed by their (IPv4) network address. Their content is another object that can contain several more fields. AVAIN requires the ``os``, ``tcp`` and ``udp`` fields to abide by a certain format:
* If the ``os`` has an entry called ``cpes``, it has to be a list of CPEs for the detected / assumed OS. ``name`` has to be the corresponding name as string.
* The ``tcp`` and ``udp`` entries are each dissected into objects for every detected port.
* Every port entry has to be indexed by its port number. The same rules apply for the ``os`` and ``cpes`` entry. Furthermore, if the ``service`` field exists, it has to be a string describing the service, e.g, ``"ssh"`` or ``"http"``.
As the interfacing language between the core and modules is Python, intermediate results can also be exchanged using a dictionary with a structure equivalent to the JSON one as described above.

### Analysis Module Results
The results for analysis modules have to be in a specific format as well. In comparison to the scanning results, the format is fairly simple. An example result could be:
```
{
    "192.168.0.24": 6.8,
    "192.168.0.42": 7.9,
    "192.168.0.64": 9.8,
    "192.168.0.78": 8.2,
    "192.168.0.101": 7.4,
}
```
It is as simple as listing every host with the score it was rated with.

### Core Results
The main files created by the core are the aggregated scan / analysis results for every network as well as the final output file that lists for every network expression its respective security score. The aggregated scan results consist of a final aggregation result that is located in ``scan_results/results.json`` and the intermediate result files for the aggregation containing for example a collection of all Operating Systems suggested by the different scanner modules. The file structure for the scan aggregation result is the same as the one for intermediate scanning results as detailed above. The main result file for the analysis is stored in ``analysis_results/results.json`` and just lists the assessed network with its final security score. The file ``analysis_results/host-scores.json`` on the other hand shows a more detailed version, where every (detected) host within network is listed with its final score (similar to the analysis module result format). At last, AVAIN also produces the file ``results.json`` located on the same directory level as the log file. This file contains for every network expression specified by the user the security score the respective network was rated with.

### Supplying User Data
With the ``-sR`` and ``-aR`` argument, the user can provide AVAIN with additional and even manually crafted intermediate result files. These files have to be JSON files with the scan / analysis result structure as described above. For example, supplying AVAIN with custom results can come in handy when AVAIN, or more specifically its utilized scanners, have difficulty determining the OS of a host.

## Adding New Modules
{...}

### Module Parameters
{...}

### Automated Building
{...}

### Keeping Data Up-to-data
{...}

## Configuration Files <a id="config_expl"></a>
{...}

## Examples
{...}

## Authors
* **Rolf Egert** - *AVAIN idea, guidance and suggestions during development*
* **Dustin Born** - *development of first release as part of his Bachelor Thesis*
