

# AVAIN - Automated Vulnerability Analysis (in) IoT Networks </B>
A modular framework for automatically assessing the security level of an IoT network

## About
AVAIN can automatically *assess* and *quantify* the security level of an (IoT) network. AVAIN's final output is a *score* between 0 and 10, where the higher the score, the more vulnerable / insecure the network. Additionally, AVAIN keeps all of the intermediate result files to empower the user in *investigating* the network's security state *in more detail*. As IT and IoT security is a continuously evolving field, AVAIN was designed to be *modular* and thereby *easily extensible*. AVAIN separates the network's security assessment into two phases: the *scanning*, i.e. reconnaissance phase and the actual vulnerability *analysis* phase. The module structure is based upon this concept, i.e. there are *scanner* and *analyzer* modules. As of now, AVAIN only supports the assessment of IPv4 and IPv6 enabled (IoT) devices. Note that IPv6 zone IDs are not guaranteed to work with AVAIN. Also, the two *Hydra brute force modules* do currently *not* work with *IPv6* addresses.

**Disclaimer:** While AVAIN can only be used in IP based (IoT) networks as of now, it is possible to extend AVAIN to be capable of working in different kinds of networks.

## Features
* **Highly modular** framework for vulnerability analysis in computer networks. Entirely new modules or wrappers for other programs can easily be written using **Pyhon**.
* **Various levels of detail** for output:
    * Highly detailed output: All intermediate files are kept, even the ones from modules
    * Less detailed output: Aggregated intermediate results and host / network scores
* **Automated installation** on macOS and Linux (Ubuntu / Kali)
* **Fully automated** vulnerability assessment without requiring user interaction
* Partitioning the assessment into different phases enables the user to **skip an undesired phase** or **provide custom intermediate results**.
* **Logging** for core and modules
* Current modules:
    * (Post-processed) **Nmap reconnaissance**
    * **Correlation** of discovered [**CPEs**](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe/ "About CPE") with **[CVE](https://cve.mitre.org "About CVE") / [NVD](https://nvd.nist.gov "About NVD")** entries
    * Brute Force Credential Check for **SSH** services
    * Brute Force Credential Check for **Telnet** services


## Installation
As of now, this tool only works on macOS and Linux (Ubuntu / Kali). Before installing, make sure to read the OS specific requirements below. To install AVAIN and all of its required software automatically, run ``./install.sh``. A list of all required / installed packages is also listed further down [below](#detail_install). Software packages are installed with a platform specific package manager and ``pip3``. For more detailed information have a look at the ``install.sh`` script directly. On Linux, the script has to be run with root privileges to allow AVAIN to install new APT packages.

So far this software has been successfully installed and run on:
* macOS High Sierra (10.13.4, 10.13.6) and Mojave (10.14.0)
* Ubuntu 18.04 LTS
* Kali Linux 2018.3

**Disclaimer (macOS):** As of recently, Hydra can not be installed with SSH support via Homebrew anymore, see the README and issues of Hydra's [repository](https://github.com/vanhauser-thc/thc-hydra/). If you are affected by this, you have to setup Hydra with SSH support manually.


## Usage
To execute AVAIN, run ``./avain``. Also, during the installation AVAIN is symlinked to ``/usr/local/bin`` and can therefore be called from anywhere with just ``avain``. Calling AVAIN without any arguments displays the usage information:
```
usage: avain [-h] [-n NETWORKS [NETWORKS {...}]] [-nL NETWORK_LIST]
             [-uM] [-aO]
             [-c CONFIG] [-o OUTPUT] [-p PORTS] [-sN]
             [-sR SCAN_RESULTS [SCAN_RESULTS {...}]]
             [-aR ANALYSIS_RESULTS [ANALYSIS_RESULTS {...}]] [-sO] [-v]
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
│   ├── cve_correlation
│   │   ├── cve_summary.json
│   │   ├── found_cves.json
│   │   └── result.json
│   ├── host_scores.json
│   ├── login_bruteforce
│   │   ├── mirai_ssh
│   │   └── mirai_telnet
│   └── results.json
├── avain.log
├── results.json
└── scan_results
    ├── add_scan_results
    │   └── results.json
    ├── nmap
    │   ├── networks.list
    │   ├── potential_oses.json
    │   ├── raw_nmap_scan_results.txt
    │   ├── raw_nmap_scan_results.xml
    │   └── result.json
    └── results.json
```

AVAIN's log ``avain.log`` and the final results as ``results.json`` are clearly visible on the first directory level. The remaining files are dissected into scan / analysis results and further subdirectories that reflect the module structure. As discussed above, AVAIN keeps all output, as can be seen with the raw Nmap results or all of the found CVEs by the ``cve_correlation`` module.

If the user specifies more than one network to assess, the results are put into different subdirectories, each containing its own results. This could look like the following:
```
avain_output-20180905_011115/
├── avain.log
├── net_dir_map.json
├── network_1
│   ├── analysis_results
│   └── scan_results
├── network_2
│   ├── analysis_results
│   └── scan_results
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
    "192.168.0.101": 7.4
}
```
It is as simple as listing every host with the score it was rated with.

### Core Results
The main files created by the core are the aggregated scan / analysis results for every network as well as the final output file that lists for every network expression its respective security score. The aggregated scan results consist of a final aggregation result that is located in ``scan_results/results.json`` and the intermediate result files for the aggregation containing for example a collection of all Operating Systems suggested by the different scanner modules. The file structure for the scan aggregation result is the same as the one for intermediate scanning results as detailed above. The main result file for the analysis is stored in ``analysis_results/results.json`` and just lists the assessed network with its final security score. The files ``analysis_results/host_scores.json`` and ``analysis_results/module_scores.json`` on the other hand show more detailed versions of the result, where every (detected) host within the network is listed with its final score (similar to the analysis module result format) and the scores returned by the different modules. At last, AVAIN also produces the file ``results.json`` located on the same directory level as the log file. This file contains for every network expression specified by the user the security score the respective network was rated with.

### Supplying User Data
With the ``-sR`` and ``-aR`` argument, the user can provide AVAIN with additional and even manually crafted intermediate result files. These files have to be JSON files with the scan / analysis result structure as described above. For example, supplying AVAIN with custom results can come in handy when AVAIN, or more specifically its utilized scanners, have difficulty determining the OS of a host.

## Adding New Modules
Modules have to follow certain rules in order to successfully work with AVAIN. The data format for a module's results is shown above. Scanner modules have to be put into ``src/modules/scanner`` and analyzer modules into ``src/modules/analyzer``. Furthermore, scanner modules have to be prefixed with ``scanner``, while analyzer modules have to be prefixed with ``analyzer``. Have a look at the current module structure to see some examples. As modules have to be written in Python, their file extension has to be ``.py``. Scanner modules are required to have a ``conduct_scan(results: list)`` function; analyzer modules a ``conduct_analysis(results: list)``. A module's result can either be the filepath to a JSON file or the result itself as a Python dictionary. Returning the result is as easy as appending it to the ``results`` list seen in the ``conduct_scan`` / ``conduct_analysis`` function's signature. All non-essential / intermediate results of a module can be returned as well. Every intermediate result needs to be stored in a separate file. Finally, to return all of these files, the module has to append their filepaths to a / its **global** ``CREATED_FILES`` variable / list. Also, it is important to mention that AVAIN switches into the directory of a module when calling it, so that every module can run within its own environment.

### Module Parameters
There are two ways a module can receive parameters from the core: configuration files ([see further below](#config_expl)) and global variables within the module. E.g. if a module has defined the global variable ``NETWORKS``, the core assigns that variable its corresponding value. Currently available module parameters are:
* Both
    * ``VERBOSE`` &ndash; Specifies whether AVAIN should be verbose
    * ``CONFIG`` &ndash; The part of the config file relevant to this module
    * ``CORE_CONFIG`` &ndash; The part of the config file relevant for all modules
* Scanner
    * ``NETWORKS`` &ndash; A list of network (expressions) to scan, possibly containing wildcards and prefixes
    * ``OMIT_NETWORKS`` &ndash; &nbsp A list of network (expressions) **not** to scan, possibly containing wildcards and prefixes
    * ``PORTS`` &ndash; A list of ports to scan, possibly containing the prefix "T" for TCP or "U" for UDP as well a range of ports to scan
    * ``HOSTS`` &ndash; A list of all (pure) host addresses to scan, **not** containing any wildcards or prefixes
    * ``SCAN_RESULTS`` &ndash; A dict containing an aggregation of the already retrieved scan results
* Analyzer
    * ``HOSTS`` &ndash; A dictionary containing the results of the analysis phase. The keys are the hosts' addresses and the values their scan result (as specified above)

### Logging
Every module has the ability to log events. First a logger needs to be setup. This can be done simply with:
```
import logging
logger = logging.getLogger(__name__)
```
Once set up, the logger can be used like this:
```
logger.info("Starting with Nmap scan")
```

### Automated Building
Since modules, except for their Python interface, are not restricted to any kind of programming language or in what kind of data they use, modules can have a separate shell script that can build them automatically. For example, the CVE correlation module has an automatic build script that downloads the NVD data feeds, compiles the database building program written in C++ and finally builds the database. The requirements for an automatic module build script are fairly simple: it has to be named ``avain_build.sh`` and be executable directly, i.e. by calling it like ``./avain_build.sh``. As above, the core switches into the directory of the build script before it is executed.

### Keeping Modules Up-to-date
As some modules may rely on data that needs to stay up-to-date like "the 1000 most common passwords", AVAIN provides a way for modules to be updated. Similar to the scanner and analyzer modules, there are separate "modules" that can update their respective scanner or analyzer module. Similar to above, these modules have to interface with the core in Python (file extension ``.py``) and their name has to be prefixed with ``module_updater``. Furthermore, they have to provide a function with the signature ``update_module()``. Any files that should be stored by the AVAIN core have to be put into the global list ``CREATED_FILES``, just as above. For an example of the update module concept have a look at the ``module_updater.py`` file in ``src/modules/analyzer/cve_correlation``. To update all of AVAIN's modules that provide this update mechanism, the user has to call AVAIN with the **-uM / --update modules** argument.

## Configuration Files <a id="config_expl"></a>
AVAIN can also accept a separate configuration file as program argument. A configuration file can act as a profile for AVAIN that specifies many different arguments at once. The default configuration file is called ``default_config.txt`` and can be found in AVAIN's ``config`` directory. Note that this file has to be present for AVAIN to work correctly. Its contents look like the following:
```
// here defined are default configuration settings
[core]
scan_modules = ALL  // the list of scanner modules to use (in order), or ALL
default_trust = 3
scan_aggregation_scheme = TRUST_AGGR  // possible values --> {TRUST_MAX, TRUST_AGGR}
DB_expire = 20160  // in minutes, i.e. every other week

// here defined are module specific configuration settings
[modules.scanner.nmap.scanner_nmap]
// add_nmap_params = "--max-rtt-timeout 100ms --max-retries 1"  // additional Nmap params
scan_type = "SU"  // SYN scan and UDP scan require root privileges
fast_scan = False  // whether Nmap should use T5 and F option as speedup
add_scripts = "default, http-headers, smb-os-discovery, banner"  // additional scripts Nmap should use

[modules.analyzer.cve_correlation.analyzer_cve_correlation]
DB_expire = 10080  // in minutes, i.e. every week
skip_os = False  // whether to skip OS CVE analysis --> {True, False}
max_cve_count = -1  // the maximum number of CVEs to retrieve; -1 for unlimited
squash_cpes = True  // whether to squash every discovered CPE in case of invalid CPE
allow_versionless_search = True  // whether to fully search for CVEs when CPE has no version

[modules.analyzer.login_bruteforce.hydra_ssh.analyzer]
wordlists = ../wordlists/mirai_user_pass.txt  // Mirai wordlist relative to module dir

[modules.analyzer.login_bruteforce.hydra_telnet.analyzer]
wordlists = ../wordlists/mirai_user_pass.txt  // Mirai wordlist relative to module dir
timeout = 300  // Hydra timeout in seconds (if Telnet bruteforce does not work)
```
Like in many programming languages, comments can be made with ``//`` and ``/* */``. The strings surrounded by ``[`` and ``]`` specify the module the following configuration settings apply to. Every setting has to be placed on a separate line. Settings are specified using a ``key = value`` structure. The keys and values can be custom for every every module, AVAIN does not restrict the keys in any way. The only thing AVAIN does for every module is parse its section of the config file into a dictionary whose keys and values are the same as the config's. *Every module itself is responsible for parsing its config values.*
In case the user specifies a separate config file to use, AVAIN overwrites its default configuration settings with the ones specified in the user's config file. Therefore, the user's config file is not required to contain all settings available but only the ones the user wants changed. It is advised that the user supplies their own configuration file instead of manually overwriting the default configuration file.

## Examples
{...}
* ``avain -n 192.168.0.* -uM -p TCP:80,UDP:53 -o http_dns_sec``
* ``avain -n 192.168.0.1 192.168.0.100-150 -sN -c config/example_configs/fast_nmap_scan.txt -v``
* ``avain -aO -sR path_to_sr_1 path_to_sr_2 -o network_analysis``


## Detailed installation information <a id="detail_install"></a>
Below you can find more information on required software and installation instructions.

### Common Software Requirements
The following list provides an overview of the software used by AVAIN for both macOS and Linux. The versions listed below have shown to work. Other versions may work as well. To install the Git submodules manually, run ``git submodule init && git submodule update``.

* Homebrew / APT
    * Python 3 (3.7.0) with pip3
    * wget (1.19.5)
    * cmake (3.12.1)
    * nmap (7.7.0)
    * sqlite (3.24.0)
    * hydra (8.6_2) with libssh
* Pip3
    * requests >= 2.18.4
    * cvsslib >= 0.5.5
    * packaging >= 17.1
* Git submodules
    * [SRombauts/SQLiteCpp](https://github.com/SRombauts/SQLiteCpp "SQLiteCpp GitHub Page")
    * [nlohmann/json](https://github.com/nlohmann/json "json GitHub Page")
* [The official CPE v2.2 dictionary](https://nvd.nist.gov/products/cpe), stored as ``resources/official-cpe-dictionary_v2.2.xml`` relative to AVAIN's base directory.

### Specific macOS Requirements
On macOS a running version of Homebrew is required for the automated installation. Look [here](https://brew.sh/index_de) for instructions on how to install Homebrew. Additionally, Homebrew's ``coreutils`` package has to be installed.

### Installation on Linux
On Linux the package manager ``apt`` is used for installing software. Therefore, the installation script has to be run as root.

## License
AVAIN is licensed under the MIT license, see [here](https://github.com/RE4CT10N/avain/blob/master/LICENSE.mit).

## Contribution & Bugs
If you want to contribute, or have any questions, use GitHub or directly contact me via Email <a href="mailto:dustin.born@stud.tu-darmstadt.de">here</a>. If you found a bug, feel free to open an issue.

## About the Creation of AVAIN
I created AVAIN as part of my Bachelor Thesis at TU Darmstadt (located in Germany) under the guidance of my advisor Rolf Egert. 
