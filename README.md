# AVAIN - Automated Vulnerability Analysis (in) IP-based Networks
A framework for the automated vulnerability analysis in IP-based networks that enables its modules to work collaboratively by sharing results.

## About
AVAIN can automatically *assess* and *quantify* the security level of an IP-based network. Its final output is a *score* between 0 and 10, where the higher the score, the more vulnerable / insecure the network. Additionally, AVAIN keeps all of the intermediate result files to empower the user in *investigating* the network's security state *in more detail*. As IT and IoT security is a continuously evolving field, AVAIN was designed to be *modular* and thereby *easily extensible*. Therefore AVAIN is comprised of a core and several modules. During a vulnerability analysis, AVAIN's core invokes all (specified) modules which return a result at the end of their execution. Currently, there are two results types: *scan* results, i.e. reconnaissance information, and *vulnerability score* results representing the outcome of a vulnerability analysis. By sharing their results, modules can work *collaboratively* to help AVAIN achieve a *more sophisticated* vulnerability assessment. As of now, AVAIN only supports the assessment of IPv4 and IPv6 enabled devices. Note that IPv6 zone IDs are not guaranteed to work with AVAIN. Also, the two *Hydra brute force modules* do currently *not* work with IPv6 addresses.

While AVAIN can only be used in IP-based networks as of now, it is possible to extend AVAIN to make it capable of working in different kinds of networks such as specialized IoT networks.

## Features
* **Highly modular** framework for vulnerability analysis in computer networks. Entirely new modules or wrappers for other programs can easily be written using **Pyhon**.
* Modules can work **collaboratively** by sharing their results. This **simplifies the implementation** of modules and enables AVAIN to achieve a **more sophisticated** vulnerability assessment.
* **Various levels of detail** for output:
    * Highly detailed output: All intermediate files are kept, even the ones from modules
    * Less detailed output: Aggregated intermediate results and host / network vulnerability scores
* Highly **configurable**
* **Automated installation** on macOS and Linux (Ubuntu / Kali)
* **Fully automated** vulnerability assessment without requiring user interaction
* Users can provide **custom intermediate results**
* Current modules:
    * (Post-processed) **Nmap reconnaissance**
    * **Correlation** of discovered [**CPEs**](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe/ "About CPE") with **[CVE](https://cve.mitre.org "About CVE") / [NVD](https://nvd.nist.gov "About NVD")** entries
    * Brute Force Credential Check for **SSH** services
    * Brute Force Credential Check for **Telnet** services


## Installation
As of now, this tool only works on macOS and Linux (Ubuntu / Kali). Before installing, make sure to read the OS specific requirements below. To install AVAIN and all of its required software automatically, run ``./install.sh``. The software packages are installed with a platform specific package manager and ``pip3``. For more detailed information have a look at the ``install.sh`` script directly or the list of all required / installed software packages further down [below](#used_software). After installation, AVAIN may only be fully useable by the original user that installed it (and root).

### Specific macOS Requirements
On macOS a running version of Homebrew is required for the automated installation. Look [here](https://brew.sh/index_de) for instructions on how to install Homebrew. Additionally, Homebrew's ``coreutils`` package has to be installed.
**Disclaimer:** As of recently, Hydra can not be installed with SSH support via Homebrew anymore, see the README and issues of Hydra's [repository](https://github.com/vanhauser-thc/thc-hydra/). If you are affected by this, you have to setup Hydra with SSH support manually.

### Installation on Linux
On Linux the package manager ``apt`` is used for installing software. Therefore, the installation script has to be run as root.


## Usage
To use AVAIN, run ``./avain``. Also, during the installation a symlink is created for AVAIN in ``/usr/local/bin`` which makes it possible to call AVAIN from anywhere with just ``avain``. Calling AVAIN without any arguments displays the usage information:
```
usage: avain [-h] [-n NETWORKS [NETWORKS ...]] [-nL NETWORK_LIST] [-uM]
             [-c CONFIG] [-o OUTPUT] [-p PORTS] [-sN] [-v]
             [-sR SCAN_RESULTS [SCAN_RESULTS ...]]
             [-vS VULNERABILITY_SCORES [VULNERABILITY_SCORES ...]]
avain: error: at least one of the following arguments is required: -n/--network,-nL/--network-list, -uD/--update-modules or any one of [-sR/--scan-results, -vS/--vulnerability-scores]
```
The different program arguments are described as follows:
* **-h / --help:** Prints AVAIN's help message and exits.
* **-n / --networks:** Specify one or more networks to scan. A network can be a single IP, an IP range expression, a wildcard expression or a CIDR expression. This is identical to Nmap's concept of a network expression (see [here](https://nmap.org/book/nping-man-target-specification.html) "Specification and Examples"). To specify multiple networks, separate them with a space.
* **-nL / --network-list:** Specify a file containing networks to include into or exclude from the scan. The file has to be a text file containing one network expression per line. If a network expression is prefixed with a ``+`` or has no prefix at all, the network is included into the scan. If a network expression is prefixed with a ``-``, the network is excluded from the scan.
* **-uM / --update-modules:** A flag that signals AVAIN to update all of its modules.
* **-c / --config:** Specify a [configuration file](#config_expl) for AVAIN to use. The specified configuration overwrites AVAIN's default configuration.
* **-o / --output:** Specify the name of the output directory. If the directory does not exist, AVAIN creates it.
* **-p / --ports:** Set the ports that should be scanned on every host. As of now, it is not possible to set a custom setting per host. The port expressions are very similar to Nmap's port expressions (see [here](https://nmap.org/book/man-port-specification.html "Nmap Port Specification")). Multiple port expressions are separated by a comma.
* **-sN / --single-network:** Instruct AVAIN to operate in single network mode meaning that all specified networks are considered to be a subnet of one common supernet. As a result, in the end there will only be one score that represents the security level of the specified networks all together. This argument is especially helpful, if the user would like to specify single hosts placed in the same network.
* **-sR / --scan-results:** <a id="expl_scan_results"></a> Have AVAIN include additional scan results from one or more JSON files.
* **-vS / --vulnerability-scores:** Have AVAIN include additional vulnerability score results from one or more JSON files.
* **-v / --verbose:** A flag to make AVAIN's output more verbose.

Out of the above arguments, required is at least one of **-n/--network**, **-nL/--network-list**, **-uD/--update-modules** or any one of  **[-sR/--scan-results, -vS/--vulnerability-scores]**.

Once called, AVAIN runs automatically without the need for further user interaction. If the user specified a certain output directory, the results are put into that directory. Otherwise they are put into a directory named similarly to ``avain_output-20180824_235333``, where the numbers are a (unique) timestamp of the current day and time.

### Output Structure
AVAIN puts its output into a directory that generally looks like the following:
```
avain_output-20180905_005831
├── modules
│   ├── cve_correlation
│   │   ├── cve_summary.json
│   │   ├── found_cves.json
│   │   └── result.json
│   ├── login_bruteforce
│   │   ├── hydra_ssh
│   │   └── hydra_telnet
│   └── nmap
├── user_results
├── scan_result_aggregation
├── vuln_score_aggregation
├── avain.log
└── network_vulnerability_ratings.json
```

AVAIN's log ``avain.log`` and the final results as ``network_vulnerability_ratings.json`` are clearly visible on the first directory level. The remaining files are put into a ``modules`` subdirectory, a ``user_results`` subdirectory and several result aggregation subdirectories, one for every type of result. As stated above, AVAIN keeps all (intermediate) results, as can be seen with all of the found CVEs stored within the ``cve_correlation`` module's subdirectory.

If the user specifies more than one network to assess, the results are put into different subdirectories, each containing its own results. This could look like the following:
```
avain_output-20180905_011115/
├── avain.log
├── net_dir_map.json
├── network_1
│   ├── ...
│   └── modules
├── network_2
│   ├── ...
│   └── modules
└── network_vulnerability_ratings.json
```
Here, the different networks are listed as ``network_1`` and ``network_2``. This is because directories on Unix have naming restrictions that e.g. prevent the creation of a single directory called ``192.168.0.0/24``. The directories are numberered according to the order of their network expressions in the AVAIN call. Still, a translation between the output directories and given network expressions is available in the file ``net_dir_map.json``.

## AVAIN File Formats
For the the current two result types, AVAIN uses JSON (or Python dicts) as a common exchange format. This allows for human-readable, but also computationally processable data. Modules can have their own results (stored in separate files) as well as results intended to be shared with other modules and the AVAIN core. The results shared with AVAIN have to abide by the common exchange formats detailed below. Furthermore, modules always work in the scope of one network, i.e. if the user would like four networks to be assessed, every module is called four times, not just once (unless configured otherwise). Therefore, an intermediate result generally lists hosts with their results instead of entire networks.

### Scan Results
An example scan result could look like to following (as JSON):
```json
{
   "192.168.178.36": {
      "os": [
         {
            "name": "Apple OS X 10.10.X",
            "cpes": [
               "cpe:/o:apple:mac_os_x:10.10"
            ],
            "accuracy": "97"
         }
      ],
      "ip": {
         "addr": "192.168.178.36",
         "type": "ipv4"
      },
      "tcp": {
         "80": [
            {
               "portid": "80",
               "protocol": "tcp",
               "cpes": [
                  "cpe:/a:apache:http_server:2.4.33"
               ],
               "name": "Apache httpd 2.4.33",
               "service": "http"
            }
         ]
      }
   },
   "trust": 4
}
```
For brevity, only one host is shown above. All hosts are indexed by their (IPv4) network address. Their content is another object that can contain several more fields. AVAIN requires the ``os``, ``tcp`` and ``udp`` fields to abide by a certain format:
* The ``os`` node is a list that contains one or more OS information nodes. If an OS information node has an entry called ``cpes``, it has to be a list of CPEs for the detected / assumed OS. ``name`` has to be the OSs name as string.
* The ``tcp`` and ``udp`` entries are each dissected into objects for every detected port, hence their indexing.
* Every port node contains one or more port information nodes stored within a list, similar to the "os" node. For port information nodes the same rules apply for the ``name`` and ``cpes`` entry as for OS information nodes. Furthermore, if the ``service`` field exists, it has to be a string describing the service, e.g, ``"ssh"`` or ``"http"``.

Additionally, a scan result can contain one or more ``"trust"`` fields that can reside on any one of the different hierarchy levels. This fields symbolizes how much a module trusts its results, i.e. how accurate and valuable it perceives its results to be. It is basically a quality of data indicator. The value of the ``"trust"`` field can be any integer or floating point number. Apart from the aforementioned restrictions, scan results can contain other custom information.

As the interfacing language between the core and modules is Python, intermediate results can also be exchanged using a dictionary with a structure equivalent to the JSON one as described above.

### Vulnerability Score Results
Vulnerability score results have to be in a specific format as well. In comparison to the scan results, the format is fairly simple. An example result could be:
```json
{
    "192.168.0.24": 6.8,
    "192.168.0.42": 7.9,
    "192.168.0.64": 9.8,
    "192.168.0.78": 8.2,
    "192.168.0.101": 7.4
}
```
It is as simple as listing every host with the vulnerability / security score it was rated with.

### Core Results
The main files created by the core are the aggregated scan / vulnerability score results for every network as well as the final output file that lists for every network expression its respective vulnerability score. The aggregated scan results consist of a final aggregation result that is located in ``scan_result_aggregation/results.json`` and the intermediate result files for the aggregation containing for example a collection of all Operating Systems suggested by the different modules. The file structure for the scan aggregation result is the same as the one for intermediate scan results as detailed above. The main result file for the vulnerability score aggregation is stored in ``vuln_score_aggregation/results.json`` and just lists the assessed network with its final vulnerability score. The files ``vuln_score_aggregation/host_scores.json`` and ``vuln_score_aggregation/module_scores.json`` on the other hand show more detailed versions of the result, where every (detected) host within the network is listed with its final score (similar to the vulnerability score result format) and the scores returned by the different modules. At last, AVAIN also produces the file ``network_vulnerability_ratings.json`` located on the same directory level as the log file. This file contains for every network expression specified by the user the security score the respective network was rated with.

### Supplying User Data
With the ``-sR`` and ``-vS`` argument, the user can provide AVAIN with additional and even manually crafted intermediate result files. These files have to be JSON files with the scan / vulneability score result format as described above. For example, supplying AVAIN with custom results can come in handy when AVAIN, or more specifically its utilized scanners, have difficulties determining the OS of a host. For scan results, the user can include a ``"trust"`` field that symbolizes the quality of their results. Setting this field to a high value will overwrite any module's result.

## Adding New Modules
Modules have to follow certain rules in order to successfully work with AVAIN. The data format for a module's results is shown above. New modules have to be placed into the ``src/modules`` subdirectory. All modules have to be prefixed with the word ``avain`` to be distinguishable from other files / scripts. Have a look at the current module structure to see some examples. As modules have to be written in Python, their file extension has to be ``.py``. Also, modules are required to have a ``run(results: list)`` function. To share its results with AVAIN's core, a module has to append them to the list ``results`` list. For this, every result has to be appended to the list as a tuple of ``(TYPE, RESULT)``, where ``TYPE`` is a key or string contained in the enum defined in ``core/result_types.py`` and  ``RESULT`` can either be the filepath to a JSON file or the result itself as a Python dictionary. All non-essential / intermediate results of a module can be returned separately. Every such result needs to be stored in a separate file. To return all of these files, the module has to store the filepaths in a **global** ``CREATED_FILES`` list. Also, it is important to mention that AVAIN switches into the directory of a module when calling it, so that every module can run within its own environment.

### Module Parameters
There are two ways a module can receive parameters from the core: configuration files ([see further below](#config_expl)) and global variables within the module. E.g. if a module has defined the global variable ``NETWORKS``, the core assigns that variable its corresponding value. Currently available module parameters are:
    * ``VERBOSE`` &ndash; Specifies whether AVAIN should be verbose
    * ``CONFIG`` &ndash; The part of the config file relevant to this module
    * ``CORE_CONFIG`` &ndash; The part of the config file relevant for all modules
    * ``NETWORKS`` &ndash; A list of network (expressions) to scan, possibly containing wildcards and prefixes
    * ``OMIT_NETWORKS`` &ndash; &nbsp A list of network (expressions) **not** to scan, possibly containing wildcards and prefixes
    * ``PORTS`` &ndash; A list of ports to scan, possibly containing the prefix "T" for TCP or "U" for UDP as well a range of ports to scan
    * ``HOSTS`` &ndash; A list of all (pure) host addresses to scan, **not** containing any wildcards or prefixes

Furthermore, to retrieve any of the intermediate / shared results, modules have to define which kind of results they want to retrieve as well as a variable to store them in. This can be done by defining the global dict ``INTERMEDIATE_RESULTS`` and putting into it the requested types of intermediate results as keys. The available results types are defined in ``core/result_types.py`` as enum. Example:
```python
INTERMEDIATE_RESULTS = {ResultType.SCAN: None}  # get the current SCAN result
```
Alternatively to the enum keys, their values can be put into the dict of intermediate results. Example:
```python
INTERMEDIATE_RESULTS = {"SCAN": None}  # get the current SCAN result
```


## Configuration Files <a id="config_expl"></a>
AVAIN can also accept a separate configuration file as program argument. A configuration file can act as a profile for AVAIN that specifies many different arguments at once. The default configuration file is called ``default_config.txt`` and can be found in AVAIN's ``config`` directory. Note that this file has to be present for AVAIN to work correctly. An excerpt of its content looks like the following:
```
// here defined are default configuration settings
[core]
// the list of modules to use (in order)
modules = nmap.avain_nmap, cve_correlation.avain_cve_correlation, login_bruteforce.hydra_ssh.avain, login_bruteforce.hydra_telnet.avain
default_trust = 3
scan_trust_aggr_scheme = TRUST_AGGR  // possible values --> {TRUST_MAX, TRUST_AGGR}
scan_result_aggr_scheme = FILTER  // possible value --> {SINGLE, MULTIPLE, FILTER}
DB_expire = 20160  // in minutes, i.e. every other week
print_result_types = SCAN

// here defined are module specific configuration settings
[nmap.avain_nmap]
// add_nmap_params = "--max-rtt-timeout 100ms --max-retries 1"  // additional Nmap params
scan_type = "SU"  // SYN scan and UDP scan require root privileges
fast_scan = False  // whether Nmap should use T5 and F option as speedup
add_scripts = "default, http-headers, smb-os-discovery, banner"  // additional scripts Nmap should use
```
Like in many programming languages, comments can be made with ``//`` and ``/* */``. The strings surrounded by ``[`` and ``]`` specify the module the following configuration settings apply to. Every setting has to be placed on a separate line. Settings are specified using a ``key = value`` structure. The keys and values can be custom for every module; mostly AVAIN does not have any restrictions on keys or values. The only thing AVAIN does for every module regarding the config file is parse its section into a dictionary whose keys and values are the same as the config's. *Every module itself is responsible for parsing its config values.*
In case the user specifies a separate config file to use, AVAIN overwrites its default configuration settings with the ones specified in the user's config file. Therefore, the user's config file is not required to contain all settings available but only the ones the user wants changed. It is advised that the user supplies their own configuration file instead of manually overwriting the default configuration file.
As an example, at the beginning of the excerpt the modules AVAIN should run (in order) can be configured via the ``modules`` key and a comma-separated list of module names as value.

### Logging
Every module has the ability to log events. First a logger needs to be setup. This can be done simply with:
```python
import logging
logger = logging.getLogger(__name__)
```
Once set up, the logger can be used like this:
```python
logger.info("Starting the Nmap scan")
```

### Automated Building
Since modules, except for their Python interface, are not restricted to any kind of programming language or in what kind of data they use, modules can have a separate shell script that can build them automatically. For example, the CVE correlation module has an automatic build script that downloads the NVD data feeds, compiles the database building program written in C++ and finally builds the database. The requirements for an automatic module build script are fairly simple: it has to be named ``avain_build.sh`` and be executable directly, i.e. by calling it like ``./avain_build.sh``. As above, the core switches into the directory of the build script before it is executed.

### Keeping Modules Up-to-date
As some modules may rely on data that needs to stay up-to-date like "the 1000 most common passwords", AVAIN provides a way for modules to be updated. In accordance with AVAIN's modular concept, there are separate "modules" that can update their respective other module. Similar to above, these modules have to interface with the core in Python (file extension ``.py``) and their name has to be prefixed with ``module_updater``. Furthermore, they have to provide a function with the signature ``run()``. Any files that should be stored by the AVAIN core have to be put into the global list ``CREATED_FILES``, just as above. For an example of the update module concept have a look at the ``module_updater.py`` file in ``src/modules/cve_correlation``. To update all of AVAIN's modules that provide this update mechanism, the user has to call AVAIN with the **-uM / --update modules** argument.


## Examples
Three examples of how you can call AVAIN:
* ``avain -n 192.168.0.* -uM -p T:80,U:53 -o http_dns_sec``
* ``avain -n 192.168.0.1 192.168.0.100-150 -sN -c config/someconfig.cfg -v``
* ``avain -sR path_to_sr_1 path_to_sr_2 -o network_analysis``


## Detailed Installation Information <a id="used_software"></a>
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

## License
AVAIN is licensed under the MIT license, see [here](https://github.com/DustinBorn/avain/blob/master/LICENSE.mit).

## Contribution & Bugs
If you want to contribute, or have any questions or suggestions, use GitHub or directly contact me via Email <a href="mailto:dustin.born@stud.tu-darmstadt.de">here</a>. If you found a bug, feel free to open an issue.

## About the Creation of AVAIN
I created AVAIN as part of my Bachelor Thesis at TU Darmstadt (located in Germany) under the guidance of my advisor Rolf Egert.
