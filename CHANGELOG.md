# Changelog
This file keeps track of all notable changes between the different versions of AVAIN.

## v0.1.2 - 2019-09-22
### Added
- A very detailed wiki
- All Hydra output is now printed in real time to the screen
### Changed
- Greatly shrink README and refer to respective wiki sites
- Hydra SSH is now by default configured to use only 4 tasks
- The user agent for the web/crawler module is now by default configured to use a Linux UA

## v0.1.1 - 2019-09-19
### Changed
- Installation of gobuster on Linux is now indepedent of detected kernel version
- Make Docker installation quieter and add installation of locales
- Use Ubuntu as base image in the Dockerfile
- The used package manager for the automated installation on Linux can now be easily changed
### Fixed
- Quiet installation of apt packages
- The module_update_interval configuration parameter correctly now specifies minutes and not seconds

## v0.1.0 - 2019-09-18
### Added
- Marks the base version of AVAIN, including:
    - main functionality (Nmap scanner, CVE analysis, web scraping, Telnet &amp; SSH credential bruteforce)
    - module result sharing &amp; aggregation for scan results, web scraping results and vulnerability scores
    - automation of installation and module updates + simple addition of new installers / updaters
    - simple configuration + simple addition of new configuration parameters
