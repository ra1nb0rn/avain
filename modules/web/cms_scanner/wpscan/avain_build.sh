#!/bin/bash

if [ "${KERNEL}" == "Darwin" ]; then
    if [ $QUIET != 1 ]; then
        sudo -u $REAL_USER_NAME brew install wpscan
        sudo -u $REAL_USER_NAME brew upgrade wpscan
        if [ $? != 0 ]; then
            printf "${RED}Installation of wpscan via brew was not successful.\\n"
            exit 1
        fi
    else
        sudo -u $REAL_USER_NAME brew install wpscan >/dev/null
        sudo -u $REAL_USER_NAME brew upgrade wpscan >/dev/null
        if [ $? != 0 ]; then
            printf "${RED}Installation of wpscan via brew was not successful.\\n"
            exit 1
        fi
    fi
else
    # only install WPScan if it is not already installed to avoid any conflicts in e.g. Kali
    which wpscan &> /dev/null
    if [ $? != 0 ]; then
        # first try to install directly via package manager
        if [ ${QUIET} != 1 ]; then
            sudo ${LINUX_PACKAGE_MANAGER} -y install wpscan
        else
            sudo ${LINUX_PACKAGE_MANAGER} -y install wpscan >/dev/null
        fi
        wpscan -h &> /dev/null

        # if install did not work, install Ruby and then wpscan via gem
        if [ $? != 0 ]; then
            if [ ${QUIET} != 1 ]; then
                sudo ${LINUX_PACKAGE_MANAGER} -y install ruby rubygems
            else
                sudo ${LINUX_PACKAGE_MANAGER} -y install ruby rubygems >/dev/null
            fi
            if [ ${QUIET} != 1 ]; then
                gem install wpscan
            else
                gem install wpscan --quiet --silent
            fi

            # check if install worked this time
            wpscan -h &> /dev/null
            if [ $? != 0 ]; then
                printf "${RED}Could not find or install wpscan.\\nPlease install it manually and then restart the overall installation.\\n"
                exit 1
            fi
        fi
    fi
fi
