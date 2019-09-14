#!/bin/bash

echo "Installing required software for 'web/crawler' module ..."

# install PIP packages
pip3 install -r requirements.txt

# install linkfinder
if [ ! -d LinkFinder ]; then
    git clone https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder
    pip3 install -r requirements.txt
    cd ..
fi

# install chromedriver for selenium
KERNEL=$(uname)
if [ "${KERNEL}" == "Darwin" ]; then
    # if $REAL_USER_NAME is not set, e.g. by parent script, set it
    if [ -z $REAL_USER_NAME ]; then
        REAL_USER_NAME=$(who am i | cut -d" " -f1)
    fi
    sudo -u $REAL_USER_NAME brew cask install chromedriver && sudo -u $REAL_USER_NAME brew cask upgrade chromedriver
    # edit the first line to have linkfinder run with Python 3 by default
    sed -i "" -e "1s/python$/python3/" LinkFinder/linkfinder.py
elif [ "${KERNEL}" == "Linux" ]; then
    # chromedriver is installed differently on Debian and e.g. Ubuntu
    IS_DEBIAN=$(grep -q "Debian" <<< "${KERNEL_VERSION}"; echo $?)
    if [ ${IS_DEBIAN} -eq 0 ]; then
        sudo apt-get install -y chromium-driver && sudo apt-get --only-upgrade -y install chromium-driver
    else
        sudo apt-get install -y chromium-chromedriver && sudo apt-get --only-upgrade -y install chromium-chromedriver
    fi

    # edit the first line to have linkfinder run with Python 3 by default
    sed -i "1s/python$/python3/" LinkFinder/linkfinder.py
else
    printf "Could not identify running OS.\\nPlease install AVAIN manually."
    exit 1
fi

echo "Done"
