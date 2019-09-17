#!/bin/bash

install_chromedriver_linux() {
    POSSIBLE_PKGS="chromium-driver chromium-chromedriver"
    SUCCESS=0

    QPRINT="-qq"
    if [ $QUIET != 1 ]; then
        QPRINT=""
    fi

    for pkg in $POSSIBLE_PKGS; do
        sudo apt-get install -y ${QPRINT} $pkg
        if [ $? -eq 0 ]; then
            SUCCESS=1
            sudo apt-get --only-upgrade -y ${QPRINT} install $pkg
            break
        fi
    done

    if [ $SUCCESS != 1 ]; then
        printf "${RED}Could not install chromedriver. Please install it manually."
        exit 1
    fi
}


QPRINT="--quiet"
if [ $QUIET != 1 ]; then
    QPRINT=""
fi

# install PIP packages
pip3 install ${QPRINT} -r requirements.txt

# install linkfinder
if [ ! -d LinkFinder ]; then
    git clone ${QPRINT} https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder
    pip3 install ${QPRINT} -r requirements.txt
    cd ..
fi

# install chromedriver for selenium
KERNEL=$(uname)
if [ "${KERNEL}" == "Darwin" ]; then
    # if $REAL_USER_NAME is not set, e.g. by parent script, set it
    if [ -z $REAL_USER_NAME ]; then
        REAL_USER_NAME=$(who am i | cut -d" " -f1)
    fi

    if [ $QUIET != 1 ]; then
        sudo -u $REAL_USER_NAME brew cask install chromedriver
        sudo -u $REAL_USER_NAME brew cask upgrade chromedriver
    else
        sudo -u $REAL_USER_NAME brew cask install chromedriver >/dev/null
        sudo -u $REAL_USER_NAME brew cask upgrade chromedriver >/dev/null
    fi

    # edit the first line to have linkfinder run with Python 3 by default
    sed -i "" -e "1s/python$/python3/" LinkFinder/linkfinder.py
elif [ "${KERNEL}" == "Linux" ]; then
    # chromedriver is installed differently on different Linux distros
    install_chromedriver_linux

    # edit the first line to have linkfinder run with Python 3 by default
    sed -i "1s/python$/python3/" LinkFinder/linkfinder.py
else
    printf "${RED}Could not identify running OS.\\nPlease install AVAIN manually."
    exit 1
fi
