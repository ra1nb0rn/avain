#!/bin/bash

install_brew_packages() {
    # Use brew to install macOS software packages
    BREW_PACKAGES="python wget nmap"

    which brew &> /dev/null
    if [ $? != 0 ]; then
        printf "Could not find brew command.\nPlease install Homebrew first."
        exit 1
    fi

    eval brew install ${BREW_PACKAGES}
    if [ $? != 0 ]; then
        printf "Installation of basic brew packages was not successful."
        exit 1
    fi

    eval brew instal hydra --with-libssh
    if [ $? != 0 ]; then
        printf "Installation of hydra with libssh using brew was not successful."
        exit 1
    fi
    echo "Done."
}

install_apt_packages() {
    # Use apt to install Linux software packages
    APT_PACKAGES="python3 python3-pip nmap libssh-dev hydra wget"
    which apt-get &> /dev/null
    if [ $? != 0 ]; then
        printf "Could not find apt-get command.\nPlease check your apt installation first."
        exit 1
    fi

    eval sudo apt-get -y install ${APT_PACKAGES}
    if [ $? != 0 ]; then
        printf "Installation of apt packages was not successful."
        exit 1
    fi
    echo "Done."
}

echo "Installing software packages ..."
KERNEL=$(uname)
if [ ${KERNEL} == "Darwin" ]; then
    echo "Identified OS as: macOS"
    echo "Using packet manager: brew"
    install_brew_packages
elif [ ${KERNEL} == "Linux" ]; then
    echo "Identified OS as: Linux"
    echo "Using packet manager: apt"
    install_apt_packages
else
    printf "Could not identify running OS.\nPlease install software packages manually."
fi

echo ""
echo "Installing python packages ..."
which pip3 &> /dev/null

if [ $? != 0 ]; then
    printf "Could not find pip3.\nPlease install it first or install python packages manually"
    exit 1
fi

eval pip3 install -r requirements.txt
if [ $? != 0 ]; then
    printf "Could not install python packages with pip3."
    exit 1
fi
echo "Done."

echo ""
echo "Downloading CPE 2.2 dictionary ..."
mkdir -p resources
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip
unzip -o -d resources official-cpe-dictionary_v2.2.xml.zip
rm official-cpe-dictionary_v2.2.xml.zip
echo "Done."

echo "That's it. Installation finished."
