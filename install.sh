#!/bin/bash

install_brew_packages() {
    # Use brew to install macOS software packages
    BREW_PACKAGES="python"

    which brew &> /dev/null
    if [ $? != 0 ]; then
        printf "Could not find brew command.\nPlease install Homebrew first."
        exit 1
    fi
    eval brew install ${BREW_PACKAGES}

    eval brew instal hydra --with-libssh

    echo "Done."
}

install_apt_packages() {
    # Use apt to install Linux software packages
:
}

echo "Installing software packages ..."
KERNEL=$(uname)
if [ ${KERNEL} == "Darwin" ]; then
    echo "Identified OS as: macOS"
    echo "Using packet manager brew."
    install_brew_packages
elif [ ${KERNEL} == "Linux" ]; then
    echo "Identified OS as: Linux"
    echo "Using packet manager apt."
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
echo "Done".

echo ""
echo "Downloading CPE 2.2 dictionary ..."
mkdir -p resources
curl https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip -o official-cpe-dictionary_v2.2.xml.zip
unzip -f -d resources official-cpe-dictionary_v2.2.xml.zip
rm official-cpe-dictionary_v2.2.xml.zip
echo "Done."

echo "That's it. Installation successful."
