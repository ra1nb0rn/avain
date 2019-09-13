#!/bin/bash

install_brew_packages() {
    # Use brew to install macOS software packages
    BREW_PACKAGES="python wget nmap sqlite3 cmake coreutils gobuster"  # gcc should be available by default

    which brew &> /dev/null
    if [ $? != 0 ]; then
        printf "Could not find brew command.\\nPlease install Homebrew first."
        exit 1
    fi

    echo "Updating Homebrew and upgrading installed packages to latest version."
    # as brew cannot be run with root privileges, we need to run it as the real user
    REAL_USER_NAME=$(who am i | cut -d" " -f1)
    eval sudo -u $REAL_USER_NAME brew update && sudo -u $REAL_USER_NAME brew upgrade && sudo -u $REAL_USER_NAME brew cleanup
    if [ $? != 0 ]; then
        printf "Installation of basic brew packages was not successful."
        exit 1
    fi

    eval sudo -u $REAL_USER_NAME brew install "${BREW_PACKAGES}"
    if [ $? != 0 ]; then
        printf "Installation of basic brew packages was not successful."
        exit 1
    fi

    eval sudo -u $REAL_USER_NAME brew install hydra --with-libssh
    if [ $? != 0 ]; then
        printf "Installation of hydra with libssh using brew was not successful."
        exit 1
    fi
    echo "Done."
}

install_apt_packages() {
    # Use apt to install Linux software packages
    APT_PACKAGES="python3 python3-pip nmap libssh-dev hydra wget sqlite3 libsqlite3-dev cmake gcc"
    which apt-get &> /dev/null
    if [ $? != 0 ]; then
        printf "Could not find apt-get command.\\nPlease check your apt installation first."
        exit 1
    fi

    eval sudo apt-get update
    eval sudo apt-get -y install "${APT_PACKAGES}"
    if [ $? != 0 ]; then
        printf "Installation of apt packages was not successful."
        exit 1
    fi
    echo "Done."
}

install_linux_gobuster() {
    KERNEL_VERSION=$(uname -v)
    IS_DEBIAN=$(grep -q "Debian" <<< "${KERNEL_VERSION}"; echo $?)

    if [ ${IS_DEBIAN} -eq 0 ]; then
        sudo apt-get install -y gobuster
    else
        # check that gobuster is not already installed
        which gobuster &> /dev/null
        if [ $? == 0 ]; then
            return
        fi

        # otherwise install it
        sudo apt-get install -y golang-go
        sudo go get github.com/OJ/gobuster
        GOBUSTER_BIN="${HOME}/go/bin/gobuster"
        sudo ln -s $GOBUSTER_BIN /usr/bin/gobuster
    fi
}

# cd into AVAIN directory
PREV_CWD=$(pwd)
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "Installing software packages ..."
KERNEL=$(uname)
if [ "${KERNEL}" == "Darwin" ]; then
    echo "Identified OS as: macOS"
    echo "Using packet manager: brew"
    install_brew_packages
elif [ "${KERNEL}" == "Linux" ]; then
    echo "Identified OS as: Linux"
    echo "Using packet manager: apt"
    install_apt_packages
    install_linux_gobuster
else
    printf "Could not identify running OS.\\nPlease install AVAIN manually."
    exit 1
fi

echo ""
echo "Installing python packages ..."
which pip3 &> /dev/null

if [ $? != 0 ]; then
    printf "Could not find pip3.\\nPlease install it first or install python packages manually"
    exit 1
fi

eval pip3 install -r requirements.txt
if [ $? != 0 ]; then
    printf "Could not install python packages with pip3."
    exit 1
fi
echo "Done."
echo ""

echo "Setting up git submodules ..."
git submodule init
if [ $? != 0 ]; then
    printf "Could not initialize git submodules."
    exit 1
fi
git submodule update
if [ $? != 0 ]; then
    printf "Could not update git submodules."
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

echo ""
echo "Building modules ..."
echo ""
CWD=$(pwd)
find src/modules -name avain_build.sh -print0 | while IFS= read -r -d "" file; do
    cd "$(dirname ${file})"
    ./avain_build.sh
    if [ $? != 0 ]; then
        printf "Could not successfully build module in %s\\n\\n" "$(dirname "${file}")"
        exit 1
    fi

    cd "${CWD}"
done
echo "Done"

# Install AVAIN script and link it
echo "Creating avain executable ..."
if [ "${KERNEL}" == "Darwin" ]; then
    AVAIN_DIR=$(dirname "$(greadlink -f src)")
else
    AVAIN_DIR=$(dirname "$(readlink -f src)")
fi

cat << EOF > avain
#!/bin/sh
AVAIN_DIR="${AVAIN_DIR}"
export AVAIN_DIR
exec "\${AVAIN_DIR}/src/cli.py" "\$@"
EOF

chmod +x avain
AVAIN_DIR=$(pwd -P)
ln -sf "${AVAIN_DIR}/avain" /usr/local/bin/avain

echo "Done"
echo ""

# Change AVAIN directory and file ownership to actual user if installation is run with sudo
EUID_=$(id -u)
UID_=$(who | awk '{print $1; exit}' | xargs id -u)

if [ "${EUID_}" != "${UID_}" ]; then
    GID_=$(id -g ${UID_})
    chown -R "${UID_}:${GID_}" .
fi

# cd into original directory
cd "${PREV_CWD}"

echo "That's it. Installation finished."
