#!/bin/bash

# the package manager on Linux to use
LINUX_PACKAGE_MANAGER="apt-get"

# some function definitions
install_brew_packages() {
    # Use brew to install macOS software packages
    BREW_PACKAGES="python wget curl nmap sqlite3 cmake coreutils hydra gobuster"  # gcc should be available by default

    which brew &> /dev/null
    if [ $? != 0 ]; then
        printf "${RED}Could not find brew command.\\nPlease install Homebrew first.\\n"
        exit 1
    fi

    if [ $QUIET != 1 ]; then
        echo -e "${GREEN}[+] Updating Homebrew and upgrading installed packages to latest version.${SANE}"
    fi

    # as brew cannot be run with root privileges, we need to run it as the real user
    if [ $QUIET != 1 ]; then
        sudo -u $REAL_USER_NAME brew update
        brew_fail_check
        sudo -u $REAL_USER_NAME brew install ${BREW_PACKAGES}
        sudo -u $REAL_USER_NAME brew upgrade ${BREW_PACKAGES}
        brew_fail_check
        sudo -u $REAL_USER_NAME brew cleanup
    else
        sudo -u $REAL_USER_NAME brew update >/dev/null
        brew_fail_check
        sudo -u $REAL_USER_NAME brew install ${BREW_PACKAGES} >/dev/null
        sudo -u $REAL_USER_NAME brew upgrade ${BREW_PACKAGES} >/dev/null
        brew_fail_check
        sudo -u $REAL_USER_NAME brew cleanup >/dev/null
    fi
    brew_fail_check
}

brew_fail_check() {
    if [ $? != 0 ]; then
        printf "${RED}Installation of basic brew packages was not successful.\\n"
        exit 1
    fi
}

install_linux_packages() {
    # Use ${LINUX_PACKAGE_MANAGER} to install Linux software packages
    PACKAGES="python3 python3-pip nmap libssh-dev hydra wget curl sqlite3 libsqlite3-dev cmake gcc"
    which ${LINUX_PACKAGE_MANAGER} &> /dev/null
    if [ $? != 0 ]; then
        printf "${RED}Could not find ${LINUX_PACKAGE_MANAGER} command.\\nPlease check your package mannager installation first.\\n"
        exit 1
    fi

    if [ $QUIET != 1 ]; then
        sudo ${LINUX_PACKAGE_MANAGER} update
    else
        sudo ${LINUX_PACKAGE_MANAGER} update >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n"
        exit 1
    fi

    if [ ${QUIET} != 1 ]; then
        sudo ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES}
    else
        sudo ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES} >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n"
        exit 1
    fi
}

install_linux_gobuster() {
    if [ $QUIET != 1 ]; then
        sudo ${LINUX_PACKAGE_MANAGER} install -y gobuster
    else
        sudo ${LINUX_PACKAGE_MANAGER} install -y gobuster 1>/dev/null
    fi
   
    if [ $? != 0 ]; then
        # check that gobuster is not already installed
        which gobuster &> /dev/null
        if [ $? == 0 ]; then
            return
        fi

        # otherwise install it
        echo -e "${CYAN}Info: Installing gobuster directly via go${SANE}"

        # install go if it is not already installed
        which go &> /dev/null
        if [ $? != 0 ]; then
            if [ $QUIET != 1 ]; then
                sudo ${LINUX_PACKAGE_MANAGER} install -y golang-go
            else
                sudo ${LINUX_PACKAGE_MANAGER} install -y golang-go 1>/dev/null
            fi
            if [ $? != 0 ]; then
                printf "${RED}Installation of gobuster was not successfull.\\n"
                exit 1
            fi
        fi

        # use go to install gobuster
        sudo go get github.com/OJ/gobuster
        if [ $? != 0 ]; then
            printf "${RED}Installation of gobuster was not successfull.\\n"
            exit 1
        fi
        GOBUSTER_BIN="${HOME}/go/bin/gobuster"
        sudo ln -s $GOBUSTER_BIN /usr/bin/gobuster
    fi
}


#####################
#### Entry Point ####
#####################

# Process command line arguments
QUIET=0
if [ $# -gt 0 ]; then
    if [ $1 == "-q" ]; then
        QUIET=1
    elif [ $1 == "-v" ]; then
        QUIET=0
    fi
fi

# colors (from: https://stackoverflow.com/a/5947802)
GREEN="\033[0;32m"
SANE="\033[0m"
RED="\033[1;31m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"

# cd into AVAIN directory
PREV_CWD=$(pwd)
cd "$(dirname "${BASH_SOURCE[0]}")"
# store real user name if sudo was used
REAL_USER_NAME=$(who am i | cut -d" " -f1)
# store version info
KERNEL_VERSION=$(uname -v)
IS_DEBIAN=$(grep -q "Debian" <<< "${KERNEL_VERSION}"; echo $?)

echo -e "${GREEN}[+] Started installation of AVAIN (this may take some time)${SANE}"
echo -e "${GREEN}[+] Installing basic software packages${SANE}"
KERNEL=$(uname)
if [ "${KERNEL}" == "Darwin" ]; then
    echo -e "${GREEN}[+] Identified OS as: macOS --> using packet manager: brew${SANE}"
    install_brew_packages
elif [ "${KERNEL}" == "Linux" ]; then
    echo -e "${GREEN}[+] Identified OS as: Linux --> using packet manager: ${LINUX_PACKAGE_MANAGER}${SANE}"
    install_linux_packages
    install_linux_gobuster
else
    printf "${RED}Could not identify running OS.\\nPlease install AVAIN manually.\\n"
    exit 1
fi


QPRINT="--quiet"
if [ $QUIET != 1 ]; then
    echo ""
    QPRINT=""
fi

echo -e "${GREEN}[+] Installing basic python packages${SANE}"
which pip3 &> /dev/null

if [ $? != 0 ]; then
    printf "${RED}Could not find pip3.\\nPlease install it first or install python packages manually\\n"
    exit 1
fi

pip3 install ${QPRINT} -r requirements.txt
if [ $? != 0 ]; then
    printf "${RED}Could not install python packages with pip3.\\n"
    exit 1
fi

if [ $QUIET != 1 ]; then
    echo ""
fi

echo -e "${GREEN}[+] Setting up git submodules${SANE}"
git submodule ${QPRINT} init
if [ $? != 0 ]; then
    printf "${RED}Could not initialize git submodules.\\n"
    exit 1
fi
git submodule ${QPRINT} update
if [ $? != 0 ]; then
    printf "${RED}Could not update git submodules.\\n"
    exit 1
fi

if [ $QUIET != 1 ]; then
    echo ""
fi

# Download & setup basic resources
echo -e "${GREEN}[+] Downloading required basic resources"
cd modules
if [ $QUIET != 1 ]; then
    ./module_updater.py
else
    ./module_updater.py >/dev/null
fi
cd ..

if [ $QUIET != 1 ]; then
    echo ""
fi

echo -e "${GREEN}[+] Started building the individual modules${SANE}"
CWD=$(pwd)
find modules -name avain_build.sh -print0 | while IFS= read -r -d "" file; do
    cd "$(dirname ${file})"

    echo -e "${GREEN}[+] Executing build script ${BLUE}${file}${SANE}"

    if [ $QUIET != 1 ]; then
        source avain_build.sh
    else
        source avain_build.sh >/dev/null
    fi

    if [ $? != 0 ]; then
        printf "${RED}Could not successfully build module in %s\\n\\n" "$(dirname "${file}")\\n"
        exit 1
    fi

    cd "${CWD}"
done

# Create executable AVAIN script and link it
echo ""
echo -e "${GREEN}[+] Created symlink as /usr/local/bin/avain"
chmod +x avain.py
AVAIN_DIR=$(pwd -P)
ln -sf "${AVAIN_DIR}/avain.py" /usr/local/bin/avain

# Change AVAIN directory and file ownership to actual user if installation is run as root via sudo
EUID_=$(id -u)
UID_=$(who | awk '{print $1; exit}' | xargs id -u)

if [ "${EUID_}" = 0 ] && [ "${EUID_}" != "${UID_}" ]; then
    echo -e "${GREEN}[+] Setting proper file permissions for files in AVAIN directory"
    GID_=$(id -g ${UID_})
    chown -R "${UID_}:${GID_}" .
fi

# cd into original directory
cd "${PREV_CWD}"

echo -e "${CYAN}[+] That's it. Installation was successful${SANE}"
