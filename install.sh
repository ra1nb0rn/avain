#!/bin/bash
PIP3_COMMAND='pip3'

# install python3 packages
eval ${PIP3_COMMAND} install -r requirements.txt

# download and unzip CPE 2.2 dictionary
mkdir -p resources
curl https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip -o official-cpe-dictionary_v2.2.xml.zip
unzip official-cpe-dictionary_v2.2.xml.zip -d resources
rm official-cpe-dictionary_v2.2.xml.zip
