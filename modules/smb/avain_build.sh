#!/bin/bash

git clone ${QPRINT} https://github.com/ShawnDEvans/smbmap.git
cd smbmap
pip3 install ${QPRINT} -r requirements.txt
cd ..
