#!/bin/bash

cd "db_creation_src/"
cd "SQLiteCpp"
git submodule init
git submodule update
cd ".."

rm -rf build
mkdir -p build
cd "build"
cmake ..
make
echo ""
cp create_db ../../

cd "../../"
eval "./module_updater.py"

if [ $? != 0 ]; then
    echo "Could not update database"
    exit 1
fi
