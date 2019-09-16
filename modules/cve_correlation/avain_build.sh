#!/bin/bash

# configure submodules of SQLiteCpp
cd "db_creation_src/SQLiteCpp"
git submodule init
git submodule update
cd ".."

# get C++ JSON parser from https://github.com/nlohmann/json
mkdir -p "json/single_include/nlohmann"
cd json/single_include/nlohmann
wget https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp
cd "../../../"

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
