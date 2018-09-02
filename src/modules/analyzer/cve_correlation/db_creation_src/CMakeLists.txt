project(cve-database-creation)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define CMake settings
cmake_minimum_required(VERSION 3.11.2)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

# Include SQLiteCpp library and build it
option(SQLITECPP_RUN_CPPLINT OFF)
include_directories(SQLiteCpp/include)
add_subdirectory(SQLiteCpp)

# Include Json C++ file
include_directories(json/single_include)

SET_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

ADD_EXECUTABLE(create_db create_db.cpp)
TARGET_LINK_LIBRARIES(create_db SQLiteCpp sqlite3 pthread)
if (NOT APPLE)
    TARGET_LINK_LIBRARIES(create_db dl)
endif()