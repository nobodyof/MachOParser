# /CMakeLists.txt
cmake_minimum_required(VERSION 3.12.0)
project(MachOParser VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# -DLIEF_DIR=<LIEF install prefix>/share/LIEF/cmake
# COMPONENTS: <SHARED | STATIC> - Default: STATIC
find_package(LIEF REQUIRED COMPONENTS STATIC) 

add_executable(MachOParser main.cpp)

# Enable C++11
set_property(TARGET MachOParser
             PROPERTY CXX_STANDARD           11
             PROPERTY CXX_STANDARD_REQUIRED  ON)

# Link the executable with LIEF
target_link_libraries(MachOParser PRIVATE LIEF::LIEF)