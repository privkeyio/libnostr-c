cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS ../../ ../../../noscrypt ../../../secp256k1-frost)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(libnostr_test)
