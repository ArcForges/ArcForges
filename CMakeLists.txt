# SPDX-License-Identifier: AGPL-3.0-only
cmake_minimum_required(VERSION 4.3.3)

project(ArcForges VERSION 0.1.0 LANGUAGES C CXX)

option(ARCFORGES_BUILD_TESTS "Build native ABI smoke tests" ON)
if(ARCFORGES_BUILD_TESTS)
    include(CTest)
    enable_testing()
endif()

add_subdirectory(native)
