# SPDX-License-Identifier: AGPL-3.0-only
cmake_minimum_required(VERSION 4.3.3)

set(ARCFORGES_NATIVE_PROFILE "" CACHE STRING "Native component set: runtime-shared, shim-static, or host-tools")
set(_arcforges_profiles runtime-shared shim-static host-tools)
if(NOT ARCFORGES_NATIVE_PROFILE IN_LIST _arcforges_profiles)
    message(FATAL_ERROR "ARCFORGES_NATIVE_PROFILE must name one of: ${_arcforges_profiles}")
endif()

foreach(_required IN ITEMS CMAKE_TOOLCHAIN_FILE VCPKG_TARGET_TRIPLET)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} must be set explicitly by an ArcForges preset")
    endif()
endforeach()

project(ArcForges VERSION 0.1.0 LANGUAGES C CXX)

option(ARCFORGES_BUILD_TESTS "Build native ABI smoke tests" ON)
option(ARCFORGES_BUILD_FUZZERS "Build Clang libFuzzer ABI boundary targets" OFF)
if(ARCFORGES_BUILD_TESTS)
    include(CTest)
    enable_testing()
endif()

add_subdirectory(native)
