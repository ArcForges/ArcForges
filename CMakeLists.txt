# SPDX-License-Identifier: AGPL-3.0-only
cmake_minimum_required(VERSION 4.3.3)

set(ARCFORGES_NATIVE_PROFILE "" CACHE STRING "ArcForges vcpkg graph: runtime-shared, shim-static, or host-tools")
set(ARCFORGES_TARGET_RID "" CACHE STRING "ArcForges product RID")
set(_arcforges_profiles runtime-shared shim-static host-tools)
if(NOT ARCFORGES_NATIVE_PROFILE IN_LIST _arcforges_profiles)
    message(FATAL_ERROR "ARCFORGES_NATIVE_PROFILE must name one of: ${_arcforges_profiles}")
endif()

foreach(_required IN ITEMS CMAKE_TOOLCHAIN_FILE VCPKG_MANIFEST_DIR VCPKG_INSTALLED_DIR
        VCPKG_TARGET_TRIPLET VCPKG_HOST_TRIPLET)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} must be set explicitly by an ArcForges preset")
    endif()
endforeach()

cmake_path(NORMAL_PATH VCPKG_MANIFEST_DIR OUTPUT_VARIABLE _manifest_dir)
cmake_path(NORMAL_PATH CMAKE_SOURCE_DIR OUTPUT_VARIABLE _source_dir)
set(_expected_manifest "${_source_dir}/eng/native/vcpkg/manifests/${ARCFORGES_NATIVE_PROFILE}")
cmake_path(NORMAL_PATH _expected_manifest OUTPUT_VARIABLE _expected_manifest)
if(NOT _manifest_dir STREQUAL _expected_manifest)
    message(FATAL_ERROR "VCPKG_MANIFEST_DIR '${_manifest_dir}' does not match profile '${_expected_manifest}'")
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/vcpkg.json" OR EXISTS "${CMAKE_SOURCE_DIR}/vcpkg-configuration.json")
    message(FATAL_ERROR "The repository root must not create a fourth vcpkg dependency graph")
endif()

project(ArcForges VERSION 0.1.0 LANGUAGES C CXX)

option(ARCFORGES_BUILD_TESTS "Build native ABI smoke tests" ON)
option(ARCFORGES_BUILD_FUZZERS "Build Clang libFuzzer ABI boundary targets" OFF)
if(ARCFORGES_BUILD_TESTS)
    include(CTest)
    enable_testing()
endif()

add_subdirectory(native)
