# SPDX-License-Identifier: AGPL-3.0-only
set(ARCFORGES_SPDX_LICENSE "AGPL-3.0-only")
set(ARCFORGES_LICENCE_BOUNDARY "AGPL")
cmake_minimum_required(VERSION 4.3.3)

set(ARCFORGES_NATIVE_PROFILE "" CACHE STRING "Native component set: shim-static")
set(_arcforges_profiles shim-static)
if(NOT ARCFORGES_NATIVE_PROFILE IN_LIST _arcforges_profiles)
    message(FATAL_ERROR "ARCFORGES_NATIVE_PROFILE must name one of: ${_arcforges_profiles}")
endif()

foreach(_required IN ITEMS CMAKE_TOOLCHAIN_FILE VCPKG_TARGET_TRIPLET)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} must be set explicitly by an ArcForges preset")
    endif()
endforeach()

project(DesktopPlatform VERSION 0.1.0 LANGUAGES C CXX)

option(ARCFORGES_BUILD_TESTS "Build native ABI smoke tests" ON)
option(ARCFORGES_BUILD_FUZZERS "Build Clang libFuzzer ABI boundary targets" OFF)
if(ARCFORGES_BUILD_TESTS)
    get_property(_arcforges_targets_before_ctest DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    include(CTest)
    get_property(_arcforges_ctest_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    # Exempt only targets created by CTest, including when owned targets precede it.
    if(_arcforges_targets_before_ctest)
        list(REMOVE_ITEM _arcforges_ctest_targets ${_arcforges_targets_before_ctest})
    endif()
    set_property(DIRECTORY PROPERTY ARCFORGES_EXTERNAL_TARGETS "${_arcforges_ctest_targets}")
    enable_testing()
endif()

include(eng/cmake/LicenceBoundary.cmake)
add_subdirectory(native)
cmake_language(DEFER CALL arcforges_verify_native_licences)
