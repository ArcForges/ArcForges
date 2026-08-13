# SPDX-License-Identifier: AGPL-3.0-only

vcpkg_check_linkage(ONLY_STATIC_LIBRARY ONLY_DYNAMIC_CRT)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO ihedvall/mdflib
    REF "v2.3.0"
    SHA512 b52fdf8c31637b635861eb583076acafd9ec547962e45854ddf2e202d521e45624ae99b35752d6562ee399a87ce083aaf5ab9e4288fb5ef26cf75308ba4b8efe
    HEAD_REF main
)

vcpkg_replace_string("${SOURCE_PATH}/CMakeLists.txt" "  VERSION 2.3" "  VERSION 2.3.0")
vcpkg_replace_string("${SOURCE_PATH}/CMakeLists.txt" "mdflib/mdflibConfigVersion.cmake" "mdflib/MdfLibConfigVersion.cmake")
vcpkg_replace_string("${SOURCE_PATH}/CMakeLists.txt" "mdflib/mdflibTargets.cmake" "mdflib/MdfLibTargets.cmake")
vcpkg_replace_string("${SOURCE_PATH}/CMakeLists.txt"
    [=[VERSION ${Upstream_VERSION}]=]
    [=[VERSION "${PROJECT_VERSION}"]=])
vcpkg_replace_string("${SOURCE_PATH}/cmake/MdfLibConfig.cmake"
    [=[include("${CMAKE_CURRENT_LIST_DIR}/MdfLibTargets.cmake")]=]
    [=[include(CMakeFindDependencyMacro)
find_dependency(ZLIB)
find_dependency(expat CONFIG)

include("${CMAKE_CURRENT_LIST_DIR}/MdfLibTargets.cmake")]=])
vcpkg_replace_string("${SOURCE_PATH}/include/mdf/itimestamp.h"
    [=[#include <string>]=]
    [=[#include <cstdint>
#include <string>]=])
vcpkg_replace_string("${SOURCE_PATH}/mdflib/CMakeLists.txt"
    [=[  mdf PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>)]=]
    [=[  mdf PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>)]=])
vcpkg_replace_string("${SOURCE_PATH}/mdflib/CMakeLists.txt" "LIBRARY DESTINATION mdf/lib" "LIBRARY DESTINATION lib")
vcpkg_replace_string("${SOURCE_PATH}/mdflib/CMakeLists.txt" "ARCHIVE DESTINATION mdf/lib" "ARCHIVE DESTINATION lib")
vcpkg_replace_string("${SOURCE_PATH}/mdflib/CMakeLists.txt" "RUNTIME DESTINATION mdf/bin" "RUNTIME DESTINATION bin")
vcpkg_replace_string("${SOURCE_PATH}/mdflib/CMakeLists.txt" "PUBLIC_HEADER DESTINATION mdf/include/mdf" "PUBLIC_HEADER DESTINATION include/mdf")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DBUILD_SHARED_LIBS=OFF
        -DMDF_BUILD_SHARED_LIB=OFF
        -DMDF_BUILD_SHARED_LIB_NET=OFF
        -DMDF_BUILD_SHARED_LIB_EXAMPLE=OFF
        -DMDF_BUILD_DOC=OFF
        -DMDF_BUILD_TOOL=OFF
        -DMDF_BUILD_TEST=OFF
        -DMDF_BUILD_PYTHON=OFF
)
vcpkg_cmake_install()
vcpkg_copy_pdbs()
vcpkg_cmake_config_fixup(PACKAGE_NAME mdflib CONFIG_PATH lib/cmake/mdflib)
file(INSTALL "${SOURCE_PATH}/include/mdf/" DESTINATION "${CURRENT_PACKAGES_DIR}/include/mdf"
    FILES_MATCHING PATTERN "*.h")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE" "${SOURCE_PATH}/LICENSE-3RD-PARTY.md")
