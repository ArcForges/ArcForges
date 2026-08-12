# SPDX-License-Identifier: AGPL-3.0-only
if(NOT APPLE)
    return()
endif()

file(GLOB_RECURSE ARCFORGES_SHIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.mm")
file(GLOB_RECURSE ARCFORGES_SHIM_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(arcgraphics_metal_abi SHARED ${ARCFORGES_SHIM_SOURCES} ${ARCFORGES_SHIM_HEADERS})
target_compile_features(arcgraphics_metal_abi PRIVATE cxx_std_20)
set_target_properties(arcgraphics_metal_abi PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME "ArcGraphicsMetalNative")
target_include_directories(arcgraphics_metal_abi
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")

if(MSVC)
    target_compile_options(arcgraphics_metal_abi PRIVATE /W4 /permissive- /EHsc /GR-)
    target_link_options(arcgraphics_metal_abi PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports/windows.def")
elseif(APPLE)
    target_compile_options(arcgraphics_metal_abi PRIVATE -Wall -Wextra -Wpedantic -fno-exceptions -fno-rtti)
    target_link_options(arcgraphics_metal_abi PRIVATE "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
else()
    target_compile_options(arcgraphics_metal_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti)
    target_link_options(arcgraphics_metal_abi PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
endif()

if(ARCFORGES_BUILD_TESTS)
    add_executable(arcgraphics_metal_abi_tests "tests/arcgraphics_metal_abi_tests.cpp")
    target_compile_features(arcgraphics_metal_abi_tests PRIVATE cxx_std_20)
    target_link_libraries(arcgraphics_metal_abi_tests PRIVATE arcgraphics_metal_abi)
    add_test(NAME arcgraphics_metal_abi.hello COMMAND arcgraphics_metal_abi_tests)
endif()
