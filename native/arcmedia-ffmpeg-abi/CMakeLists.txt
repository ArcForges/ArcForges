# SPDX-License-Identifier: AGPL-3.0-only
file(GLOB_RECURSE ARCFORGES_SHIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE ARCFORGES_SHIM_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(arcmedia_ffmpeg_abi SHARED ${ARCFORGES_SHIM_SOURCES} ${ARCFORGES_SHIM_HEADERS})
target_compile_features(arcmedia_ffmpeg_abi PRIVATE cxx_std_20)
set_target_properties(arcmedia_ffmpeg_abi PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME "ArcMediaNative")
target_include_directories(arcmedia_ffmpeg_abi
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")

if(MSVC)
    target_compile_options(arcmedia_ffmpeg_abi PRIVATE /W4 /permissive- /EHsc /GR-)
    target_link_options(arcmedia_ffmpeg_abi PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports/windows.def")
elseif(APPLE)
    target_compile_options(arcmedia_ffmpeg_abi PRIVATE -Wall -Wextra -Wpedantic -fno-exceptions -fno-rtti)
    target_link_options(arcmedia_ffmpeg_abi PRIVATE "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
else()
    target_compile_options(arcmedia_ffmpeg_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti)
    target_link_options(arcmedia_ffmpeg_abi PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
endif()

if(ARCFORGES_BUILD_TESTS)
    add_executable(arcmedia_ffmpeg_abi_tests "tests/arcmedia_ffmpeg_abi_tests.cpp")
    target_compile_features(arcmedia_ffmpeg_abi_tests PRIVATE cxx_std_20)
    target_link_libraries(arcmedia_ffmpeg_abi_tests PRIVATE arcmedia_ffmpeg_abi)
    add_test(NAME arcmedia_ffmpeg_abi.hello COMMAND arcmedia_ffmpeg_abi_tests)
endif()
