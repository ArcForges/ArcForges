# SPDX-License-Identifier: AGPL-3.0-only
file(GLOB_RECURSE ARCFORGES_SHIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE ARCFORGES_SHIM_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(arcmedia_ffmpeg_abi SHARED ${ARCFORGES_SHIM_SOURCES} ${ARCFORGES_SHIM_HEADERS} ${ARCFORGES_SHARED_ABI_SOURCE})
target_compile_features(arcmedia_ffmpeg_abi PRIVATE cxx_std_20)
set_target_properties(arcmedia_ffmpeg_abi PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME "ArcMediaNative")
if(APPLE)
    set_property(TARGET arcmedia_ffmpeg_abi PROPERTY INSTALL_RPATH "@loader_path")
elseif(UNIX)
    set_property(TARGET arcmedia_ffmpeg_abi PROPERTY INSTALL_RPATH "$ORIGIN")
endif()
target_include_directories(arcmedia_ffmpeg_abi
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")
target_include_directories(arcmedia_ffmpeg_abi SYSTEM PRIVATE
        ${FFMPEG_INCLUDE_DIRS}
        ${MINIAUDIO_INCLUDE_DIR})
target_include_directories(arcmedia_ffmpeg_abi PRIVATE "${ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE}")
target_link_libraries(arcmedia_ffmpeg_abi PRIVATE ${FFMPEG_LIBRARIES} PkgConfig::LIBUSB)
target_compile_definitions(arcmedia_ffmpeg_abi PRIVATE ARCFORGES_RUNTIME_SHARED_GRAPH=1)

if(MSVC)
    target_compile_options(arcmedia_ffmpeg_abi PRIVATE /W4 /WX /permissive- /EHsc /GR- /utf-8 /external:W0)
    target_link_options(arcmedia_ffmpeg_abi PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports/windows.def")
elseif(APPLE)
    target_compile_options(arcmedia_ffmpeg_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcmedia_ffmpeg_abi PRIVATE "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
else()
    target_compile_options(arcmedia_ffmpeg_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcmedia_ffmpeg_abi PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
endif()

arcforges_add_abi_fuzzer(arcmedia_ffmpeg_abi_fuzzer arcmedia_ffmpeg_abi arc_media)

if(WIN32)
    install(TARGETS arcmedia_ffmpeg_abi
        RUNTIME DESTINATION native
        ARCHIVE DESTINATION lib)
    install(DIRECTORY "$<TARGET_FILE_DIR:arcmedia_ffmpeg_abi>/"
        DESTINATION native
        FILES_MATCHING
        PATTERN "*.dll"
        PATTERN "ArcMediaNative.dll" EXCLUDE)
else()
    install(TARGETS arcmedia_ffmpeg_abi
        RUNTIME_DEPENDENCIES
            PRE_EXCLUDE_REGEXES "api-ms-" "ext-ms-"
            POST_EXCLUDE_REGEXES "^/lib/.*" "^/usr/lib/.*" "^/System/Library/.*"
        LIBRARY DESTINATION native
        ARCHIVE DESTINATION lib)
endif()

if(ARCFORGES_BUILD_TESTS)
    add_executable(arcmedia_ffmpeg_abi_tests "tests/arcmedia_ffmpeg_abi_tests.cpp")
    target_compile_features(arcmedia_ffmpeg_abi_tests PRIVATE cxx_std_20)
    target_link_libraries(arcmedia_ffmpeg_abi_tests PRIVATE arcmedia_ffmpeg_abi)
    add_test(NAME arcmedia_ffmpeg_abi.hello COMMAND arcmedia_ffmpeg_abi_tests)
endif()
