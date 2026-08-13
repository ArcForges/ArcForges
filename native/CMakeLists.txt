# SPDX-License-Identifier: AGPL-3.0-only
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(ARCFORGES_SHARED_ABI_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/shared/src/arc_native_abi.cpp")
set(ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/shared/src")

function(arcforges_add_abi_fuzzer name library prefix)
    if(NOT ARCFORGES_BUILD_FUZZERS)
        return()
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR WIN32)
        message(FATAL_ERROR "ARCFORGES_BUILD_FUZZERS requires Clang on Linux or macOS")
    endif()
    add_executable(${name} "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/shared/fuzz/arc_native_abi_fuzzer.cpp")
    target_compile_features(${name} PRIVATE cxx_std_20)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/shared/include")
    target_compile_definitions(${name} PRIVATE
        ARCFORGES_FUZZ_GET_ABI_VERSION=${prefix}_get_abi_version
        ARCFORGES_FUZZ_GET_BUILD_INFO=${prefix}_get_build_info
        ARCFORGES_FUZZ_GET_LAST_ERROR=${prefix}_get_last_error)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic -Werror
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(${name} PRIVATE ${library})
endfunction()

if(ARCFORGES_NATIVE_PROFILE STREQUAL "runtime-shared")
    find_package(FFMPEG REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBUSB REQUIRED IMPORTED_TARGET libusb-1.0)
    find_path(MINIAUDIO_INCLUDE_DIR NAMES miniaudio.h REQUIRED)
    add_subdirectory(arcmedia-ffmpeg-abi)
    if(WIN32)
        install(DIRECTORY "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin/"
            DESTINATION native FILES_MATCHING PATTERN "*.dll")
    elseif(APPLE)
        install(DIRECTORY "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib/"
            DESTINATION native FILES_MATCHING PATTERN "*.dylib")
    else()
        install(DIRECTORY "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib/"
            DESTINATION native FILES_MATCHING PATTERN "*.so" PATTERN "*.so.*")
    endif()
elseif(ARCFORGES_NATIVE_PROFILE STREQUAL "shim-static")
    find_package(MdfLib CONFIG REQUIRED)
    find_package(OpenTimelineIO CONFIG REQUIRED)
    find_package(OpenColorIO CONFIG REQUIRED)
    find_package(OpenImageIO CONFIG REQUIRED)
    add_subdirectory(arcscope-mdf-abi)
    add_subdirectory(arcslate-otio-abi)
    add_subdirectory(arcslate-color-abi)
    add_subdirectory(arcslate-image-abi)
    add_subdirectory(arcgraphics-metal-abi)
elseif(ARCFORGES_NATIVE_PROFILE STREQUAL "host-tools")
    find_program(GLSLANG_VALIDATOR_EXECUTABLE NAMES glslangValidator REQUIRED)
    find_program(SPIRV_CROSS_EXECUTABLE NAMES spirv-cross REQUIRED)
    add_custom_target(arcforges_host_tools ALL
        COMMAND "${GLSLANG_VALIDATOR_EXECUTABLE}" --version
        COMMAND "${SPIRV_CROSS_EXECUTABLE}" --version
        COMMENT "Verifying the locked shader host-tool graph")
endif()
