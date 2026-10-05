# SPDX-License-Identifier: AGPL-3.0-only
set(ARCFORGES_SPDX_LICENSE "AGPL-3.0-only")
set(ARCFORGES_LICENCE_BOUNDARY "AGPL")
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(ARCFORGES_SHARED_ABI_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/shared/src/arc_native_abi.cpp")
set(ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/shared/src")
find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
set(_identity_header "${CMAKE_CURRENT_BINARY_DIR}/identity/arc_build_identity.hpp")
add_custom_target(arcforges_build_identity
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/eng/build_identity.py" --native-header "${_identity_header}"
    BYPRODUCTS "${_identity_header}"
    VERBATIM)
arcforges_declare_target_licence(arcforges_build_identity)
include_directories("${CMAKE_CURRENT_BINARY_DIR}/identity")

function(arcforges_add_abi_fuzzer name library prefix)
    if(NOT ARCFORGES_BUILD_FUZZERS)
        return()
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR WIN32)
        message(FATAL_ERROR "ARCFORGES_BUILD_FUZZERS requires Clang on Linux or macOS")
    endif()
    add_executable(${name} "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/shared/fuzz/arc_native_abi_fuzzer.cpp")
    arcforges_declare_target_licence(${name})
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

if(ARCFORGES_NATIVE_PROFILE STREQUAL "shim-static")
    find_package(OpenImageIO CONFIG REQUIRED)
    add_subdirectory(arcimage-abi)
    add_subdirectory(arcpdf-abi)

    if(ARCFORGES_BUILD_TESTS)
        find_package(Threads REQUIRED)

        add_executable(arc_native_abi_c17_layout_tests "shared/tests/arc_native_abi_c17_layout.c")
        arcforges_declare_target_licence(arc_native_abi_c17_layout_tests)
        set_target_properties(arc_native_abi_c17_layout_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
        target_compile_features(arc_native_abi_c17_layout_tests PRIVATE c_std_17)
        target_include_directories(arc_native_abi_c17_layout_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/shared/include")
        if(MSVC)
            target_compile_options(arc_native_abi_c17_layout_tests PRIVATE /W4 /WX /permissive-)
        else()
            target_compile_options(arc_native_abi_c17_layout_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
        endif()
        add_test(NAME arc_native_abi_c17_layout_tests COMMAND arc_native_abi_c17_layout_tests)

        add_executable(arc_native_abi_cpp20_tests
            "shared/tests/arc_native_abi_cpp20_tests.cpp"
            "${ARCFORGES_SHARED_ABI_SOURCE}")
        arcforges_declare_target_licence(arc_native_abi_cpp20_tests)
        set_target_properties(arc_native_abi_cpp20_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
        add_dependencies(arc_native_abi_cpp20_tests arcforges_build_identity)
        target_compile_features(arc_native_abi_cpp20_tests PRIVATE cxx_std_20)
        target_include_directories(arc_native_abi_cpp20_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/shared/include"
            "${ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE}")
        target_link_libraries(arc_native_abi_cpp20_tests PRIVATE Threads::Threads)
        if(MSVC)
            target_compile_options(arc_native_abi_cpp20_tests PRIVATE /W4 /WX /permissive- /EHsc /GR-)
        else()
            target_compile_options(arc_native_abi_cpp20_tests PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
        endif()
        add_test(NAME arc_native_abi_cpp20_tests COMMAND arc_native_abi_cpp20_tests)
    endif()
endif()
