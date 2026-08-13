# SPDX-License-Identifier: AGPL-3.0-only
file(GLOB_RECURSE ARCFORGES_SHIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE ARCFORGES_SHIM_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(arcscope_mdf_abi SHARED ${ARCFORGES_SHIM_SOURCES} ${ARCFORGES_SHIM_HEADERS} ${ARCFORGES_SHARED_ABI_SOURCE})
target_compile_features(arcscope_mdf_abi PRIVATE cxx_std_20)
set_target_properties(arcscope_mdf_abi PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME "ArcScopeMdfNative")
target_include_directories(arcscope_mdf_abi
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")
target_include_directories(arcscope_mdf_abi PRIVATE "${ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE}")
target_link_libraries(arcscope_mdf_abi PRIVATE Upstream::mdf)
target_compile_definitions(arcscope_mdf_abi PRIVATE ARCFORGES_SHIM_STATIC_GRAPH=1)

if(MSVC)
    target_compile_options(arcscope_mdf_abi PRIVATE /W4 /WX /permissive- /EHsc /GR-)
    target_link_options(arcscope_mdf_abi PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports/windows.def")
elseif(APPLE)
    target_compile_options(arcscope_mdf_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcscope_mdf_abi PRIVATE "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
else()
    target_compile_options(arcscope_mdf_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcscope_mdf_abi PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
endif()

arcforges_add_abi_fuzzer(arcscope_mdf_abi_fuzzer arcscope_mdf_abi arc_mdf)

install(TARGETS arcscope_mdf_abi
    RUNTIME DESTINATION native
    LIBRARY DESTINATION native
    ARCHIVE DESTINATION lib)

if(ARCFORGES_BUILD_TESTS)
    add_executable(arcscope_mdf_abi_tests "tests/arcscope_mdf_abi_tests.cpp")
    target_compile_features(arcscope_mdf_abi_tests PRIVATE cxx_std_20)
    target_link_libraries(arcscope_mdf_abi_tests PRIVATE arcscope_mdf_abi)
    add_test(NAME arcscope_mdf_abi.hello COMMAND arcscope_mdf_abi_tests)
endif()
