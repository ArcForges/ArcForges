# SPDX-License-Identifier: AGPL-3.0-only
file(GLOB_RECURSE ARCFORGES_SHIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE ARCFORGES_SHIM_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(arcslate_image_abi SHARED ${ARCFORGES_SHIM_SOURCES} ${ARCFORGES_SHIM_HEADERS} ${ARCFORGES_SHARED_ABI_SOURCE})
target_compile_features(arcslate_image_abi PRIVATE cxx_std_20)
set_target_properties(arcslate_image_abi PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME "ArcSlateImageNative")
target_include_directories(arcslate_image_abi
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")
target_include_directories(arcslate_image_abi PRIVATE "${ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE}")
target_link_libraries(arcslate_image_abi PRIVATE OpenImageIO::OpenImageIO)
target_compile_definitions(arcslate_image_abi PRIVATE ARCFORGES_SHIM_STATIC_GRAPH=1)

if(MSVC)
    target_compile_options(arcslate_image_abi PRIVATE /W4 /WX /permissive- /EHsc /GR-)
    target_link_options(arcslate_image_abi PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports/windows.def")
elseif(APPLE)
    target_compile_options(arcslate_image_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcslate_image_abi PRIVATE "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
else()
    target_compile_options(arcslate_image_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcslate_image_abi PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
endif()

arcforges_add_abi_fuzzer(arcslate_image_abi_fuzzer arcslate_image_abi arc_image)

install(TARGETS arcslate_image_abi
    RUNTIME DESTINATION native
    LIBRARY DESTINATION native
    ARCHIVE DESTINATION lib)

if(ARCFORGES_BUILD_TESTS)
    add_executable(arcslate_image_abi_tests "tests/arcslate_image_abi_tests.cpp")
    target_compile_features(arcslate_image_abi_tests PRIVATE cxx_std_20)
    target_link_libraries(arcslate_image_abi_tests PRIVATE arcslate_image_abi)
    add_test(NAME arcslate_image_abi.hello COMMAND arcslate_image_abi_tests)
endif()
