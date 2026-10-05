# SPDX-License-Identifier: AGPL-3.0-only
set(ARCFORGES_SPDX_LICENSE "AGPL-3.0-only")
set(ARCFORGES_LICENCE_BOUNDARY "AGPL")

# The owned arc_pdf_* engine behind a backend interface (src/pdf_backend.hpp). This delivery links NO PDF parser:
# backend_none.cpp makes arc_pdf_open fail closed with ARC_UNSUPPORTED. The PDFium binding replaces that one source
# in a later, separately admitted change; nothing here downloads, builds or vendors PDFium.
set(ARCPDF_ENGINE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/pdf_engine.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/arcpdf_abi.cpp"
    ${ARCFORGES_SHARED_ABI_SOURCE})

add_library(arcpdf_abi SHARED ${ARCPDF_ENGINE_SOURCES} "${CMAKE_CURRENT_SOURCE_DIR}/src/backend_none.cpp")
arcforges_declare_target_licence(arcpdf_abi)
add_dependencies(arcpdf_abi arcforges_build_identity)
target_compile_features(arcpdf_abi PRIVATE cxx_std_20)
set_target_properties(arcpdf_abi PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME "ArcPdfNative")
target_include_directories(arcpdf_abi
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE}")

if(MSVC)
    target_compile_options(arcpdf_abi PRIVATE /W4 /WX /permissive- /EHsc /GR-)
    target_link_options(arcpdf_abi PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports/windows.def")
elseif(APPLE)
    target_compile_options(arcpdf_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcpdf_abi PRIVATE "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/macos.exports")
else()
    target_compile_options(arcpdf_abi PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    target_link_options(arcpdf_abi PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/linux.map")
endif()

install(TARGETS arcpdf_abi
    RUNTIME DESTINATION native
    LIBRARY DESTINATION native
    ARCHIVE DESTINATION lib)

if(ARCFORGES_BUILD_TESTS)
    find_package(Threads REQUIRED)

    # The engine compiled together with the scripted fake backend (test only; the fake is never part of arcpdf_abi).
    add_executable(arcpdf_abi_engine_tests
        "tests/arcpdf_abi_engine_tests.cpp"
        ${ARCPDF_ENGINE_SOURCES})
    arcforges_declare_target_licence(arcpdf_abi_engine_tests)
    set_target_properties(arcpdf_abi_engine_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
    add_dependencies(arcpdf_abi_engine_tests arcforges_build_identity)
    target_compile_features(arcpdf_abi_engine_tests PRIVATE cxx_std_20)
    target_include_directories(arcpdf_abi_engine_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include"
        "${ARCFORGES_SHARED_ABI_PRIVATE_INCLUDE}")
    target_link_libraries(arcpdf_abi_engine_tests PRIVATE Threads::Threads)
    if(MSVC)
        target_compile_options(arcpdf_abi_engine_tests PRIVATE /W4 /WX /permissive- /EHsc /GR-)
    else()
        target_compile_options(arcpdf_abi_engine_tests PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
    endif()
    add_test(NAME arcpdf_abi_engine_tests COMMAND arcpdf_abi_engine_tests)

    # The shipped configuration: the real library target with no parser linked.
    add_executable(arcpdf_abi_unsupported_tests "tests/arcpdf_abi_unsupported_tests.cpp")
    arcforges_declare_target_licence(arcpdf_abi_unsupported_tests)
    set_target_properties(arcpdf_abi_unsupported_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
    target_compile_features(arcpdf_abi_unsupported_tests PRIVATE cxx_std_20)
    target_link_libraries(arcpdf_abi_unsupported_tests PRIVATE arcpdf_abi)
    add_test(NAME arcpdf_abi_unsupported_tests COMMAND arcpdf_abi_unsupported_tests)
endif()
