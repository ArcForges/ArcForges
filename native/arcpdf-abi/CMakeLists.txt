# SPDX-License-Identifier: AGPL-3.0-only
set(ARCFORGES_SPDX_LICENSE "AGPL-3.0-only")
set(ARCFORGES_LICENCE_BOUNDARY "AGPL")

# The owned arc_pdf_* engine behind a backend interface (src/pdf_backend.hpp). A production build requires
# the verified no-V8/no-XFA chromium/8044 admission prefix. Acquisition belongs to the producer build,
# never a consumer. The explicit parserless option is retained for isolated ABI fixtures only.
option(ARCFORGES_PDFIUM "Link the admitted real PDFium parser" OFF)
if(ARCFORGES_PDFIUM)
    find_package(PDFium CONFIG REQUIRED)
    if(NOT PDFium_VERSION STREQUAL "155.0.8044.0")
        message(FATAL_ERROR "PDFium must be the admitted chromium/8044 build")
    endif()
    set(ARCPDF_BACKEND_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/backend_pdfium.cpp")
else()
    set(ARCPDF_BACKEND_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/backend_none.cpp")
endif()
set(ARCPDF_ENGINE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/pdf_engine.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/arcpdf_abi.cpp"
    ${ARCFORGES_SHARED_ABI_SOURCE})

add_library(arcpdf_abi SHARED ${ARCPDF_ENGINE_SOURCES} ${ARCPDF_BACKEND_SOURCE})
if(ARCFORGES_PDFIUM)
    target_link_libraries(arcpdf_abi PRIVATE pdfium)
    target_compile_definitions(arcpdf_abi PRIVATE ARCFORGES_PDFIUM_BACKEND=1)
    install(FILES "$<TARGET_FILE:pdfium>" DESTINATION native)
endif()
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

    if(ARCFORGES_PDFIUM)
        add_executable(arcpdf_abi_pdfium_tests "tests/arcpdf_abi_pdfium_tests.cpp")
        arcforges_declare_target_licence(arcpdf_abi_pdfium_tests)
        set_target_properties(arcpdf_abi_pdfium_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
        target_compile_features(arcpdf_abi_pdfium_tests PRIVATE cxx_std_20)
        target_link_libraries(arcpdf_abi_pdfium_tests PRIVATE arcpdf_abi Threads::Threads)
        if(MSVC)
            target_compile_options(arcpdf_abi_pdfium_tests PRIVATE /W4 /WX /permissive- /EHsc /GR-)
        else()
            target_compile_options(arcpdf_abi_pdfium_tests PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
        endif()
        add_custom_command(TARGET arcpdf_abi_pdfium_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:pdfium>" "$<TARGET_FILE_DIR:arcpdf_abi_pdfium_tests>")
        add_test(NAME arcpdf_abi_pdfium_tests COMMAND arcpdf_abi_pdfium_tests)
        set_tests_properties(arcpdf_abi_pdfium_tests PROPERTIES LABELS "local-real-parser")
    else()
        add_executable(arcpdf_abi_unsupported_tests "tests/arcpdf_abi_unsupported_tests.cpp")
        arcforges_declare_target_licence(arcpdf_abi_unsupported_tests)
        set_target_properties(arcpdf_abi_unsupported_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
        target_compile_features(arcpdf_abi_unsupported_tests PRIVATE cxx_std_20)
        target_link_libraries(arcpdf_abi_unsupported_tests PRIVATE arcpdf_abi)
        add_test(NAME arcpdf_abi_unsupported_tests COMMAND arcpdf_abi_unsupported_tests)
    endif()
endif()
