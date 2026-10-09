# SPDX-License-Identifier: AGPL-3.0-only
set(ARCFORGES_SPDX_LICENSE "AGPL-3.0-only")
set(ARCFORGES_LICENCE_BOUNDARY "AGPL")
file(GLOB_RECURSE ARCFORGES_SHIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE ARCFORGES_SHIM_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(arcslate_image_abi SHARED ${ARCFORGES_SHIM_SOURCES} ${ARCFORGES_SHIM_HEADERS} ${ARCFORGES_SHARED_ABI_SOURCE})
arcforges_declare_target_licence(arcslate_image_abi)
add_dependencies(arcslate_image_abi arcforges_build_identity)
target_compile_features(arcslate_image_abi PRIVATE cxx_std_20)
set_target_properties(arcslate_image_abi PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    OUTPUT_NAME "ArcImageNative")
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
    arcforges_declare_target_licence(arcslate_image_abi_tests)
    set_target_properties(arcslate_image_abi_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
    target_compile_features(arcslate_image_abi_tests PRIVATE cxx_std_20)
    target_link_libraries(arcslate_image_abi_tests PRIVATE arcslate_image_abi)
    add_test(NAME arcslate_image_abi.hello COMMAND arcslate_image_abi_tests)

    add_executable(arcslate_image_codec_tests "tests/arcslate_image_codec_tests.cpp")
    arcforges_declare_target_licence(arcslate_image_codec_tests)
    set_target_properties(arcslate_image_codec_tests PROPERTIES ARCFORGES_TEST_ONLY TRUE)
    target_compile_features(arcslate_image_codec_tests PRIVATE cxx_std_20)
    target_link_libraries(arcslate_image_codec_tests PRIVATE arcslate_image_abi OpenImageIO::OpenImageIO)
    # One CTest target per codec test. Keep this list in step with test_cases in tests/arcslate_image_codec_tests.cpp.
    set(ARCFORGES_IMAGE_CODEC_TESTS
        probe
        png_rgba8
        png_rgb_fills_alpha
        png16_bit_loss
        png16_float_identity
        png_linear_premultiply
        tiff8_straight
        tiff16_float_identity
        exr_float
        exr_half_clamp
        exr_premultiplied
        tiff_associated
        tiled_tiff_edges
        edge_one_pixel
        coverage_order
        coverage_refusals
        buffer_too_small
        buffer_one_byte_short
        unsupported_content
        unsupported_formats
        corrupt_input
        failed_codec
        limits_bomb
        bomb_before_decode
        region_validation
        options_subimage
        cancellation
        cancel_each_boundary
        read_deadline
        callback_failures
        handle_lifecycle
        exr_multipart
        exr_mips
        oiio_size_pin)
    foreach(codec_test IN LISTS ARCFORGES_IMAGE_CODEC_TESTS)
        add_test(NAME arcslate_image_abi.codec.${codec_test} COMMAND arcslate_image_codec_tests ${codec_test})
    endforeach()
endif()
