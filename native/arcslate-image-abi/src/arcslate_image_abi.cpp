// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_image_abi.h>

#include "arc_native_abi_internal.hpp"

#include <OpenImageIO/imageio.h>

#ifndef ARCFORGES_SHIM_STATIC_GRAPH
#error ArcSlateImageNative must be built from the shim-static dependency graph.
#endif

namespace {
constexpr uint32_t image_domain = 0x494D4147U;
}

arc_status_t ARC_ABI_CALL arc_image_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    return arc::abi::get_abi_version(out_major, out_minor);
}

arc_status_t ARC_ABI_CALL arc_image_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        if (OIIO::get_string_attribute("format_list").empty()) {
            return arc::abi::fail(ARC_INTERNAL, "OpenImageIO format probe failed", image_domain);
        }
        return arc::abi::write_build_info("ArcSlateImageNative;abi=1.0;openimageio=3.1.14.0", out_utf8);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "OpenImageIO build probe failed", image_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_image_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
