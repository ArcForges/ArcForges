// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_image_abi.h>

#include "arc_native_abi_internal.hpp"

#include <OpenImageIO/imageio.h>

#ifndef ARCFORGES_SHIM_STATIC_GRAPH
#error ArcImageNative must be built from the shim-static dependency graph.
#endif

namespace {
constexpr uint32_t image_domain = 0x494D4147U;
}

arc_status_t ARC_ABI_CALL arc_image_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    if (!out_major || !out_minor)
        return arc::abi::fail(ARC_INVALID_ARGUMENT, "Version outputs required", image_domain);
    *out_major = 1;
    *out_minor = 1;
    return ARC_OK;
}

arc_status_t ARC_ABI_CALL arc_image_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        // Functional readers bind the three embedded factories directly. Do not enumerate dynamic
        // plugins before the helper's OS restrictions have been applied.
        return arc::abi::write_build_info("ArcImageNative;abi=1.1;openimageio=3.1.14.0;formats=png,tiff,exr;rgba8;"
                                          "rgba32fLinearPremultiplied;maxTileBytes=67108864;maxHandles=64",
                                          out_utf8);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "OpenImageIO build probe failed", image_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_image_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
