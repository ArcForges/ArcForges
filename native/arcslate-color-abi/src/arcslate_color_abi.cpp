// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_color_abi.h>

#include "arc_native_abi_internal.hpp"

#include <OpenColorIO/OpenColorIO.h>

namespace OCIO = OCIO_NAMESPACE;

#ifndef ARCFORGES_SHIM_STATIC_GRAPH
#error ArcSlateColorNative must be built from the shim-static dependency graph.
#endif

namespace {
constexpr uint32_t color_domain = 0x434F4C52U;
}

arc_status_t ARC_ABI_CALL arc_color_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    return arc::abi::get_abi_version(out_major, out_minor);
}

arc_status_t ARC_ABI_CALL arc_color_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        const char* version = OCIO::GetVersion();
        if (version == nullptr || *version != '2') {
            return arc::abi::fail(ARC_VERSION_MISMATCH, "OpenColorIO version probe failed", color_domain);
        }
        return arc::abi::write_build_info("ArcSlateColorNative;abi=1.0;opencolorio=2.5.2", out_utf8);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "OpenColorIO build probe failed", color_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_color_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
