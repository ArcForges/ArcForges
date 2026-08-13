// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_otio_abi.h>

#include "arc_native_abi_internal.hpp"

#include <opentimelineio/version.h>

#ifndef ARCFORGES_SHIM_STATIC_GRAPH
#error ArcSlateOtioNative must be built from the shim-static dependency graph.
#endif

namespace {
constexpr uint32_t otio_domain = 0x4F54494FU;
}

arc_status_t ARC_ABI_CALL arc_otio_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    return arc::abi::get_abi_version(out_major, out_minor);
}

arc_status_t ARC_ABI_CALL arc_otio_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        const OTIO_NS::RationalTime frame(24.0, 24.0);
        if (frame.to_seconds() != 1.0) {
            return arc::abi::fail(ARC_INTERNAL, "OpenTimelineIO rational-time probe failed", otio_domain);
        }
        return arc::abi::write_build_info("ArcSlateOtioNative;abi=1.0;opentimelineio=0.18.1", out_utf8);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "OpenTimelineIO build probe failed", otio_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_otio_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
