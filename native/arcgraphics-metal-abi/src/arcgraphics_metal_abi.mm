// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_graphics_metal_abi.h>

#include "arc_native_abi_internal.hpp"

arc_status_t ARC_ABI_CALL arc_metal_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    return arc::abi::get_abi_version(out_major, out_minor);
}

arc_status_t ARC_ABI_CALL arc_metal_get_build_info(arc_mut_buffer_t* out_utf8)
{
    return arc::abi::write_build_info("ArcGraphicsMetalNative;abi=1.0;metal=system", out_utf8);
}

arc_status_t ARC_ABI_CALL arc_metal_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
