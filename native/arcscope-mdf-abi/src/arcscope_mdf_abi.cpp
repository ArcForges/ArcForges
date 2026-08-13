// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_scope_mdf_abi.h>

#include "arc_native_abi_internal.hpp"

#include <mdf/mdffactory.h>
#include <mdf/mdffile.h>

#ifndef ARCFORGES_SHIM_STATIC_GRAPH
#error ArcScopeMdfNative must be built from the shim-static dependency graph.
#endif

namespace {
constexpr uint32_t mdf_domain = 0x4D444620U;
}

arc_status_t ARC_ABI_CALL arc_mdf_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    return arc::abi::get_abi_version(out_major, out_minor);
}

arc_status_t ARC_ABI_CALL arc_mdf_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        const auto file = mdf::MdfFactory::CreateMdfFile(mdf::MdfFileType::Mdf4FileType);
        if (file == nullptr) {
            return arc::abi::fail(ARC_INTERNAL, "mdflib factory probe failed", mdf_domain);
        }
        return arc::abi::write_build_info("ArcScopeMdfNative;abi=1.0;mdflib=2.3.0", out_utf8);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "mdflib build probe failed", mdf_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_mdf_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
