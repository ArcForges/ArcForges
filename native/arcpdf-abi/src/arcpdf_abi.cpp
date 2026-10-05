// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_pdf_abi.h>

#include "arc_native_abi_internal.hpp"
#include "pdf_backend.hpp"

arc_status_t ARC_ABI_CALL arc_pdf_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    if (out_major == nullptr || out_minor == nullptr) {
        return arc::abi::fail(ARC_INVALID_ARGUMENT, "ABI version outputs are required", arc::pdf::pdf_domain);
    }
    *out_major = ARC_NATIVE_ABI_MAJOR;
    *out_minor = ARC_NATIVE_FUNCTIONAL_ABI_MINOR; // this library ships the functional exports
    return ARC_OK;
}

arc_status_t ARC_ABI_CALL arc_pdf_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        // The backend is named so a consumer can tell a parserless build from one with a parser linked.
        return arc::abi::write_build_info(arc::pdf::linked_backend() ? "ArcPdfNative;abi=1.1;backend=linked"
                                                                     : "ArcPdfNative;abi=1.1;backend=none",
                                          out_utf8);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "PDF build information failed", arc::pdf::pdf_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_pdf_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
