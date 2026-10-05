// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_PDF_ABI_H
#define ARC_PDF_ABI_H

#include <arc/arc_native_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The library preamble. The five functional arc_pdf_* exports are declared in arc_native_abi.h (ABI 1.1). */
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_get_abi_version(uint32_t* out_major, uint32_t* out_minor);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_get_build_info(arc_mut_buffer_t* out_utf8);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_get_last_error(arc_error_info_t* out_error);

#ifdef __cplusplus
}
#endif

#endif
