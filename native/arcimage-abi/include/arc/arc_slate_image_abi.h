// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_SLATE_IMAGE_ABI_H
#define ARC_SLATE_IMAGE_ABI_H

#include <arc/arc_native_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_get_abi_version(uint32_t* out_major, uint32_t* out_minor);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_get_build_info(arc_mut_buffer_t* out_utf8);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_get_last_error(arc_error_info_t* out_error);

ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_open(const arc_io_v1* io, const arc_image_options_v1* options,
                                                        arc_handle_t* image, arc_mut_buffer_t* metadata,
                                                        const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_read(arc_handle_t image, const arc_region_v1* region,
                                                        arc_mut_buffer_t* pixels, const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_close(arc_handle_t image);

#ifdef __cplusplus
}
#endif

#endif
