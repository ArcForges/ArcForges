// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_native_abi.h>

_Static_assert(sizeof(void*) == 8, "ArcForges native ABI is 64-bit only");

typedef arc_status_t(ARC_ABI_CALL* arc_instruments_list_signature_t)(uint32_t, arc_mut_buffer_t*);
typedef arc_status_t(ARC_ABI_CALL* arc_instruments_open_signature_t)(const arc_instrument_options_v1*, arc_handle_t*);
typedef arc_status_t(ARC_ABI_CALL* arc_instruments_read_signature_t)(arc_handle_t, const arc_transfer_v1*,
                                                                     arc_mut_buffer_t*, uint64_t*,
                                                                     const arc_cancel_token_t*);
typedef arc_status_t(ARC_ABI_CALL* arc_instruments_write_signature_t)(arc_handle_t, const arc_transfer_v1*,
                                                                      arc_byte_view_t, uint64_t*,
                                                                      const arc_cancel_token_t*);
typedef arc_status_t(ARC_ABI_CALL* arc_instruments_cancel_signature_t)(arc_handle_t);
typedef arc_status_t(ARC_ABI_CALL* arc_instruments_close_signature_t)(arc_handle_t);
typedef arc_status_t(ARC_ABI_CALL* arc_image_open_signature_t)(const arc_io_v1*, const arc_image_options_v1*,
                                                               arc_handle_t*, arc_mut_buffer_t*,
                                                               const arc_cancel_token_t*);
typedef arc_status_t(ARC_ABI_CALL* arc_image_read_signature_t)(arc_handle_t, const arc_region_v1*, arc_mut_buffer_t*,
                                                               const arc_cancel_token_t*);
typedef arc_status_t(ARC_ABI_CALL* arc_image_close_signature_t)(arc_handle_t);

#define ARC_ABI_REQUIRE_SIGNATURE(function_name, signature_type)                                                       \
    _Static_assert(_Generic(&(function_name), signature_type: 1, default: 0), #function_name " signature mismatch")

ARC_ABI_REQUIRE_SIGNATURE(arc_instruments_list, arc_instruments_list_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_instruments_open, arc_instruments_open_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_instruments_read, arc_instruments_read_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_instruments_write, arc_instruments_write_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_instruments_cancel, arc_instruments_cancel_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_instruments_close, arc_instruments_close_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_image_open, arc_image_open_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_image_read, arc_image_read_signature_t);
ARC_ABI_REQUIRE_SIGNATURE(arc_image_close, arc_image_close_signature_t);

#undef ARC_ABI_REQUIRE_SIGNATURE

int main(void)
{
    return ARC_NATIVE_ABI_MAJOR == UINT32_C(1) && ARC_NATIVE_ABI_MINOR == UINT32_C(0) &&
                   ARC_NATIVE_FUNCTIONAL_ABI_MINOR == UINT32_C(1) && ARC_NATIVE_RECORD_VERSION_1 == UINT32_C(1) &&
                   sizeof(arc_status_t) == 4 && sizeof(arc_bool_t) == 1 && sizeof(arc_handle_t) == 8
               ? 0
               : 1;
}
