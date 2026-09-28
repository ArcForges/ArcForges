// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_native_abi.h>

_Static_assert(sizeof(void*) == 8, "ArcForges native ABI is 64-bit only");

int main(void)
{
    return ARC_NATIVE_ABI_MAJOR == UINT32_C(1) && ARC_NATIVE_ABI_MINOR == UINT32_C(0) &&
                   ARC_NATIVE_FUNCTIONAL_ABI_MINOR == UINT32_C(1) && ARC_NATIVE_RECORD_VERSION_1 == UINT32_C(1) &&
                   sizeof(arc_status_t) == 4 && sizeof(arc_bool_t) == 1 && sizeof(arc_handle_t) == 8
               ? 0
               : 1;
}
