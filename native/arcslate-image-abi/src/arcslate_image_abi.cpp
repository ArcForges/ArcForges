// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_image_abi.h>

uint32_t ARC_ABI_CALL arc_slate_image_abi_version(void)
{
    return ARC_NATIVE_ABI_VERSION;
}

arc_status ARC_ABI_CALL arc_slate_image_hello(void)
{
    return ARC_STATUS_OK;
}
