// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_graphics_metal_abi.h>

int main()
{
    return (arc_graphics_metal_abi_version() == ARC_NATIVE_ABI_VERSION && arc_graphics_metal_hello() == ARC_STATUS_OK)
               ? 0
               : 1;
}
