// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_graphics_metal_abi.h>

int main()
{
    uint32_t major = 0;
    uint32_t minor = 0;
    return arc_metal_get_abi_version(&major, &minor) == ARC_OK && major == 1 && minor == 0 ? 0 : 1;
}
