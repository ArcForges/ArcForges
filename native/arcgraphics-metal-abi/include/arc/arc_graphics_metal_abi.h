// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_GRAPHICS_METAL_ABI_H
#define ARC_GRAPHICS_METAL_ABI_H

#include <arc/arc_native_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

ARC_ABI_EXPORT uint32_t ARC_ABI_CALL arc_graphics_metal_abi_version(void);
ARC_ABI_EXPORT arc_status ARC_ABI_CALL arc_graphics_metal_hello(void);

#ifdef __cplusplus
}
#endif

#endif
