// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_NATIVE_ABI_H
#define ARC_NATIVE_ABI_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define ARC_ABI_EXPORT __declspec(dllexport)
#define ARC_ABI_CALL __cdecl
#else
#define ARC_ABI_EXPORT __attribute__((visibility("default")))
#define ARC_ABI_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ARC_NATIVE_ABI_VERSION UINT32_C(1)

typedef enum arc_status {
    ARC_STATUS_OK = 0,
    ARC_STATUS_INVALID_ARGUMENT = 1,
    ARC_STATUS_NOT_SUPPORTED = 2,
    ARC_STATUS_INTERNAL_ERROR = 3
} arc_status;

typedef struct arc_read_only_buffer {
    const uint8_t* data;
    size_t size;
} arc_read_only_buffer;

typedef struct arc_mutable_buffer {
    uint8_t* data;
    size_t capacity;
} arc_mutable_buffer;

#ifdef __cplusplus
}
#endif

#endif
