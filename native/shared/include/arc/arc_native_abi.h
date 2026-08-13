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

#define ARC_NATIVE_ABI_MAJOR UINT32_C(1)
#define ARC_NATIVE_ABI_MINOR UINT32_C(0)

typedef int32_t arc_status_t;
enum {
    ARC_OK = 0,
    ARC_BUFFER_TOO_SMALL = 1,
    ARC_INVALID_ARGUMENT = -1,
    ARC_NOT_FOUND = -2,
    ARC_UNSUPPORTED = -3,
    ARC_IO = -4,
    ARC_CANCELLED = -5,
    ARC_VERSION_MISMATCH = -6,
    ARC_CORRUPT = -7,
    ARC_OUT_OF_MEMORY = -8,
    ARC_RESOURCE_LIMIT = -9,
    ARC_CLOSED = -10,
    ARC_BUSY = -11,
    ARC_PERMISSION_DENIED = -12,
    ARC_INTERNAL = -13
};

typedef uint8_t arc_bool_t;

#pragma pack(push, 8)
typedef struct arc_string_view_t {
    const char* data;
    uint64_t size;
} arc_string_view_t;

typedef struct arc_byte_view_t {
    const void* data;
    uint64_t size;
} arc_byte_view_t;

typedef struct arc_mut_buffer_t {
    void* data;
    uint64_t capacity;
    uint64_t required;
} arc_mut_buffer_t;

typedef struct arc_rational_t {
    int64_t numerator;
    int64_t denominator;
} arc_rational_t;

typedef struct arc_time_range_t {
    arc_rational_t start;
    arc_rational_t duration;
} arc_time_range_t;

typedef struct arc_error_info_t {
    uint32_t struct_size;
    uint32_t struct_version;
    int32_t status;
    uint32_t domain;
    uint64_t correlation_id;
    arc_mut_buffer_t message_utf8;
} arc_error_info_t;

typedef arc_bool_t(ARC_ABI_CALL* arc_is_cancelled_fn)(void* user_data);

typedef struct arc_cancel_token_t {
    uint32_t struct_size;
    uint32_t struct_version;
    arc_is_cancelled_fn is_cancelled;
    void* user_data;
} arc_cancel_token_t;
#pragma pack(pop)

#ifdef __cplusplus
}

static_assert(sizeof(arc_status_t) == 4);
static_assert(sizeof(arc_bool_t) == 1);
#if INTPTR_MAX == INT64_MAX
static_assert(sizeof(arc_string_view_t) == 16 && alignof(arc_string_view_t) == 8);
static_assert(sizeof(arc_byte_view_t) == 16 && alignof(arc_byte_view_t) == 8);
static_assert(sizeof(arc_mut_buffer_t) == 24 && alignof(arc_mut_buffer_t) == 8);
static_assert(sizeof(arc_rational_t) == 16 && alignof(arc_rational_t) == 8);
static_assert(sizeof(arc_time_range_t) == 32 && alignof(arc_time_range_t) == 8);
static_assert(sizeof(arc_error_info_t) == 48 && alignof(arc_error_info_t) == 8);
static_assert(sizeof(arc_cancel_token_t) == 24 && alignof(arc_cancel_token_t) == 8);
#endif
#endif

#endif
