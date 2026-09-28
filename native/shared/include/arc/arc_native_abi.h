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
/* The retained probe-only image library stays at 1.0 until functional exports ship. */
#define ARC_NATIVE_ABI_MINOR UINT32_C(0)
#define ARC_NATIVE_FUNCTIONAL_ABI_MINOR UINT32_C(1)
#define ARC_NATIVE_RECORD_VERSION_1 UINT32_C(1)

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
    ARC_INTERNAL = -13,
    ARC_END_OF_STREAM = 2,
    ARC_WOULD_BLOCK = 3
};

typedef uint8_t arc_bool_t;
/* Opaque nonzero process-local generation token; never a pointer or durable/wire identifier. */
typedef uint64_t arc_handle_t;

enum {
    ARC_IO_READ = 1,
    ARC_IO_WRITE = 2,
    ARC_FRAME_VIDEO = 1,
    ARC_FRAME_AUDIO = 2,
    ARC_FRAME_SUBTITLE = 3,
    ARC_FRAME_DATA = 4,
    ARC_FORMAT_RGBA8 = 1,
    ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED = 2,
    ARC_FORMAT_FLOAT32_INTERLEAVED = 3,
    ARC_INSTRUMENT_SERIAL = 1,
    ARC_INSTRUMENT_USB = 2,
    ARC_PARITY_NONE = 0,
    ARC_PARITY_ODD = 1,
    ARC_PARITY_EVEN = 2,
    ARC_STOP_BITS_ONE = 1,
    ARC_STOP_BITS_TWO = 2,
    ARC_FLOW_CONTROL_NONE = 0,
    ARC_FLOW_CONTROL_RTS_CTS = 1,
    ARC_FLOW_CONTROL_XON_XOFF = 2,
    ARC_TRANSFER_USB_CONTROL = 1,
    ARC_TRANSFER_USB_BULK = 2,
    ARC_TRANSFER_USB_INTERRUPT = 3,
    ARC_TRANSFER_SERIAL_READ = 4,
    ARC_TRANSFER_SERIAL_WRITE = 5
};

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

/* Record v1 requires its full known prefix; same-version unknown tails are ignored. */
/* I/O callbacks borrow buffers only until return; read may be short at EOF; done is required. */
typedef arc_status_t(ARC_ABI_CALL* arc_read_at_fn)(void* context, uint64_t offset, void* destination,
                                                   uint64_t requested, uint64_t* done);
typedef arc_status_t(ARC_ABI_CALL* arc_write_at_fn)(void* context, uint64_t offset, const void* source,
                                                    uint64_t requested, uint64_t* done);
typedef arc_status_t(ARC_ABI_CALL* arc_flush_fn)(void* context);

typedef struct arc_io_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    void* context;
    uint64_t length;
    uint64_t max_length;
    arc_read_at_fn read_at;
    arc_write_at_fn write_at;
    arc_flush_fn flush;
} arc_io_v1;

typedef struct arc_limits_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    uint64_t max_input_bytes;
    uint64_t max_memory_bytes;
    uint64_t max_output_bytes;
    uint32_t max_width;
    uint32_t max_height;
    uint32_t max_items;
    uint32_t timeout_ms;
} arc_limits_v1;

typedef struct arc_frame_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    arc_handle_t buffer;
    uint64_t sequence;
    int64_t pts;
    int64_t duration;
    arc_rational_t time_base;
    uint32_t kind;
    uint32_t format;
    uint32_t width;
    uint32_t height;
    uint32_t sample_rate;
    uint32_t channels;
    uint64_t sample_count;
    uint64_t byte_length;
    uint32_t flags;
    uint32_t reserved;
} arc_frame_v1;

typedef struct arc_region_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    uint64_t first_sample;
    uint64_t sample_count;
    uint64_t row_stride;
} arc_region_v1;

typedef struct arc_instrument_options_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    arc_string_view_t device_id;
    uint32_t transport;
    uint32_t interface_number;
    uint32_t baud;
    uint32_t data_bits;
    uint32_t parity;
    uint32_t stop_bits;
    uint32_t flow_control;
    uint32_t reserved;
} arc_instrument_options_v1;

typedef struct arc_transfer_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    uint32_t kind;
    uint32_t endpoint;
    uint32_t timeout_ms;
    uint32_t request_type;
    uint32_t request;
    uint32_t value;
    uint32_t index;
    uint32_t reserved;
} arc_transfer_v1;

typedef struct arc_image_options_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    uint32_t subimage;
    uint32_t mip;
    uint32_t format;
    uint32_t reserved;
    arc_limits_v1 limits;
} arc_image_options_v1;

typedef struct arc_pdf_page_v1 {
    uint32_t struct_size;
    uint32_t struct_version;
    uint32_t page_index;
    uint32_t rotation;
    double width_points;
    double height_points;
} arc_pdf_page_v1;
#pragma pack(pop)

/* ABI 1.1 family declarations are shared here; family bodies/exports are delivered separately. */
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_instruments_list(uint32_t transport, arc_mut_buffer_t* devices);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_instruments_open(const arc_instrument_options_v1* options,
                                                              arc_handle_t* device);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_instruments_read(arc_handle_t device, const arc_transfer_v1* transfer,
                                                              arc_mut_buffer_t* data, uint64_t* actual,
                                                              const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_instruments_write(arc_handle_t device, const arc_transfer_v1* transfer,
                                                               arc_byte_view_t data, uint64_t* actual,
                                                               const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_instruments_cancel(arc_handle_t device);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_instruments_close(arc_handle_t device);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_open(const arc_io_v1* io, const arc_image_options_v1* options,
                                                        arc_handle_t* image, arc_mut_buffer_t* metadata,
                                                        const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_read(arc_handle_t image, const arc_region_v1* region,
                                                        arc_mut_buffer_t* pixels, const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_image_close(arc_handle_t image);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_open(const arc_io_v1* io, arc_string_view_t password,
                                                      const arc_limits_v1* limits, arc_handle_t* document,
                                                      uint32_t* pages, const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_page_info(arc_handle_t document, uint32_t index,
                                                           arc_pdf_page_v1* page);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_render(arc_handle_t document, const arc_pdf_page_v1* page,
                                                        const arc_region_v1* region, uint32_t full_width,
                                                        uint32_t full_height, arc_mut_buffer_t* rgba8,
                                                        const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_text(arc_handle_t document, uint32_t page, uint32_t start,
                                                      uint32_t count, arc_mut_buffer_t* text_geometry,
                                                      const arc_cancel_token_t* cancel);
ARC_ABI_EXPORT arc_status_t ARC_ABI_CALL arc_pdf_close(arc_handle_t document);

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus)
#define ARC_ABI_LAYOUT_ASSERT(expression) static_assert((expression), #expression)
#define ARC_ABI_ALIGNOF(type) alignof(type)
#else
#define ARC_ABI_LAYOUT_ASSERT(expression) _Static_assert((expression), #expression)
#define ARC_ABI_ALIGNOF(type) _Alignof(type)
#endif

ARC_ABI_LAYOUT_ASSERT(sizeof(arc_status_t) == 4);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_bool_t) == 1);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_handle_t) == 8);
ARC_ABI_LAYOUT_ASSERT(ARC_OK == 0 && ARC_BUFFER_TOO_SMALL == 1);
ARC_ABI_LAYOUT_ASSERT(ARC_END_OF_STREAM == 2 && ARC_WOULD_BLOCK == 3);
ARC_ABI_LAYOUT_ASSERT(ARC_INVALID_ARGUMENT == -1 && ARC_INTERNAL == -13);
ARC_ABI_LAYOUT_ASSERT(ARC_NATIVE_ABI_MAJOR == 1 && ARC_NATIVE_ABI_MINOR == 0);
ARC_ABI_LAYOUT_ASSERT(ARC_NATIVE_FUNCTIONAL_ABI_MINOR == 1 && ARC_NATIVE_RECORD_VERSION_1 == 1);
ARC_ABI_LAYOUT_ASSERT(ARC_IO_READ == 1 && ARC_IO_WRITE == 2);
ARC_ABI_LAYOUT_ASSERT(ARC_FRAME_VIDEO == 1 && ARC_FRAME_AUDIO == 2 && ARC_FRAME_SUBTITLE == 3 && ARC_FRAME_DATA == 4);
ARC_ABI_LAYOUT_ASSERT(ARC_FORMAT_RGBA8 == 1 && ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED == 2 &&
                      ARC_FORMAT_FLOAT32_INTERLEAVED == 3);
ARC_ABI_LAYOUT_ASSERT(ARC_INSTRUMENT_SERIAL == 1 && ARC_INSTRUMENT_USB == 2);
ARC_ABI_LAYOUT_ASSERT(ARC_PARITY_NONE == 0 && ARC_PARITY_ODD == 1 && ARC_PARITY_EVEN == 2);
ARC_ABI_LAYOUT_ASSERT(ARC_STOP_BITS_ONE == 1 && ARC_STOP_BITS_TWO == 2);
ARC_ABI_LAYOUT_ASSERT(ARC_FLOW_CONTROL_NONE == 0 && ARC_FLOW_CONTROL_RTS_CTS == 1 && ARC_FLOW_CONTROL_XON_XOFF == 2);
ARC_ABI_LAYOUT_ASSERT(ARC_TRANSFER_USB_CONTROL == 1 && ARC_TRANSFER_USB_BULK == 2 && ARC_TRANSFER_USB_INTERRUPT == 3 &&
                      ARC_TRANSFER_SERIAL_READ == 4 && ARC_TRANSFER_SERIAL_WRITE == 5);
#if INTPTR_MAX == INT64_MAX
ARC_ABI_LAYOUT_ASSERT(sizeof(double) == 8);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_string_view_t) == 16 && ARC_ABI_ALIGNOF(arc_string_view_t) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_string_view_t, data) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_string_view_t, size) == 8);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_byte_view_t) == 16 && ARC_ABI_ALIGNOF(arc_byte_view_t) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_byte_view_t, data) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_byte_view_t, size) == 8);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_mut_buffer_t) == 24 && ARC_ABI_ALIGNOF(arc_mut_buffer_t) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_mut_buffer_t, data) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_mut_buffer_t, capacity) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_mut_buffer_t, required) == 16);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_rational_t) == 16 && ARC_ABI_ALIGNOF(arc_rational_t) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_rational_t, numerator) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_rational_t, denominator) == 8);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_time_range_t) == 32 && ARC_ABI_ALIGNOF(arc_time_range_t) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_time_range_t, start) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_time_range_t, duration) == 16);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_error_info_t) == 48 && ARC_ABI_ALIGNOF(arc_error_info_t) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_error_info_t, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_error_info_t, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_error_info_t, status) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_error_info_t, domain) == 12);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_error_info_t, correlation_id) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_error_info_t, message_utf8) == 24);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_cancel_token_t) == 24 && ARC_ABI_ALIGNOF(arc_cancel_token_t) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_cancel_token_t, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_cancel_token_t, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_cancel_token_t, is_cancelled) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_cancel_token_t, user_data) == 16);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_io_v1) == 56 && ARC_ABI_ALIGNOF(arc_io_v1) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, context) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, length) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, max_length) == 24);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, read_at) == 32);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, write_at) == 40);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_io_v1, flush) == 48);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_limits_v1) == 48 && ARC_ABI_ALIGNOF(arc_limits_v1) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, max_input_bytes) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, max_memory_bytes) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, max_output_bytes) == 24);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, max_width) == 32);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, max_height) == 36);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, max_items) == 40);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_limits_v1, timeout_ms) == 44);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_frame_v1) == 104 && ARC_ABI_ALIGNOF(arc_frame_v1) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, buffer) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, sequence) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, pts) == 24);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, duration) == 32);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, time_base) == 40);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, kind) == 56);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, format) == 60);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, width) == 64);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, height) == 68);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, sample_rate) == 72);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, channels) == 76);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, sample_count) == 80);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, byte_length) == 88);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, flags) == 96);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_frame_v1, reserved) == 100);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_region_v1) == 48 && ARC_ABI_ALIGNOF(arc_region_v1) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, x) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, y) == 12);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, width) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, height) == 20);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, first_sample) == 24);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, sample_count) == 32);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_region_v1, row_stride) == 40);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_instrument_options_v1) == 56 && ARC_ABI_ALIGNOF(arc_instrument_options_v1) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, device_id) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, transport) == 24);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, interface_number) == 28);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, baud) == 32);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, data_bits) == 36);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, parity) == 40);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, stop_bits) == 44);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, flow_control) == 48);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_instrument_options_v1, reserved) == 52);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_transfer_v1) == 40 && ARC_ABI_ALIGNOF(arc_transfer_v1) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, kind) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, endpoint) == 12);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, timeout_ms) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, request_type) == 20);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, request) == 24);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, value) == 28);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, index) == 32);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_transfer_v1, reserved) == 36);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_image_options_v1) == 72 && ARC_ABI_ALIGNOF(arc_image_options_v1) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_image_options_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_image_options_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_image_options_v1, subimage) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_image_options_v1, mip) == 12);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_image_options_v1, format) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_image_options_v1, reserved) == 20);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_image_options_v1, limits) == 24);
ARC_ABI_LAYOUT_ASSERT(sizeof(arc_pdf_page_v1) == 32 && ARC_ABI_ALIGNOF(arc_pdf_page_v1) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_pdf_page_v1, struct_size) == 0);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_pdf_page_v1, struct_version) == 4);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_pdf_page_v1, page_index) == 8);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_pdf_page_v1, rotation) == 12);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_pdf_page_v1, width_points) == 16);
ARC_ABI_LAYOUT_ASSERT(offsetof(arc_pdf_page_v1, height_points) == 24);
#endif
#undef ARC_ABI_LAYOUT_ASSERT
#undef ARC_ABI_ALIGNOF

#endif
