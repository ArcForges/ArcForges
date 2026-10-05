// SPDX-License-Identifier: AGPL-3.0-only
// The shipped library configuration: no PDF parser is linked, so every open fails closed with ARC_UNSUPPORTED and
// leaves every output zeroed. This test links the real arcpdf_abi target, not the fake backend.
#include <arc/arc_pdf_abi.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace {
int g_failures = 0;
#define CHECK(expression)                                                                                              \
    do {                                                                                                               \
        if (!(expression)) {                                                                                           \
            std::fprintf(stderr, "FAILED %s:%d: %s\n", __FILE__, __LINE__, #expression);                               \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (false)

arc_status_t ARC_ABI_CALL never_read(void*, uint64_t, void*, uint64_t, uint64_t* done)
{
    *done = 0;
    return ARC_IO;
}
} // namespace

int main()
{
    uint32_t major = 0;
    uint32_t minor = 0;
    CHECK(arc_pdf_get_abi_version(&major, &minor) == ARC_OK && major == 1 && minor == 1);

    arc_mut_buffer_t query{};
    CHECK(arc_pdf_get_build_info(&query) == ARC_BUFFER_TOO_SMALL);
    std::string info(static_cast<size_t>(query.required), '\0');
    arc_mut_buffer_t output{info.data(), info.size(), 0};
    CHECK(arc_pdf_get_build_info(&output) == ARC_OK);
    CHECK(info.find("backend=none") != std::string::npos);

    arc_io_v1 io{};
    io.struct_size = sizeof(arc_io_v1);
    io.struct_version = 1;
    io.length = 16;
    io.max_length = 16;
    io.read_at = never_read;
    arc_limits_v1 limits{};
    limits.struct_size = sizeof(arc_limits_v1);
    limits.struct_version = 1;
    limits.max_input_bytes = 1024;
    limits.max_memory_bytes = 1024 * 1024;
    limits.max_output_bytes = 1024 * 1024;
    limits.max_width = 1024;
    limits.max_height = 1024;
    limits.max_items = 16;
    limits.timeout_ms = 1000;
    arc_handle_t document = 99;
    uint32_t pages = 99;
    CHECK(arc_pdf_open(&io, {}, &limits, &document, &pages, nullptr) == ARC_UNSUPPORTED);
    CHECK(document == 0 && pages == 0);

    arc_error_info_t error{};
    error.struct_size = sizeof(arc_error_info_t);
    error.struct_version = 1;
    CHECK(arc_pdf_get_last_error(&error) == ARC_BUFFER_TOO_SMALL && error.status == ARC_UNSUPPORTED);

    // Every other export refuses a handle the library never issued.
    arc_pdf_page_v1 page{};
    page.struct_size = sizeof(arc_pdf_page_v1);
    page.struct_version = 1;
    CHECK(arc_pdf_page_info(1, 0, &page) == ARC_CLOSED);
    CHECK(arc_pdf_close(1) == ARC_CLOSED);

    if (g_failures != 0) {
        return 1;
    }
    std::puts("arcpdf_abi_unsupported_tests: all checks passed");
    return 0;
}
