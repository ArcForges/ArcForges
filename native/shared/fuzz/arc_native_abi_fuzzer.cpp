// SPDX-License-Identifier: AGPL-3.0-only

#include <arc/arc_native_abi.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#ifndef ARCFORGES_FUZZ_GET_ABI_VERSION
#error "ARCFORGES_FUZZ_GET_ABI_VERSION must name the ABI version export"
#endif
#ifndef ARCFORGES_FUZZ_GET_BUILD_INFO
#error "ARCFORGES_FUZZ_GET_BUILD_INFO must name the build-info export"
#endif
#ifndef ARCFORGES_FUZZ_GET_LAST_ERROR
#error "ARCFORGES_FUZZ_GET_LAST_ERROR must name the last-error export"
#endif

extern "C" arc_status_t ARCFORGES_FUZZ_GET_ABI_VERSION(std::uint32_t* major, std::uint32_t* minor);
extern "C" arc_status_t ARCFORGES_FUZZ_GET_BUILD_INFO(arc_mut_buffer_t* output);
extern "C" arc_status_t ARCFORGES_FUZZ_GET_LAST_ERROR(arc_error_info_t* output);

namespace {
[[noreturn]] void fail() noexcept
{
    __builtin_trap();
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    std::uint32_t major = 0;
    std::uint32_t minor = 0;
    if (ARCFORGES_FUZZ_GET_ABI_VERSION(&major, &minor) != ARC_OK || major != ARC_NATIVE_ABI_MAJOR) {
        fail();
    }

    const std::uint64_t requested = size == 0U ? 0U : data[0];
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(requested));
    arc_mut_buffer_t buffer{bytes.empty() ? nullptr : bytes.data(), requested, 0U};
    const arc_status_t build_status = ARCFORGES_FUZZ_GET_BUILD_INFO(&buffer);
    if (build_status != ARC_OK && build_status != ARC_BUFFER_TOO_SMALL) {
        fail();
    }
    if (buffer.required == 0U ||
        buffer.required > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        fail();
    }

    arc_error_info_t error{};
    error.struct_size = sizeof(error);
    error.struct_version = 1U;
    if (ARCFORGES_FUZZ_GET_LAST_ERROR(&error) != ARC_OK || error.message_utf8.required > error.message_utf8.capacity) {
        fail();
    }
    return 0;
}
