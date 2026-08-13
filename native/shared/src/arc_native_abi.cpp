// SPDX-License-Identifier: AGPL-3.0-only
#include "arc_native_abi_internal.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace {

constexpr size_t error_message_capacity = 512;

struct error_state final {
    arc_status_t status = ARC_OK;
    uint32_t domain = 0;
    uint64_t correlation_id = 0;
    uint64_t message_size = 0;
    std::array<char, error_message_capacity> message{};
};

error_state& last_error_state() noexcept
{
    static thread_local error_state state;
    return state;
}

arc_status_t copy_utf8(std::string_view value, arc_mut_buffer_t* output) noexcept
{
    if (output == nullptr) {
        return ARC_INVALID_ARGUMENT;
    }

    output->required = static_cast<uint64_t>(value.size());
    if (output->data == nullptr && output->capacity != 0) {
        return ARC_INVALID_ARGUMENT;
    }
    if (output->capacity < value.size()) {
        return ARC_BUFFER_TOO_SMALL;
    }

    if (value.empty()) {
        return ARC_OK;
    }

    void* const data = output->data;
    if (data == nullptr) {
        return ARC_INVALID_ARGUMENT;
    }
    std::memcpy(data, value.data(), value.size());
    return ARC_OK;
}

} // namespace

arc_status_t arc::abi::fail(arc_status_t status, std::string_view message, uint32_t domain) noexcept
{
    error_state& error = last_error_state();
    error.status = status;
    error.domain = domain;
    ++error.correlation_id;
    error.message_size = std::min<uint64_t>(message.size(), error.message.size());
    if (error.message_size != 0) {
        std::memcpy(error.message.data(), message.data(), static_cast<size_t>(error.message_size));
    }
    return status;
}

arc_status_t arc::abi::get_abi_version(uint32_t* out_major, uint32_t* out_minor) noexcept
{
    if (out_major == nullptr || out_minor == nullptr) {
        return fail(ARC_INVALID_ARGUMENT, "ABI version outputs are required", 0);
    }
    *out_major = ARC_NATIVE_ABI_MAJOR;
    *out_minor = ARC_NATIVE_ABI_MINOR;
    return ARC_OK;
}

arc_status_t arc::abi::write_build_info(std::string_view value, arc_mut_buffer_t* out_utf8) noexcept
{
    const arc_status_t status = copy_utf8(value, out_utf8);
    if (status != ARC_OK && status != ARC_BUFFER_TOO_SMALL) {
        return fail(status, "Build-info output buffer is invalid", 0);
    }
    return status;
}

arc_status_t arc::abi::get_last_error(arc_error_info_t* out_error) noexcept
{
    if (out_error == nullptr || out_error->struct_size < sizeof(arc_error_info_t) || out_error->struct_version != 1) {
        return fail(ARC_INVALID_ARGUMENT, "Error-info layout is invalid", 0);
    }

    error_state& error = last_error_state();
    arc_mut_buffer_t message = out_error->message_utf8;
    out_error->status = error.status;
    out_error->domain = error.domain;
    out_error->correlation_id = error.correlation_id;
    const std::string_view text(error.message.data(), static_cast<size_t>(error.message_size));
    const arc_status_t status = copy_utf8(text, &message);
    out_error->message_utf8 = message;
    return status;
}
