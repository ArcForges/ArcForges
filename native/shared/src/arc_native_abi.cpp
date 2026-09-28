// SPDX-License-Identifier: AGPL-3.0-only
#include "arc_build_identity.hpp"
#include "arc_native_abi_internal.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>

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

bool decode_handle(arc_handle_t token, size_t& index, uint32_t& generation) noexcept
{
    const uint32_t slot_plus_one = static_cast<uint32_t>(token & UINT64_C(0xFFFFFFFF));
    generation = static_cast<uint32_t>(token >> 32U);
    if (slot_plus_one == 0 || generation == 0) {
        return false;
    }
    index = static_cast<size_t>(slot_plus_one - 1U);
    return true;
}

arc_handle_t encode_handle(size_t index, uint32_t generation) noexcept
{
    return (static_cast<uint64_t>(generation) << 32U) | static_cast<uint64_t>(index + 1U);
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

arc_status_t arc::abi::validate_record(const void* record, uint32_t required_size) noexcept
{
    if (record == nullptr || required_size < sizeof(uint32_t) * 2) {
        return fail(ARC_INVALID_ARGUMENT, "Record pointer or required prefix is invalid", 0);
    }

    uint32_t struct_size = 0;
    uint32_t struct_version = 0;
    std::memcpy(&struct_size, record, sizeof(struct_size));
    if (struct_size < required_size) {
        return fail(ARC_INVALID_ARGUMENT, "Record prefix is too small", 0);
    }
    std::memcpy(&struct_version, static_cast<const unsigned char*>(record) + sizeof(struct_size),
                sizeof(struct_version));
    if (struct_version != ARC_NATIVE_RECORD_VERSION_1) {
        return fail(ARC_VERSION_MISMATCH, "Record version is not supported", 0);
    }

    return ARC_OK;
}

arc_status_t arc::abi::check_cancelled(const arc_cancel_token_t* token) noexcept
{
    if (token == nullptr) {
        return ARC_OK;
    }
    const arc_status_t valid = validate_record(token, sizeof(arc_cancel_token_t));
    if (valid != ARC_OK) {
        return valid;
    }
    if (token->is_cancelled == nullptr) {
        return fail(ARC_INVALID_ARGUMENT, "Cancellation callback is required", 0);
    }
    try {
        const arc_bool_t cancelled = token->is_cancelled(token->user_data);
        if (cancelled > 1) {
            return fail(ARC_CORRUPT, "Cancellation callback returned an invalid value", 0);
        }
        return cancelled == 0 ? ARC_OK : ARC_CANCELLED;
    } catch (...) {
        return fail(ARC_INTERNAL, "Cancellation callback failed", 0);
    }
}

arc_status_t arc::abi::prepare_handle_output(arc_handle_t* output) noexcept
{
    return prepare_output(output);
}

arc_status_t arc::abi::prepare_buffer_output(arc_mut_buffer_t* output, uint64_t required) noexcept
{
    if (output == nullptr) {
        return fail(ARC_INVALID_ARGUMENT, "Buffer output is required", 0);
    }

    output->required = required;
    if (output->data == nullptr && output->capacity != 0) {
        return fail(ARC_INVALID_ARGUMENT, "Buffer output pointer is invalid", 0);
    }
    if (output->capacity < required) {
        return ARC_BUFFER_TOO_SMALL;
    }
    if (required != 0 && output->data == nullptr) {
        return fail(ARC_INVALID_ARGUMENT, "Buffer output pointer is invalid", 0);
    }
    return ARC_OK;
}

arc::abi::handle_lease::handle_lease(handle_table* owner, size_t index, uint32_t generation,
                                     std::shared_ptr<void> value,
                                     std::shared_ptr<handle_parent_retention> parent) noexcept
    : owner_(owner), index_(index), generation_(generation), value_(std::move(value)), parent_(std::move(parent))
{
}

arc::abi::handle_lease::~handle_lease() noexcept
{
    reset();
}

arc::abi::handle_lease::handle_lease(handle_lease&& other) noexcept
{
    *this = std::move(other);
}

arc::abi::handle_lease& arc::abi::handle_lease::operator=(handle_lease&& other) noexcept
{
    if (this != &other) {
        reset();
        owner_ = std::exchange(other.owner_, nullptr);
        index_ = std::exchange(other.index_, 0);
        generation_ = std::exchange(other.generation_, 0);
        value_ = std::move(other.value_);
        parent_ = std::move(other.parent_);
    }
    return *this;
}

void arc::abi::handle_lease::reset() noexcept
{
    if (owner_ == nullptr) {
        return;
    }

    handle_table* const owner = std::exchange(owner_, nullptr);
    const size_t index = std::exchange(index_, 0);
    const uint32_t generation = std::exchange(generation_, 0);
    value_.reset();
    parent_.reset();
    owner->release(index, generation);
}

arc::abi::handle_table::handle_table(uint32_t maximum_open) noexcept : maximum_open_(maximum_open)
{
}

arc_status_t arc::abi::handle_table::create(uint32_t kind, std::shared_ptr<void> value, arc_handle_t* output,
                                            arc_handle_t parent, uint32_t parent_kind)
{
    const arc_status_t prepared = prepare_handle_output(output);
    if (prepared != ARC_OK) {
        return prepared;
    }
    if (kind == 0 || !value || ((parent == 0) != (parent_kind == 0))) {
        return fail(ARC_INVALID_ARGUMENT, "Handle creation arguments are invalid", 0);
    }

    std::shared_ptr<handle_parent_retention> parent_retention;
    std::unique_lock lock(mutex_);
    if (open_count_ >= maximum_open_) {
        return fail(ARC_RESOURCE_LIMIT, "Native handle limit is reached", 0);
    }

    if (parent != 0) {
        size_t parent_index = 0;
        uint32_t parent_generation = 0;
        if (!decode_handle(parent, parent_index, parent_generation) || parent_index >= slots_.size()) {
            return fail(ARC_CLOSED, "Parent handle is closed", 0);
        }
        const slot& parent_slot = slots_[parent_index];
        if (parent_slot.generation != parent_generation || parent_slot.value == nullptr || parent_slot.closing) {
            return fail(ARC_CLOSED, "Parent handle is closed", 0);
        }
        if (parent_slot.kind != parent_kind) {
            return fail(ARC_INVALID_ARGUMENT, "Parent handle kind is invalid", 0);
        }
        try {
            parent_retention = std::make_shared<handle_parent_retention>(
                handle_parent_retention{parent_slot.value, parent_slot.parent});
        } catch (const std::bad_alloc&) {
            return fail(ARC_OUT_OF_MEMORY, "Native parent retention allocation failed", 0);
        } catch (...) {
            return fail(ARC_INTERNAL, "Native parent retention allocation failed", 0);
        }
    }

    size_t index = 0;
    while (index < slots_.size() &&
           (slots_[index].retired || slots_[index].value != nullptr || slots_[index].closing)) {
        ++index;
    }
    if (index == slots_.size()) {
        if (slots_.size() >= std::numeric_limits<uint32_t>::max()) {
            return fail(ARC_RESOURCE_LIMIT, "Native handle slot space is exhausted", 0);
        }
        try {
            slots_.emplace_back();
        } catch (const std::bad_alloc&) {
            return fail(ARC_OUT_OF_MEMORY, "Native handle table allocation failed", 0);
        } catch (...) {
            return fail(ARC_INTERNAL, "Native handle table allocation failed", 0);
        }
    }

    slot& target = slots_[index];
    target.kind = kind;
    target.active_calls = 0;
    target.closing = false;
    target.value = std::move(value);
    target.parent = std::move(parent_retention);
    ++open_count_;
    *output = encode_handle(index, target.generation);
    return ARC_OK;
}

arc_status_t arc::abi::handle_table::acquire(arc_handle_t token, uint32_t expected_kind, handle_lease* output)
{
    if (output == nullptr || expected_kind == 0) {
        return fail(ARC_INVALID_ARGUMENT, "Handle lease arguments are invalid", 0);
    }
    if (*output) {
        return fail(ARC_BUSY, "Handle lease output is already active", 0);
    }

    size_t index = 0;
    uint32_t generation = 0;
    if (!decode_handle(token, index, generation)) {
        return fail(ARC_CLOSED, "Native handle is closed", 0);
    }

    std::lock_guard lock(mutex_);
    if (index >= slots_.size()) {
        return fail(ARC_CLOSED, "Native handle is closed", 0);
    }
    slot& target = slots_[index];
    if (target.generation != generation || target.value == nullptr || target.closing || target.retired) {
        return fail(ARC_CLOSED, "Native handle is closed", 0);
    }
    if (target.kind != expected_kind) {
        return fail(ARC_INVALID_ARGUMENT, "Native handle kind is invalid", 0);
    }
    if (target.active_calls == std::numeric_limits<uint32_t>::max()) {
        return fail(ARC_RESOURCE_LIMIT, "Native handle borrow count is exhausted", 0);
    }

    ++target.active_calls;
    *output = handle_lease(this, index, generation, target.value, target.parent);
    return ARC_OK;
}

arc_status_t arc::abi::handle_table::close(arc_handle_t token, uint32_t expected_kind)
{
    if (expected_kind == 0) {
        return fail(ARC_INVALID_ARGUMENT, "Handle kind is invalid", 0);
    }

    size_t index = 0;
    uint32_t generation = 0;
    if (!decode_handle(token, index, generation)) {
        return fail(ARC_CLOSED, "Native handle is closed", 0);
    }

    std::shared_ptr<void> released_value;
    std::shared_ptr<handle_parent_retention> released_parent;
    std::unique_lock lock(mutex_);
    if (index >= slots_.size()) {
        return fail(ARC_CLOSED, "Native handle is closed", 0);
    }
    slot& target = slots_[index];
    if (target.generation != generation || target.value == nullptr || target.closing || target.retired) {
        return fail(ARC_CLOSED, "Native handle is closed", 0);
    }
    if (target.kind != expected_kind) {
        return fail(ARC_INVALID_ARGUMENT, "Native handle kind is invalid", 0);
    }

    target.closing = true;
    try {
        condition_.wait(lock, [this, index] { return slots_[index].active_calls == 0; });
    } catch (...) {
        slots_[index].closing = false;
        return fail(ARC_INTERNAL, "Native handle close wait failed", 0);
    }

    slot& closed = slots_[index];
    released_value = std::move(closed.value);
    released_parent = std::move(closed.parent);
    closed.kind = 0;
    closed.active_calls = 0;
    closed.closing = false;
    if (closed.generation == std::numeric_limits<uint32_t>::max()) {
        closed.retired = true;
    } else {
        ++closed.generation;
    }
    --open_count_;
    lock.unlock();
    return ARC_OK;
}

void arc::abi::handle_table::release(size_t index, uint32_t generation) noexcept
{
    try {
        std::lock_guard lock(mutex_);
        if (index >= slots_.size()) {
            return;
        }
        slot& target = slots_[index];
        if (target.generation != generation || target.active_calls == 0) {
            return;
        }
        --target.active_calls;
        if (target.closing && target.active_calls == 0) {
            condition_.notify_all();
        }
    } catch (...) {
        // Destruction cannot throw across the native ABI; the owner remains fail-closed.
    }
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
    // Preserve exact sizing and error semantics without allocating across the C ABI.
    constexpr std::string_view identity(arc_build_identity);
    if (out_utf8 == nullptr) {
        return fail(ARC_INVALID_ARGUMENT, "Build-info output buffer is invalid", 0);
    }
    out_utf8->required = static_cast<uint64_t>(value.size() + identity.size());
    if (out_utf8->data == nullptr && out_utf8->capacity != 0) {
        return fail(ARC_INVALID_ARGUMENT, "Build-info output buffer is invalid", 0);
    }
    if (out_utf8->capacity < out_utf8->required) {
        return ARC_BUFFER_TOO_SMALL;
    }
    if (out_utf8->data == nullptr) {
        return fail(ARC_INVALID_ARGUMENT, "Build-info output buffer is invalid", 0);
    }
    auto* const data = static_cast<char*>(out_utf8->data);
    std::memcpy(data, value.data(), value.size());
    std::memcpy(data + value.size(), identity.data(), identity.size());
    return ARC_OK;
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
