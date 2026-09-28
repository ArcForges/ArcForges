// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_NATIVE_ABI_INTERNAL_HPP
#define ARC_NATIVE_ABI_INTERNAL_HPP

#include <arc/arc_native_abi.h>

#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace arc::abi {

arc_status_t get_abi_version(uint32_t* out_major, uint32_t* out_minor) noexcept;
arc_status_t write_build_info(std::string_view value, arc_mut_buffer_t* out_utf8) noexcept;
arc_status_t get_last_error(arc_error_info_t* out_error) noexcept;
arc_status_t fail(arc_status_t status, std::string_view message, uint32_t domain) noexcept;
arc_status_t validate_record(const void* record, uint32_t required_size) noexcept;
arc_status_t check_cancelled(const arc_cancel_token_t* token) noexcept;
arc_status_t prepare_handle_output(arc_handle_t* output) noexcept;
arc_status_t prepare_buffer_output(arc_mut_buffer_t* output, uint64_t required) noexcept;

class handle_table;

struct handle_parent_retention final {
    std::shared_ptr<void> value;
    std::shared_ptr<handle_parent_retention> parent;
};

class handle_lease final {
public:
    handle_lease() noexcept = default;
    ~handle_lease() noexcept;
    handle_lease(const handle_lease&) = delete;
    handle_lease& operator=(const handle_lease&) = delete;
    handle_lease(handle_lease&& other) noexcept;
    handle_lease& operator=(handle_lease&& other) noexcept;

    [[nodiscard]] void* get() const noexcept { return value_.get(); }

    template <typename T>
    [[nodiscard]] T* as() const noexcept
    {
        return static_cast<T*>(value_.get());
    }

    [[nodiscard]] explicit operator bool() const noexcept { return owner_ != nullptr; }

private:
    friend class handle_table;
    handle_lease(handle_table* owner, size_t index, uint32_t generation,
                 std::shared_ptr<void> value, std::shared_ptr<handle_parent_retention> parent) noexcept;
    void reset() noexcept;

    handle_table* owner_ = nullptr;
    size_t index_ = 0;
    uint32_t generation_ = 0;
    std::shared_ptr<void> value_;
    std::shared_ptr<handle_parent_retention> parent_;
};

// One table instance belongs to one native library/process. Leases count borrowed calls;
// close blocks new leases, drains active leases, invalidates the generation, and only then
// releases the value. A child retains its parent chain after parent handles close.
class handle_table final {
public:
    explicit handle_table(uint32_t maximum_open = 64) noexcept;
    handle_table(const handle_table&) = delete;
    handle_table& operator=(const handle_table&) = delete;

    arc_status_t create(uint32_t kind, std::shared_ptr<void> value, arc_handle_t* output,
                        arc_handle_t parent = 0, uint32_t parent_kind = 0);
    arc_status_t acquire(arc_handle_t token, uint32_t expected_kind, handle_lease* output);
    arc_status_t close(arc_handle_t token, uint32_t expected_kind);

private:
    friend class handle_lease;

    struct slot final {
        uint32_t generation = 1;
        uint32_t kind = 0;
        uint32_t active_calls = 0;
        bool closing = false;
        bool retired = false;
        std::shared_ptr<void> value;
        std::shared_ptr<handle_parent_retention> parent;
    };

    void release(size_t index, uint32_t generation) noexcept;

    const uint32_t maximum_open_;
    uint32_t open_count_ = 0;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<slot> slots_;
};

template <typename T>
void zero_output(T* output) noexcept
{
    static_assert(std::is_trivially_copyable_v<T>, "C ABI output must be trivially copyable");
    if (output != nullptr) {
        std::memset(output, 0, sizeof(T));
    }
}

template <typename T>
arc_status_t prepare_output(T* output) noexcept
{
    if (output == nullptr) {
        return fail(ARC_INVALID_ARGUMENT, "Output pointer is required", 0);
    }
    zero_output(output);
    return ARC_OK;
}

} // namespace arc::abi

#endif
