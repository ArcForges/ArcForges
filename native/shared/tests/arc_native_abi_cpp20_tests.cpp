// SPDX-License-Identifier: AGPL-3.0-only
#include "arc_native_abi_internal.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>

namespace {

int failures = 0;

void expect(bool condition, const char* expression, int line)
{
    if (!condition) {
        std::fprintf(stderr, "line %d: %s\n", line, expression);
        ++failures;
    }
}

#define EXPECT(condition) expect((condition), #condition, __LINE__)

void test_retained_probe_minor_remains_zero()
{
    uint32_t major = UINT32_C(77);
    uint32_t minor = UINT32_C(88);
    EXPECT(arc::abi::get_abi_version(&major, &minor) == ARC_OK);
    EXPECT(major == ARC_NATIVE_ABI_MAJOR);
    EXPECT(minor == ARC_NATIVE_ABI_MINOR);
    EXPECT(minor == UINT32_C(0));
}

struct record_prefix final {
    uint32_t struct_size;
    uint32_t struct_version;
};

struct extended_record final {
    uint32_t struct_size;
    uint32_t struct_version;
    uint64_t tail;
};

arc_bool_t ARC_ABI_CALL read_cancellation(void* state)
{
    return *static_cast<const arc_bool_t*>(state);
}

arc_bool_t ARC_ABI_CALL invalid_cancellation(void*)
{
    return 2;
}

arc_bool_t ARC_ABI_CALL throwing_cancellation(void*)
{
    throw 1;
}

void test_record_and_cancellation_validation()
{
    EXPECT(arc::abi::validate_record(nullptr, sizeof(record_prefix)) == ARC_INVALID_ARGUMENT);
    EXPECT(arc::abi::validate_record(nullptr, 0) == ARC_INVALID_ARGUMENT);

    record_prefix record{static_cast<uint32_t>(sizeof(record_prefix)), ARC_NATIVE_RECORD_VERSION_1};
    EXPECT(arc::abi::validate_record(&record, sizeof(record_prefix)) == ARC_OK);
    record.struct_size = static_cast<uint32_t>(sizeof(record_prefix) - 1);
    EXPECT(arc::abi::validate_record(&record, sizeof(record_prefix)) == ARC_INVALID_ARGUMENT);
    record.struct_size = static_cast<uint32_t>(sizeof(record_prefix));
    record.struct_version = ARC_NATIVE_RECORD_VERSION_1 + 1;
    EXPECT(arc::abi::validate_record(&record, sizeof(record_prefix)) == ARC_VERSION_MISMATCH);

    extended_record extended{static_cast<uint32_t>(sizeof(extended_record)), ARC_NATIVE_RECORD_VERSION_1, 42};
    EXPECT(arc::abi::validate_record(&extended, sizeof(record_prefix)) == ARC_OK);

    EXPECT(arc::abi::check_cancelled(nullptr) == ARC_OK);
    arc_cancel_token_t token{};
    token.struct_size = static_cast<uint32_t>(sizeof(token));
    token.struct_version = ARC_NATIVE_RECORD_VERSION_1;
    EXPECT(arc::abi::check_cancelled(&token) == ARC_INVALID_ARGUMENT);
    token.is_cancelled = &read_cancellation;
    token.struct_size = static_cast<uint32_t>(sizeof(token) - 1);
    EXPECT(arc::abi::check_cancelled(&token) == ARC_INVALID_ARGUMENT);
    token.struct_size = static_cast<uint32_t>(sizeof(token));
    token.struct_version = ARC_NATIVE_RECORD_VERSION_1 + 1;
    EXPECT(arc::abi::check_cancelled(&token) == ARC_VERSION_MISMATCH);
    token.struct_version = ARC_NATIVE_RECORD_VERSION_1;
    token.is_cancelled = &invalid_cancellation;
    EXPECT(arc::abi::check_cancelled(&token) == ARC_CORRUPT);
    token.is_cancelled = &throwing_cancellation;
    EXPECT(arc::abi::check_cancelled(&token) == ARC_INTERNAL);
    arc_bool_t cancelled = 1;
    token.is_cancelled = &read_cancellation;
    token.user_data = &cancelled;
    EXPECT(arc::abi::check_cancelled(&token) == ARC_CANCELLED);
    arc_bool_t not_cancelled = 0;
    token.user_data = &not_cancelled;
    EXPECT(arc::abi::check_cancelled(&token) == ARC_OK);
}

void test_zero_outputs_and_bounded_buffers()
{
    arc_handle_t handle = UINT64_C(99);
    EXPECT(arc::abi::prepare_handle_output(&handle) == ARC_OK);
    EXPECT(handle == 0);
    EXPECT(arc::abi::prepare_handle_output(nullptr) == ARC_INVALID_ARGUMENT);

    struct output_record final {
        uint64_t first;
        uint32_t second;
        uint32_t third;
    } output{1, 2, 3};
    EXPECT(arc::abi::prepare_output(&output) == ARC_OK);
    const std::array<unsigned char, sizeof(output)> zero{};
    EXPECT(std::memcmp(&output, zero.data(), sizeof(output)) == 0);
    EXPECT(arc::abi::prepare_output<output_record>(nullptr) == ARC_INVALID_ARGUMENT);

    char bytes[4] = {'A', 'B', 'C', 'D'};
    arc_mut_buffer_t buffer{bytes, 3, 999};
    EXPECT(arc::abi::prepare_buffer_output(&buffer, 4) == ARC_BUFFER_TOO_SMALL);
    EXPECT(buffer.required == 4);
    EXPECT(bytes[0] == 'A' && bytes[1] == 'B' && bytes[2] == 'C' && bytes[3] == 'D');

    buffer = arc_mut_buffer_t{nullptr, 8, 999};
    EXPECT(arc::abi::prepare_buffer_output(&buffer, 4) == ARC_INVALID_ARGUMENT);
    EXPECT(buffer.required == 4);

    buffer = arc_mut_buffer_t{bytes, sizeof(bytes), 999};
    EXPECT(arc::abi::prepare_buffer_output(&buffer, 4) == ARC_OK);
    EXPECT(buffer.required == 4);
    EXPECT(bytes[0] == 'A' && bytes[1] == 'B' && bytes[2] == 'C' && bytes[3] == 'D');
}

void test_handle_kind_staleness_and_zero_on_failure()
{
    arc::abi::handle_table table;
    arc_handle_t handle = UINT64_C(99);
    EXPECT(table.create(7, std::make_shared<int>(42), &handle) == ARC_OK);
    EXPECT(handle != 0);

    arc::abi::handle_lease lease;
    EXPECT(table.acquire(handle, 8, &lease) == ARC_INVALID_ARGUMENT);
    EXPECT(!lease);
    EXPECT(table.close(handle, 8) == ARC_INVALID_ARGUMENT);
    EXPECT(table.acquire(handle, 7, &lease) == ARC_OK);
    EXPECT(static_cast<bool>(lease));
    lease = arc::abi::handle_lease{};
    EXPECT(table.close(handle, 7) == ARC_OK);
    EXPECT(table.close(handle, 7) == ARC_CLOSED);
    EXPECT(table.acquire(handle, 7, &lease) == ARC_CLOSED);

    arc_handle_t replacement = 0;
    EXPECT(table.create(7, std::make_shared<int>(43), &replacement) == ARC_OK);
    EXPECT(replacement != handle);
    EXPECT(table.acquire(handle, 7, &lease) == ARC_CLOSED);
    EXPECT(table.close(handle, 7) == ARC_CLOSED);
    EXPECT(table.acquire(replacement, 7, &lease) == ARC_OK);
    lease = arc::abi::handle_lease{};
    EXPECT(table.close(replacement, 7) == ARC_OK);

    arc_handle_t invalid = UINT64_C(99);
    EXPECT(table.create(7, {}, &invalid) == ARC_INVALID_ARGUMENT);
    EXPECT(invalid == 0);
    invalid = UINT64_C(99);
    EXPECT(table.create(0, std::make_shared<int>(1), &invalid) == ARC_INVALID_ARGUMENT);
    EXPECT(invalid == 0);
    EXPECT(table.create(7, std::make_shared<int>(1), nullptr) == ARC_INVALID_ARGUMENT);

    arc::abi::handle_table full(0);
    invalid = UINT64_C(99);
    EXPECT(full.create(7, std::make_shared<int>(1), &invalid) == ARC_RESOURCE_LIMIT);
    EXPECT(invalid == 0);
}

struct tracked_value final {
    explicit tracked_value(std::atomic<int>& destructions) : destructions_(&destructions) {}
    ~tracked_value() { destructions_->fetch_add(1, std::memory_order_relaxed); }

    std::atomic<int>* destructions_;
};

void test_child_retains_parent_chain()
{
    arc::abi::handle_table table(8);
    std::atomic<int> parent_destructions{0};
    std::atomic<int> child_destructions{0};
    std::atomic<int> grandchild_destructions{0};
    std::weak_ptr<tracked_value> parent_weak;
    std::weak_ptr<tracked_value> child_weak;
    std::weak_ptr<tracked_value> grandchild_weak;

    arc_handle_t parent = 0;
    auto parent_value = std::make_shared<tracked_value>(parent_destructions);
    parent_weak = parent_value;
    EXPECT(table.create(1, parent_value, &parent) == ARC_OK);
    parent_value.reset();

    arc_handle_t child = 0;
    auto child_value = std::make_shared<tracked_value>(child_destructions);
    child_weak = child_value;
    EXPECT(table.create(2, child_value, &child, parent, 1) == ARC_OK);
    child_value.reset();

    arc_handle_t grandchild = 0;
    auto grandchild_value = std::make_shared<tracked_value>(grandchild_destructions);
    grandchild_weak = grandchild_value;
    EXPECT(table.create(3, grandchild_value, &grandchild, child, 2) == ARC_OK);
    grandchild_value.reset();

    EXPECT(table.close(parent, 1) == ARC_OK);
    EXPECT(!parent_weak.expired());
    EXPECT(table.close(child, 2) == ARC_OK);
    EXPECT(!parent_weak.expired());
    EXPECT(!child_weak.expired());
    EXPECT(table.close(grandchild, 3) == ARC_OK);
    EXPECT(parent_weak.expired());
    EXPECT(child_weak.expired());
    EXPECT(grandchild_weak.expired());
    EXPECT(parent_destructions.load(std::memory_order_relaxed) == 1);
    EXPECT(child_destructions.load(std::memory_order_relaxed) == 1);
    EXPECT(grandchild_destructions.load(std::memory_order_relaxed) == 1);
}

void test_close_waits_for_borrowed_calls()
{
    arc::abi::handle_table table;
    arc_handle_t handle = 0;
    EXPECT(table.create(1, std::make_shared<int>(7), &handle) == ARC_OK);
    arc::abi::handle_lease active_lease;
    EXPECT(table.acquire(handle, 1, &active_lease) == ARC_OK);

    std::atomic<bool> finished{false};
    std::atomic<arc_status_t> close_status{ARC_INTERNAL};
    std::thread closer([&] {
        close_status.store(table.close(handle, 1), std::memory_order_release);
        finished.store(true, std::memory_order_release);
    });

    bool close_started = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        arc::abi::handle_lease probe;
        const arc_status_t acquired = table.acquire(handle, 1, &probe);
        if (acquired == ARC_CLOSED) {
            close_started = true;
            break;
        }
        if (probe) {
            probe = arc::abi::handle_lease{};
        }
        std::this_thread::yield();
    }

    EXPECT(close_started);
    EXPECT(!finished.load(std::memory_order_acquire));
    active_lease = arc::abi::handle_lease{};
    closer.join();
    EXPECT(finished.load(std::memory_order_acquire));
    EXPECT(close_status.load(std::memory_order_acquire) == ARC_OK);
}

} // namespace

int main()
{
    test_retained_probe_minor_remains_zero();
    test_record_and_cancellation_validation();
    test_zero_outputs_and_bounded_buffers();
    test_handle_kind_staleness_and_zero_on_failure();
    test_child_retains_parent_chain();
    test_close_waits_for_borrowed_calls();
    return failures == 0 ? 0 : 1;
}
