// SPDX-License-Identifier: AGPL-3.0-only
#include "image_callback_io.hpp"

#include "arc_native_abi_internal.hpp"

#include <algorithm>

namespace arc::image {
namespace {

// Callback reads are bounded so that cancellation and deadlines are observed at least once per MiB.
constexpr uint64_t max_callback_chunk = UINT64_C(1) << 20;
static_assert(sizeof(size_t) == sizeof(uint64_t), "ArcImageNative is a 64-bit only profile");

} // namespace

callback_io::callback_io(std::string hint, const arc_io_v1& io)
    : OIIO::Filesystem::IOProxy(hint, OIIO::Filesystem::IOProxy::Read),
      read_at_(io.read_at),
      context_(io.context),
      length_(io.length)
{
}

const char* callback_io::proxytype() const
{
    return "arc-io-v1";
}

size_t callback_io::read(void* buf, size_t size)
{
    const int64_t position = m_pos;
    const size_t count = pread(buf, size, position);
    m_pos = position + static_cast<int64_t>(count);
    return count;
}

size_t callback_io::pread(void* buf, size_t size, int64_t offset)
{
    std::lock_guard lock(mutex_);
    if (offset < 0 || (buf == nullptr && size != 0)) {
        latch(ARC_INVALID_ARGUMENT);
        return 0;
    }
    if (size == 0) {
        return 0;
    }
    if (check_call_state() != ARC_OK) {
        return 0;
    }

    const auto start = static_cast<uint64_t>(offset);
    if (start >= length_) {
        return 0;
    }

    const uint64_t wanted = std::min<uint64_t>(static_cast<uint64_t>(size), length_ - start);
    auto* const out = static_cast<unsigned char*>(buf);
    uint64_t total = 0;
    while (total < wanted) {
        if (total != 0 && check_call_state() != ARC_OK) {
            return static_cast<size_t>(total);
        }
        const uint64_t chunk = std::min<uint64_t>(wanted - total, max_callback_chunk);
        uint64_t done = 0;
        const arc_status_t status = read_at_(context_, start + total, out + total, chunk, &done);
        if (status != ARC_OK) {
            latch(status);
            return static_cast<size_t>(total);
        }
        if (done > chunk) {
            latch(ARC_CORRUPT);
            return static_cast<size_t>(total);
        }
        total += done;
        if (done < chunk) {
            // A short read is only valid at the end of the source; anywhere else it is an I/O failure.
            if (start + total != length_) {
                latch(ARC_IO);
            }
            break;
        }
    }
    return static_cast<size_t>(total);
}

bool callback_io::seek(int64_t offset)
{
    if (offset < 0) {
        return false;
    }
    m_pos = offset;
    return true;
}

size_t callback_io::size() const
{
    return static_cast<size_t>(length_);
}

void callback_io::begin_call(const arc_cancel_token_t* cancel, std::chrono::steady_clock::time_point deadline,
                             bool has_deadline) noexcept
{
    std::lock_guard lock(mutex_);
    cancel_ = cancel;
    deadline_ = deadline;
    has_deadline_ = has_deadline;
    latched_ = ARC_OK;
}

arc_status_t callback_io::latched_status() const noexcept
{
    std::lock_guard lock(mutex_);
    return latched_;
}

void callback_io::latch(arc_status_t status) noexcept
{
    if (latched_ == ARC_OK) {
        latched_ = status;
    }
}

arc_status_t callback_io::check_call_state() noexcept
{
    if (latched_ != ARC_OK) {
        return latched_;
    }
    const arc_status_t cancelled = arc::abi::check_cancelled(cancel_);
    if (cancelled != ARC_OK) {
        latch(cancelled);
        return cancelled;
    }
    if (has_deadline_ && std::chrono::steady_clock::now() > deadline_) {
        latch(ARC_RESOURCE_LIMIT);
        return ARC_RESOURCE_LIMIT;
    }
    return ARC_OK;
}

} // namespace arc::image
