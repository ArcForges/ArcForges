// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_IMAGE_CALLBACK_IO_HPP
#define ARC_IMAGE_CALLBACK_IO_HPP

#include <arc/arc_native_abi.h>

#include <OpenImageIO/filesystem.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace arc::image {

// Presents an arc_io_v1 record (caller-brokered, bounded bytes) to OpenImageIO as a read-only
// IOProxy. The adapter never opens or resolves a path: every byte comes from io.read_at.
// Callback failures are latched and mapped back to an ARC status after the codec returns,
// because OpenImageIO only sees a short read. Cancellation and the per-call deadline are checked
// before every callback, so they are observed at callback boundaries (decision D9).
class callback_io final : public OIIO::Filesystem::IOProxy {
  public:
    // The record is copied. Its context must stay valid until the owning image handle closes.
    callback_io(std::string hint, const arc_io_v1& io);
    ~callback_io() override = default;
    callback_io(const callback_io&) = delete;
    callback_io& operator=(const callback_io&) = delete;
    callback_io(callback_io&&) = delete;
    callback_io& operator=(callback_io&&) = delete;

    const char* proxytype() const override;
    size_t read(void* buf, size_t size) override;
    size_t pread(void* buf, size_t size, int64_t offset) override;
    bool seek(int64_t offset) override;
    size_t size() const override;

    // Starts one ABI call: binds its cancellation token and optional deadline and clears the
    // latched failure. Call it with a null token and has_deadline false when the call returns.
    void begin_call(const arc_cancel_token_t* cancel, std::chrono::steady_clock::time_point deadline,
                    bool has_deadline) noexcept;

    // First latched failure during the current call, or ARC_OK.
    [[nodiscard]] arc_status_t latched_status() const noexcept;

    [[nodiscard]] uint64_t length() const noexcept
    {
        return length_;
    }

  private:
    void latch(arc_status_t status) noexcept;
    arc_status_t check_call_state() noexcept;

    arc_read_at_fn read_at_ = nullptr;
    void* context_ = nullptr;
    uint64_t length_ = 0;
    const arc_cancel_token_t* cancel_ = nullptr;
    std::chrono::steady_clock::time_point deadline_{};
    bool has_deadline_ = false;
    arc_status_t latched_ = ARC_OK;
    mutable std::mutex mutex_;
};

} // namespace arc::image

#endif
