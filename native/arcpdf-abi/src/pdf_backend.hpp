// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_PDF_BACKEND_HPP
#define ARC_PDF_BACKEND_HPP

#include <arc/arc_native_abi.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// The seam between the owned arc_pdf_* engine (limits, validation, handles, cancellation, output encoding) and
// whatever parses PDF bytes. The engine never trusts a backend: every value a backend returns is validated before
// it reaches a caller, and a backend that throws, hangs past its deadline or returns nonsense fails the call closed.
// The only production backend is the PDFium binding; until it is linked the library reports ARC_UNSUPPORTED.
namespace arc::pdf {

constexpr uint32_t pdf_domain = 0x50444655U;

// Hard producer profile. Caller limits can lower these, never raise them.
constexpr uint64_t profile_max_input_bytes = UINT64_C(256) * 1024 * 1024;
constexpr uint64_t profile_max_memory_bytes = UINT64_C(1) * 1024 * 1024 * 1024;
constexpr uint64_t profile_max_output_bytes = UINT64_C(3) * 64 * 1024 * 1024;
constexpr uint32_t profile_max_dimension = 65535;
constexpr uint32_t profile_max_items = 1024;
constexpr uint32_t profile_max_timeout_ms = 30000;
constexpr uint64_t profile_max_pixels = UINT64_C(268435456);
constexpr uint64_t profile_max_tile_bytes = UINT64_C(64) * 1024 * 1024;
constexpr uint32_t max_text_units_per_call = 65536;
constexpr uint32_t max_password_bytes = 1024;
constexpr uint32_t max_pages = UINT32_C(1) << 24;
constexpr uint32_t max_page_text_units = UINT32_C(16) * 1024 * 1024;
constexpr double max_page_points = 1000000.0;

struct page_geometry final {
    uint32_t rotation = 0;
    double width_points = 0;
    double height_points = 0;
};

// Offsets are UTF-16 code-unit offsets into the full page text.
struct text_box final {
    uint32_t start = 0;
    uint32_t length = 0;
    double x = 0;
    double y = 0;
    double width = 0;
    double height = 0;
};

struct page_text final {
    std::u16string text;
    std::vector<text_box> boxes;
};

struct region final {
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
};

// What every backend call runs under: the validated limits, the caller's cancellation and the call deadline.
class call_context final {
  public:
    call_context(const arc_limits_v1& limits, const arc_cancel_token_t* cancel) noexcept;
    [[nodiscard]] const arc_limits_v1& limits() const noexcept
    {
        return limits_;
    }
    // ARC_OK, ARC_CANCELLED, ARC_RESOURCE_LIMIT (deadline) or ARC_INVALID_ARGUMENT/ARC_CORRUPT for a bad token.
    [[nodiscard]] arc_status_t check() const noexcept;

  private:
    arc_limits_v1 limits_;
    const arc_cancel_token_t* cancel_;
    std::chrono::steady_clock::time_point deadline_;
};

// The immutable input, as read through the caller's arc_io_v1 callbacks. Reads never run past the length.
class byte_source {
  public:
    virtual ~byte_source() = default;
    [[nodiscard]] virtual uint64_t length() const noexcept = 0;
    // Short reads happen only at the end of the input; done is always <= requested.
    virtual arc_status_t read_at(uint64_t offset, void* destination, uint64_t requested, uint64_t* done) noexcept = 0;
};

class document {
  public:
    virtual ~document() = default;
    virtual arc_status_t geometry(uint32_t index, const call_context& context, page_geometry& out) = 0;
    virtual arc_status_t text(uint32_t index, const call_context& context, page_text& out) = 0;
    // Writes tile rows into out at the given row stride. The region lies inside the full pixel grid of the page.
    virtual arc_status_t render(uint32_t index, uint32_t full_width, uint32_t full_height, const region& tile,
                                uint64_t row_stride, uint8_t* out, uint64_t out_size, const call_context& context) = 0;
};

class backend {
  public:
    virtual ~backend() = default;
    // Opens the document with scripts and actions disabled. A password is only passed when the caller gave one.
    // ARC_PERMISSION_DENIED: a password is required or wrong. ARC_CORRUPT: not a usable PDF.
    virtual arc_status_t open(std::shared_ptr<byte_source> source, std::string_view password,
                              const call_context& context, std::unique_ptr<document>& out, uint32_t& pages) = 0;
};

// The backend this build links, or null. backend_none.cpp returns null; the PDFium binding provides the real one.
std::shared_ptr<backend> linked_backend();

} // namespace arc::pdf

#endif
