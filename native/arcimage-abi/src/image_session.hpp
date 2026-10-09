// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_IMAGE_SESSION_HPP
#define ARC_IMAGE_SESSION_HPP

#include <arc/arc_native_abi.h>

#include "image_callback_io.hpp"
#include "image_coverage.hpp"

#include <OpenImageIO/imageio.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace arc::image {

// Error domain reported through arc_image_get_last_error (unchanged from the probe shim).
inline constexpr uint32_t image_error_domain = 0x494D4147U;
// Non-zero kind tag stored in the handle table for image sessions.
inline constexpr uint32_t image_handle_kind = 0x494D4731U;
// Annex 06 section 2 default: open image handles per library context.
inline constexpr uint32_t max_open_images = 64;

// Hard producer profile. Caller limits may narrow these bounds but never widen them.
inline constexpr uint32_t hard_max_dimension = 65535;
inline constexpr uint64_t hard_max_pixels = UINT64_C(268435456);
inline constexpr uint64_t hard_max_region_bytes = UINT64_C(67108864);
inline constexpr uint64_t hard_max_input_bytes = UINT64_C(4294967296);
inline constexpr uint64_t hard_max_memory_bytes = UINT64_C(4294967296);
inline constexpr uint32_t hard_max_items = 256;
inline constexpr uint32_t max_channels = 64;
inline constexpr uint32_t max_channel_name_bytes = 64;
inline constexpr uint64_t max_coverage_intervals = UINT64_C(1048576);

// One open still image. Owns the callback proxy and the OpenImageIO reader. The reader is declared
// after the proxy so that it is destroyed first. A session serialises its own reads; the ABI handle
// table adds the lease and close semantics on top.
class image_session final {
  public:
    ~image_session();
    image_session(const image_session&) = delete;
    image_session& operator=(const image_session&) = delete;

    // Probes the content (PNG, TIFF or EXR only), validates every bound against the limits before
    // any pixel allocation, and builds the metadata document. On failure output stays empty.
    static arc_status_t open(const arc_io_v1& io, const arc_image_options_v1& options,
                             const arc_cancel_token_t* cancel, std::unique_ptr<image_session>& output);

    // Closed JSON metadata document produced by open().
    [[nodiscard]] const std::string& metadata() const noexcept
    {
        return metadata_;
    }

    // Decodes one packed region into pixels. Coverage (decision D3) and conversion (decision D4)
    // apply. The output is staged, so pixels is written only after the whole region decodes.
    arc_status_t read(const arc_region_v1& region, arc_mut_buffer_t* pixels, const arc_cancel_token_t* cancel);

  private:
    image_session();

    struct call_scope;
    arc_status_t poll() const;
    arc_status_t decode_failure(const char* message) const;
    arc_status_t decode_tiles(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t* out);
    arc_status_t decode_scanlines(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t* out);
    arc_status_t ensure_rows(uint32_t first_row, uint32_t end_row);
    void convert_segment(const float* source, uint32_t count, uint8_t* out);
    void convert_pixel(const float* source, float* destination) const;

    // Declaration order matters: the reader holds a pointer to the proxy, so it is declared after it.
    std::unique_ptr<callback_io> proxy_;
    std::unique_ptr<OIIO::ImageInput> input_;

    arc_limits_v1 limits_{};
    uint32_t format_ = 0;
    int32_t origin_x_ = 0;
    int32_t origin_y_ = 0;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    uint32_t channels_ = 0;
    uint32_t tile_width_ = 0;  // zero for scanline images
    uint32_t tile_height_ = 0;
    uint32_t output_channels_ = 0;
    uint32_t bytes_per_pixel_ = 0;

    // Channel plan (decision D4), fixed at open.
    int32_t red_ = -1;
    int32_t green_ = -1;
    int32_t blue_ = -1;
    int32_t alpha_ = -1;
    bool grey_ = false;
    bool identity_ = false;
    bool srgb_to_linear_ = false;
    bool unpremultiply_output_ = false;

    std::vector<float> tile_buffer_;  // one decoded tile (tiled sources)
    std::vector<float> band_;         // decoded full-width rows [band_begin_, band_end_)
    uint32_t band_begin_ = 0;
    uint32_t band_end_ = 0;
    std::vector<float> scratch_;
    std::string metadata_;
    coverage_tracker coverage_{1, 1, max_coverage_intervals};

    std::mutex mutex_;
    const arc_cancel_token_t* cancel_ = nullptr;
    std::chrono::steady_clock::time_point deadline_{};
    bool has_deadline_ = false;
};

} // namespace arc::image

#endif
