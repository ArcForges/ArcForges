// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_IMAGE_COVERAGE_HPP
#define ARC_IMAGE_COVERAGE_HPP

#include <arc/arc_native_abi.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace arc::image {

// Enforces decision D3 for one image handle. Regions must cover every pixel exactly once in
// raster order: a region is accepted only when its top-left pixel is the first pixel in raster
// order that is not yet covered, and when it overlaps no covered pixel. A refused check leaves
// the tracker unchanged. Storage is one sorted span list per pending row, bounded by
// max_intervals; rows that are fully covered are dropped as the cursor advances.
class coverage_tracker final {
  public:
    coverage_tracker(uint32_t width, uint32_t height, uint64_t max_intervals) noexcept
        : width_(width), height_(height), max_intervals_(max_intervals)
    {
    }

    // ARC_OK when the region may be committed. ARC_INVALID_ARGUMENT for an out-of-bounds,
    // overlapping or out-of-raster-order region. ARC_RESOURCE_LIMIT when the bounded storage
    // would be exceeded. Never changes state.
    [[nodiscard]] arc_status_t check(uint32_t x, uint32_t y, uint32_t w, uint32_t h) const
    {
        if (w == 0 || h == 0 || x > width_ || w > width_ - x || y > height_ || h > height_ - y) {
            return ARC_INVALID_ARGUMENT;
        }
        if (first_row_ >= height_ || y != first_row_ || x != cursor_column()) {
            return ARC_INVALID_ARGUMENT;
        }
        const uint64_t x_end = static_cast<uint64_t>(x) + w;
        const size_t rows_to_check = std::min<size_t>(rows_.size(), h);
        for (size_t row = 0; row < rows_to_check; ++row) {
            for (const span& covered : rows_[row]) {
                if (covered.begin < x_end && x < covered.end) {
                    return ARC_INVALID_ARGUMENT;
                }
            }
        }
        if (interval_count_ + h > max_intervals_) {
            return ARC_RESOURCE_LIMIT;
        }
        return ARC_OK;
    }

    // Commits a region that check() accepted for the same arguments.
    void commit(uint32_t x, uint32_t y, uint32_t w, uint32_t h)
    {
        (void)y;
        if (rows_.size() < h) {
            rows_.resize(h);
        }
        const uint64_t x_end = static_cast<uint64_t>(x) + w;
        for (uint32_t row = 0; row < h; ++row) {
            insert_span(rows_[row], x, static_cast<uint32_t>(x_end));
        }
        while (!rows_.empty() && is_full(rows_.front())) {
            interval_count_ -= rows_.front().size();
            rows_.erase(rows_.begin());
            ++first_row_;
        }
    }

    [[nodiscard]] bool complete() const noexcept
    {
        return first_row_ >= height_;
    }

  private:
    struct span final {
        uint32_t begin;
        uint32_t end;
    };

    // The covered prefix of the first pending row, which is where the next region must start.
    [[nodiscard]] uint32_t cursor_column() const noexcept
    {
        if (rows_.empty() || rows_.front().empty() || rows_.front().front().begin != 0) {
            return 0;
        }
        return rows_.front().front().end;
    }

    [[nodiscard]] bool is_full(const std::vector<span>& row) const noexcept
    {
        return row.size() == 1 && row.front().begin == 0 && row.front().end == width_;
    }

    void insert_span(std::vector<span>& row, uint32_t begin, uint32_t end)
    {
        const size_t before = row.size();
        auto first = std::lower_bound(row.begin(), row.end(), begin,
                                      [](const span& existing, uint32_t value) { return existing.end < value; });
        auto last = first;
        uint32_t merged_begin = begin;
        uint32_t merged_end = end;
        while (last != row.end() && last->begin <= merged_end) {
            merged_begin = std::min(merged_begin, last->begin);
            merged_end = std::max(merged_end, last->end);
            ++last;
        }
        const auto position = row.erase(first, last);
        row.insert(position, span{merged_begin, merged_end});
        if (row.size() >= before) {
            interval_count_ += row.size() - before;
        } else {
            interval_count_ -= before - row.size();
        }
    }

    uint32_t width_;
    uint32_t height_;
    uint64_t max_intervals_;
    uint32_t first_row_ = 0;
    uint64_t interval_count_ = 0;
    std::vector<std::vector<span>> rows_;
};

} // namespace arc::image

#endif
