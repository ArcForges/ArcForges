// SPDX-License-Identifier: AGPL-3.0-only
// The owned arc_pdf_* engine. It validates every argument and every value a PDF backend returns, enforces the
// signed hard limits, serialises each document (PDFium is not thread safe), encodes bounded text/geometry and
// pixel output, and fails closed: an output buffer the caller supplied is never left holding partial results.
#include <arc/arc_pdf_abi.h>

#include "arc_native_abi_internal.hpp"
#include "pdf_backend.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <string>

namespace arc::pdf {
namespace {

constexpr uint32_t document_kind = 1;
constexpr size_t geometry_cache_limit = 1024;

arc_status_t failure(arc_status_t status, std::string_view message) noexcept
{
    return abi::fail(status, message, pdf_domain);
}

// A backend answers with ARC_OK or one of the closed negative codes. Anything else is a defect of the backend.
arc_status_t backend_status(arc_status_t status, std::string_view message) noexcept
{
    if (status == ARC_OK) {
        return ARC_OK;
    }
    if (status >= ARC_INTERNAL && status <= ARC_INVALID_ARGUMENT) {
        return failure(status, message);
    }
    return failure(ARC_INTERNAL, "The PDF backend returned a status outside the closed set");
}

template <typename F> arc_status_t guarded(F&& body) noexcept
{
    try {
        return body();
    } catch (const std::bad_alloc&) {
        return failure(ARC_OUT_OF_MEMORY, "PDF allocation failed");
    } catch (...) {
        return failure(ARC_INTERNAL, "The PDF backend raised an exception");
    }
}

arc_status_t take_limits(const arc_limits_v1* in, arc_limits_v1& out) noexcept
{
    if (in == nullptr) {
        return failure(ARC_INVALID_ARGUMENT, "Limits are required");
    }
    const arc_status_t valid = abi::validate_record(in, sizeof(arc_limits_v1));
    if (valid != ARC_OK) {
        return valid;
    }
    std::memcpy(&out, in, sizeof(arc_limits_v1));
    if (out.max_input_bytes == 0 || out.max_memory_bytes == 0 || out.max_output_bytes == 0 || out.max_width == 0 ||
        out.max_height == 0 || out.max_items == 0 || out.timeout_ms == 0) {
        return failure(ARC_INVALID_ARGUMENT, "Every limit must be positive");
    }
    if (out.max_input_bytes > profile_max_input_bytes || out.max_memory_bytes > profile_max_memory_bytes ||
        out.max_output_bytes > profile_max_output_bytes || out.max_width > profile_max_dimension ||
        out.max_height > profile_max_dimension || out.max_items > profile_max_items ||
        out.timeout_ms > profile_max_timeout_ms) {
        return failure(ARC_RESOURCE_LIMIT, "A limit exceeds the signed producer profile");
    }
    return ARC_OK;
}

class io_source final : public byte_source {
  public:
    explicit io_source(const arc_io_v1& io) noexcept : io_(io)
    {
    }
    [[nodiscard]] uint64_t length() const noexcept override
    {
        return io_.length;
    }
    arc_status_t read_at(uint64_t offset, void* destination, uint64_t requested, uint64_t* done) noexcept override
    {
        if (done == nullptr || (destination == nullptr && requested != 0)) {
            return ARC_INVALID_ARGUMENT;
        }
        *done = 0;
        if (offset >= io_.length || requested == 0) {
            return ARC_OK;
        }
        const uint64_t count = std::min<uint64_t>(requested, io_.length - offset);
        uint64_t read = 0;
        const arc_status_t status = io_.read_at(io_.context, offset, destination, count, &read);
        if (status != ARC_OK && status != ARC_END_OF_STREAM) {
            return status < 0 ? status : ARC_IO;
        }
        // The window is already clamped to the input, so a short read, however it is reported, is a defect of the
        // callback.
        if (read != count) {
            return ARC_IO;
        }
        *done = read;
        return ARC_OK;
    }

  private:
    arc_io_v1 io_;
};

struct document_state final {
    std::shared_ptr<byte_source> source;
    std::unique_ptr<document> parsed;
    arc_limits_v1 limits{};
    uint32_t pages = 0;
    std::mutex gate;
    std::map<uint32_t, page_geometry> geometries;
    uint32_t cached_text_page = UINT32_MAX;
    page_text cached_text;
};

abi::handle_table& table()
{
    static abi::handle_table instance(64);
    return instance;
}

bool is_high(char16_t unit) noexcept
{
    return unit >= 0xD800 && unit <= 0xDBFF;
}

bool is_low(char16_t unit) noexcept
{
    return unit >= 0xDC00 && unit <= 0xDFFF;
}

bool finite_in(double value, double low, double high) noexcept
{
    return std::isfinite(value) && value >= low && value <= high;
}

// Caller holds state.gate.
arc_status_t geometry_of(document_state& state, uint32_t index, const call_context& context, page_geometry& out)
{
    if (index >= state.pages) {
        return failure(ARC_NOT_FOUND, "Page index is out of range");
    }
    if (const auto found = state.geometries.find(index); found != state.geometries.end()) {
        out = found->second;
        return ARC_OK;
    }
    if (const arc_status_t gate = context.check(); gate != ARC_OK) {
        return gate;
    }
    page_geometry value;
    const arc_status_t status =
        backend_status(state.parsed->geometry(index, context, value), "PDF page geometry failed");
    if (status != ARC_OK) {
        return status;
    }
    if (const arc_status_t gate = context.check(); gate != ARC_OK) {
        return gate;
    }
    const bool rotation_valid =
        value.rotation == 0 || value.rotation == 90 || value.rotation == 180 || value.rotation == 270;
    if (!rotation_valid || !finite_in(value.width_points, std::numeric_limits<double>::min(), max_page_points) ||
        !finite_in(value.height_points, std::numeric_limits<double>::min(), max_page_points)) {
        return failure(ARC_CORRUPT, "The PDF backend returned invalid page geometry");
    }
    if (state.geometries.size() < geometry_cache_limit) {
        state.geometries.emplace(index, value);
    }
    out = value;
    return ARC_OK;
}

// Caller holds state.gate. Validates once on fetch: finite boxes inside the text, ordered by start.
arc_status_t text_of(document_state& state, uint32_t index, const call_context& context, const page_text*& out)
{
    if (index >= state.pages) {
        return failure(ARC_NOT_FOUND, "Page index is out of range");
    }
    if (state.cached_text_page == index) {
        out = &state.cached_text;
        return ARC_OK;
    }
    if (const arc_status_t gate = context.check(); gate != ARC_OK) {
        return gate;
    }
    page_text fetched;
    const arc_status_t status =
        backend_status(state.parsed->text(index, context, fetched), "PDF text extraction failed");
    if (status != ARC_OK) {
        return status;
    }
    if (const arc_status_t gate = context.check(); gate != ARC_OK) {
        return gate;
    }
    if (fetched.text.size() > max_page_text_units) {
        return failure(ARC_RESOURCE_LIMIT, "Page text exceeds its bound");
    }
    const uint64_t length = fetched.text.size();
    uint32_t previous = 0;
    for (const text_box& box : fetched.boxes) {
        if (const arc_status_t gate = context.check(); gate != ARC_OK) {
            return gate;
        }
        if (box.start < previous || box.length == 0 || static_cast<uint64_t>(box.start) + box.length > length ||
            !finite_in(box.x, -max_page_points, max_page_points) ||
            !finite_in(box.y, -max_page_points, max_page_points) || !finite_in(box.width, 0.0, max_page_points) ||
            !finite_in(box.height, 0.0, max_page_points)) {
            return failure(ARC_CORRUPT, "The PDF backend returned an invalid text box");
        }
        previous = box.start;
    }
    state.cached_text = std::move(fetched);
    state.cached_text_page = index;
    out = &state.cached_text;
    return ARC_OK;
}

void append_number(std::string& json, double value)
{
    char buffer[40];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
    json.append(buffer, result.ptr);
}

void append_number(std::string& json, uint64_t value)
{
    char buffer[24];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
    json.append(buffer, result.ptr);
}

void append_utf8(std::string& json, char32_t scalar)
{
    if (scalar < 0x80) {
        json.push_back(static_cast<char>(scalar));
    } else if (scalar < 0x800) {
        json.push_back(static_cast<char>(0xC0 | (scalar >> 6)));
        json.push_back(static_cast<char>(0x80 | (scalar & 0x3F)));
    } else if (scalar < 0x10000) {
        json.push_back(static_cast<char>(0xE0 | (scalar >> 12)));
        json.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3F)));
        json.push_back(static_cast<char>(0x80 | (scalar & 0x3F)));
    } else {
        json.push_back(static_cast<char>(0xF0 | (scalar >> 18)));
        json.push_back(static_cast<char>(0x80 | ((scalar >> 12) & 0x3F)));
        json.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3F)));
        json.push_back(static_cast<char>(0x80 | (scalar & 0x3F)));
    }
}

void append_json_text(std::string& json, const std::u16string& text, size_t begin, size_t end)
{
    static constexpr char hex[] = "0123456789abcdef";
    json.push_back('"');
    for (size_t i = begin; i < end; ++i) {
        const char16_t unit = text[i];
        if (unit == u'"' || unit == u'\\') {
            json.push_back('\\');
            json.push_back(static_cast<char>(unit));
        } else if (unit < 0x20) {
            json.append("\\u00");
            json.push_back(hex[(unit >> 4) & 0xF]);
            json.push_back(hex[unit & 0xF]);
        } else if (is_high(unit) && i + 1 < end && is_low(text[i + 1])) {
            append_utf8(json, 0x10000 + ((static_cast<char32_t>(unit) - 0xD800) << 10) +
                                  (static_cast<char32_t>(text[i + 1]) - 0xDC00));
            ++i;
        } else if (is_high(unit) || is_low(unit)) {
            append_utf8(json, 0xFFFD); // A lone surrogate is never valid UTF-8; it is replaced, not passed on.
        } else {
            append_utf8(json, unit);
        }
    }
    json.push_back('"');
}

size_t keep_pairs_whole(const std::u16string& text, size_t start, size_t end) noexcept
{
    if (end < text.size() && end > start && is_low(text[end]) && is_high(text[end - 1])) {
        --end;
    }
    if (end == start && start < text.size()) {
        end = start + ((is_high(text[start]) && start + 1 < text.size() && is_low(text[start + 1])) ? 2 : 1);
    }
    return end;
}

} // namespace

call_context::call_context(const arc_limits_v1& limits, const arc_cancel_token_t* cancel) noexcept
    : limits_(limits), cancel_(cancel),
      deadline_(std::chrono::steady_clock::now() + std::chrono::milliseconds(limits.timeout_ms))
{
}

arc_status_t call_context::check() const noexcept
{
    if (const arc_status_t cancelled = abi::check_cancelled(cancel_); cancelled != ARC_OK) {
        return cancelled;
    }
    if (std::chrono::steady_clock::now() > deadline_) {
        return failure(ARC_RESOURCE_LIMIT, "The parser deadline passed");
    }
    return ARC_OK;
}

} // namespace arc::pdf

using namespace arc::pdf;

arc_status_t ARC_ABI_CALL arc_pdf_open(const arc_io_v1* io, arc_string_view_t password, const arc_limits_v1* limits,
                                       arc_handle_t* document, uint32_t* pages, const arc_cancel_token_t* cancel)
{
    return guarded([&]() -> arc_status_t {
        if (const arc_status_t prepared = arc::abi::prepare_handle_output(document); prepared != ARC_OK) {
            return prepared;
        }
        if (pages == nullptr) {
            return failure(ARC_INVALID_ARGUMENT, "Page-count output is required");
        }
        *pages = 0;
        if (const arc_status_t valid = arc::abi::validate_record(io, sizeof(arc_io_v1)); valid != ARC_OK) {
            return valid;
        }
        if (io->read_at == nullptr) {
            return failure(ARC_INVALID_ARGUMENT, "The input read callback is required");
        }
        arc_limits_v1 bounded{};
        if (const arc_status_t taken = take_limits(limits, bounded); taken != ARC_OK) {
            return taken;
        }
        if (io->length == 0) {
            return failure(ARC_CORRUPT, "The input is empty");
        }
        if (io->length > bounded.max_input_bytes || (io->max_length != 0 && io->length > io->max_length)) {
            return failure(ARC_RESOURCE_LIMIT, "The input exceeds its bound");
        }
        if ((password.data == nullptr && password.size != 0) || password.size > max_password_bytes ||
            (password.size != 0 && std::memchr(password.data, 0, static_cast<size_t>(password.size)) != nullptr)) {
            return failure(ARC_INVALID_ARGUMENT, "The password is invalid");
        }
        if (const arc_status_t cancelled = arc::abi::check_cancelled(cancel); cancelled != ARC_OK) {
            return cancelled;
        }
        const std::shared_ptr<backend> parser = linked_backend();
        if (!parser) {
            return failure(ARC_UNSUPPORTED, "No PDF backend is linked into this build");
        }

        const call_context context(bounded, cancel);
        auto state = std::make_shared<document_state>();
        state->source = std::make_shared<io_source>(*io);
        state->limits = bounded;
        uint32_t count = 0;
        const std::string_view secret(password.data == nullptr ? "" : password.data,
                                      static_cast<size_t>(password.size));
        const arc_status_t opened = backend_status(parser->open(state->source, secret, context, state->parsed, count),
                                                   "The PDF could not be opened");
        if (opened != ARC_OK) {
            return opened;
        }
        if (!state->parsed) {
            return failure(ARC_INTERNAL, "The PDF backend returned no document");
        }
        if (const arc_status_t gate = context.check(); gate != ARC_OK) {
            return gate;
        }
        if (count == 0) {
            return failure(ARC_CORRUPT, "The PDF has no pages");
        }
        if (count > max_pages) {
            return failure(ARC_RESOURCE_LIMIT, "The PDF has too many pages");
        }
        state->pages = count;
        arc_handle_t created = 0;
        if (const arc_status_t made = table().create(document_kind, state, &created); made != ARC_OK) {
            return made;
        }
        *document = created;
        *pages = count;
        return ARC_OK;
    });
}

arc_status_t ARC_ABI_CALL arc_pdf_page_info(arc_handle_t document, uint32_t index, arc_pdf_page_v1* page)
{
    return guarded([&]() -> arc_status_t {
        if (const arc_status_t valid = arc::abi::validate_record(page, sizeof(arc_pdf_page_v1)); valid != ARC_OK) {
            return valid;
        }
        const uint32_t size = page->struct_size;
        const uint32_t version = page->struct_version;
        std::memset(page, 0, sizeof(arc_pdf_page_v1));
        page->struct_size = size;
        page->struct_version = version;
        arc::abi::handle_lease lease;
        if (const arc_status_t acquired = table().acquire(document, document_kind, &lease); acquired != ARC_OK) {
            return acquired;
        }
        auto& state = *lease.as<document_state>();
        const std::lock_guard lock(state.gate);
        const call_context context(state.limits, nullptr);
        page_geometry value;
        if (const arc_status_t read = geometry_of(state, index, context, value); read != ARC_OK) {
            return read;
        }
        page->page_index = index;
        page->rotation = value.rotation;
        page->width_points = value.width_points;
        page->height_points = value.height_points;
        return ARC_OK;
    });
}

arc_status_t ARC_ABI_CALL arc_pdf_render(arc_handle_t document, const arc_pdf_page_v1* page, const arc_region_v1* tile,
                                         uint32_t full_width, uint32_t full_height, arc_mut_buffer_t* rgba8,
                                         const arc_cancel_token_t* cancel)
{
    uint8_t* written_from = nullptr;
    uint64_t written_size = 0;
    const arc_status_t status = guarded([&]() -> arc_status_t {
        if (const arc_status_t valid = arc::abi::validate_record(page, sizeof(arc_pdf_page_v1)); valid != ARC_OK) {
            return valid;
        }
        if (const arc_status_t valid = arc::abi::validate_record(tile, sizeof(arc_region_v1)); valid != ARC_OK) {
            return valid;
        }
        if (rgba8 == nullptr) {
            return failure(ARC_INVALID_ARGUMENT, "Pixel output is required");
        }
        if (tile->width == 0 || tile->height == 0 || full_width == 0 || full_height == 0 || tile->first_sample != 0 ||
            tile->sample_count != 0) {
            return failure(ARC_INVALID_ARGUMENT, "The render region is invalid");
        }
        const uint64_t row_bytes = static_cast<uint64_t>(tile->width) * 4U;
        const uint64_t stride = tile->row_stride == 0 ? row_bytes : tile->row_stride;
        if (stride < row_bytes || stride > profile_max_tile_bytes) {
            return failure(ARC_INVALID_ARGUMENT, "The row stride is invalid");
        }
        if (static_cast<uint64_t>(tile->x) + tile->width > full_width ||
            static_cast<uint64_t>(tile->y) + tile->height > full_height) {
            return failure(ARC_INVALID_ARGUMENT, "The region lies outside the pixel grid");
        }
        if (static_cast<uint64_t>(full_width) * full_height > profile_max_pixels) {
            return failure(ARC_RESOURCE_LIMIT, "The pixel grid exceeds its bound");
        }
        // (height - 1) rows of stride plus one packed row: no byte past the last pixel is written or required.
        const uint64_t required = (static_cast<uint64_t>(tile->height) - 1U) * stride + row_bytes;
        if (const arc_status_t cancelled = arc::abi::check_cancelled(cancel); cancelled != ARC_OK) {
            return cancelled;
        }
        arc::abi::handle_lease lease;
        if (const arc_status_t acquired = table().acquire(document, document_kind, &lease); acquired != ARC_OK) {
            return acquired;
        }
        auto& state = *lease.as<document_state>();
        if (full_width > state.limits.max_width || full_height > state.limits.max_height ||
            required > state.limits.max_output_bytes || required > profile_max_tile_bytes) {
            return failure(ARC_RESOURCE_LIMIT, "The render request exceeds the document limits");
        }
        if (const arc_status_t prepared = arc::abi::prepare_buffer_output(rgba8, required); prepared != ARC_OK) {
            return prepared;
        }
        const std::lock_guard lock(state.gate);
        const call_context context(state.limits, cancel);
        page_geometry known;
        if (const arc_status_t read = geometry_of(state, page->page_index, context, known); read != ARC_OK) {
            return read;
        }
        // Scaling is never inferred from the caller's page record: it must be the geometry this document reports.
        if (page->rotation != known.rotation || page->width_points != known.width_points ||
            page->height_points != known.height_points) {
            return failure(ARC_INVALID_ARGUMENT, "The page record differs from the document page");
        }
        auto* const out = static_cast<uint8_t*>(rgba8->data);
        written_from = out;
        written_size = required;
        const region area{tile->x, tile->y, tile->width, tile->height};
        const arc_status_t rendered = backend_status(
            state.parsed->render(page->page_index, full_width, full_height, area, stride, out, required, context),
            "PDF rendering failed");
        if (rendered != ARC_OK) {
            return rendered;
        }
        return context.check();
    });
    if (status != ARC_OK && written_from != nullptr) {
        std::memset(written_from, 0, static_cast<size_t>(written_size)); // never leave partial pixels behind
    }
    return status;
}

arc_status_t ARC_ABI_CALL arc_pdf_text(arc_handle_t document, uint32_t page, uint32_t start, uint32_t count,
                                       arc_mut_buffer_t* text_geometry, const arc_cancel_token_t* cancel)
{
    return guarded([&]() -> arc_status_t {
        if (text_geometry == nullptr) {
            return failure(ARC_INVALID_ARGUMENT, "Text output is required");
        }
        if (count == 0 || count > max_text_units_per_call) {
            return failure(ARC_INVALID_ARGUMENT, "The text count is outside 1..65536");
        }
        if (const arc_status_t cancelled = arc::abi::check_cancelled(cancel); cancelled != ARC_OK) {
            return cancelled;
        }
        arc::abi::handle_lease lease;
        if (const arc_status_t acquired = table().acquire(document, document_kind, &lease); acquired != ARC_OK) {
            return acquired;
        }
        auto& state = *lease.as<document_state>();
        const std::lock_guard lock(state.gate);
        const call_context context(state.limits, cancel);
        const page_text* extracted = nullptr;
        if (const arc_status_t read = text_of(state, page, context, extracted); read != ARC_OK) {
            return read;
        }
        const std::u16string& text = extracted->text;
        const std::vector<text_box>& boxes = extracted->boxes;
        const size_t length = text.size();
        if (start > length || (start > 0 && start < length && is_low(text[start]) && is_high(text[start - 1]))) {
            return failure(ARC_INVALID_ARGUMENT, "The text start is not a position a chunk can begin at");
        }

        size_t end = keep_pairs_whole(text, start, std::min<size_t>(length, static_cast<size_t>(start) + count));
        std::vector<const text_box*> inside;
        while (true) {
            if (const arc_status_t gate = context.check(); gate != ARC_OK) {
                return gate;
            }
            inside.clear();
            auto first = std::lower_bound(boxes.begin(), boxes.end(), start,
                                          [](const text_box& box, uint32_t value) { return box.start < value; });
            // A box that would straddle the chunk end moves whole into the next chunk: the chunk ends where it starts.
            // A box that already straddles the window start cannot be moved and is not carried (it began in an earlier
            // window).
            size_t moved_end = end;
            for (auto probe = first; probe != boxes.end() && probe->start < end; ++probe) {
                if (const arc_status_t gate = context.check(); gate != ARC_OK) {
                    return gate;
                }
                if (probe->start > start && static_cast<uint64_t>(probe->start) + probe->length > end) {
                    moved_end = std::min<size_t>(moved_end, keep_pairs_whole(text, start, probe->start));
                    break;
                }
            }
            if (moved_end < end) {
                end = moved_end;
                continue;
            }
            for (; first != boxes.end() && first->start < end; ++first) {
                if (const arc_status_t gate = context.check(); gate != ARC_OK) {
                    return gate;
                }
                if (static_cast<uint64_t>(first->start) + first->length <= end) {
                    inside.push_back(&*first);
                }
            }
            if (inside.size() <= state.limits.max_items) {
                break;
            }
            const size_t cut = keep_pairs_whole(text, start, inside[state.limits.max_items]->start);
            if (cut <= start || cut >= end) {
                return failure(ARC_RESOURCE_LIMIT, "The text chunk carries too many boxes");
            }
            end = cut;
        }

        std::string json;
        json.reserve(256 + (end - start) * 2 + inside.size() * 96);
        json.append("{\"version\":1,\"page\":");
        append_number(json, static_cast<uint64_t>(page));
        json.append(",\"start\":");
        append_number(json, static_cast<uint64_t>(start));
        if (end < length) {
            json.append(",\"next\":");
            append_number(json, static_cast<uint64_t>(end));
        }
        json.append(",\"text\":");
        append_json_text(json, text, start, end);
        json.append(",\"boxes\":[");
        bool separator = false;
        for (const text_box* box : inside) {
            if (const arc_status_t gate = context.check(); gate != ARC_OK) {
                return gate;
            }
            if (separator) {
                json.push_back(',');
            }
            separator = true;
            json.append("{\"start\":");
            append_number(json, static_cast<uint64_t>(box->start));
            json.append(",\"length\":");
            append_number(json, static_cast<uint64_t>(box->length));
            json.append(",\"x\":");
            append_number(json, box->x);
            json.append(",\"y\":");
            append_number(json, box->y);
            json.append(",\"width\":");
            append_number(json, box->width);
            json.append(",\"height\":");
            append_number(json, box->height);
            json.push_back('}');
        }
        json.append("]}");
        if (json.size() > state.limits.max_output_bytes) {
            return failure(ARC_RESOURCE_LIMIT, "The text chunk exceeds the output limit");
        }
        if (const arc_status_t prepared = arc::abi::prepare_buffer_output(text_geometry, json.size());
            prepared != ARC_OK) {
            return prepared;
        }
        std::memcpy(text_geometry->data, json.data(), json.size());
        return ARC_OK;
    });
}

arc_status_t ARC_ABI_CALL arc_pdf_close(arc_handle_t document)
{
    return guarded([&]() -> arc_status_t { return table().close(document, document_kind); });
}
