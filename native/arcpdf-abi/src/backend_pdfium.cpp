// SPDX-License-Identifier: AGPL-3.0-only
// Only the admitted no-V8/no-XFA PDFium build is linked. No form environment is created, no document or
// page action is dispatched, and system fonts are disabled. All PDFium entry points share one lock:
// PDFium is not thread safe even across different documents. The helper's OS profile is the hard memory
// and deadline boundary; cooperative checks here allow ordinary cancellation without killing a helper.
#include "pdf_backend.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <fpdf_edit.h>
#include <fpdf_progressive.h>
#include <fpdf_sysfontinfo.h>
#include <fpdf_text.h>
#include <fpdfview.h>

#include <algorithm>
#include <climits>
#include <cmath>
#include <mutex>
#include <thread>

namespace arc::pdf {
namespace {

std::timed_mutex& library_gate()
{
    // The handle registry can still own documents during static teardown. Keep the gate alive for
    // the same process lifetime as PDFium rather than locking a destroyed static mutex on shutdown.
    static auto* gate = new std::timed_mutex;
    return *gate;
}

arc_status_t enter(std::unique_lock<std::timed_mutex>& lock, const call_context& context)
{
    while (!lock.try_lock_for(std::chrono::milliseconds(2))) {
        if (const auto status = context.check(); status != ARC_OK) {
            return status;
        }
    }
    return context.check();
}

void* no_font(FPDF_SYSFONTINFO*, int, FPDF_BOOL, int, int, const char*, FPDF_BOOL*)
{
    return nullptr;
}

unsigned long no_font_data(FPDF_SYSFONTINFO*, void*, unsigned int, unsigned char*, unsigned long)
{
    return 0;
}

void initialise()
{
    // Called under library_gate. Keep PDFium initialized until process exit: a backend object can be
    // released while generation handles still own documents, so object lifetime cannot govern teardown.
    static const bool ready = [] {
        FPDF_LIBRARY_CONFIG config{};
        config.version = 2;
        FPDF_InitLibraryWithConfig(&config);
        static FPDF_SYSFONTINFO fonts{};
        fonts.version = 2;
        fonts.MapFont = no_font;
        fonts.GetFontData = no_font_data;
        FPDF_SetSystemFontInfo(&fonts);
        return true;
    }();
    (void)ready;
}

class page_owner final {
  public:
    explicit page_owner(FPDF_PAGE value) noexcept : value_(value)
    {
    }
    ~page_owner()
    {
        if (value_)
            FPDF_ClosePage(value_);
    }
    page_owner(const page_owner&) = delete;
    page_owner& operator=(const page_owner&) = delete;
    [[nodiscard]] FPDF_PAGE get() const noexcept
    {
        return value_;
    }

  private:
    FPDF_PAGE value_;
};

class text_owner final {
  public:
    explicit text_owner(FPDF_TEXTPAGE value) noexcept : value_(value)
    {
    }
    ~text_owner()
    {
        if (value_)
            FPDFText_ClosePage(value_);
    }
    text_owner(const text_owner&) = delete;
    text_owner& operator=(const text_owner&) = delete;
    [[nodiscard]] FPDF_TEXTPAGE get() const noexcept
    {
        return value_;
    }

  private:
    FPDF_TEXTPAGE value_;
};

class bitmap_owner final {
  public:
    explicit bitmap_owner(FPDF_BITMAP value) noexcept : value_(value)
    {
    }
    ~bitmap_owner()
    {
        if (value_)
            FPDFBitmap_Destroy(value_);
    }
    bitmap_owner(const bitmap_owner&) = delete;
    bitmap_owner& operator=(const bitmap_owner&) = delete;
    [[nodiscard]] FPDF_BITMAP get() const noexcept
    {
        return value_;
    }

  private:
    FPDF_BITMAP value_;
};

class render_owner final {
  public:
    explicit render_owner(FPDF_PAGE page) noexcept : page_(page)
    {
    }
    ~render_owner()
    {
        FPDF_RenderPage_Close(page_);
    }
    render_owner(const render_owner&) = delete;
    render_owner& operator=(const render_owner&) = delete;

  private:
    FPDF_PAGE page_;
};

FPDF_BOOL pause_now(IFSDK_PAUSE* pause)
{
    // Ask PDFium to yield at every progressive checkpoint, bounding the work between cancellation checks.
    (void)pause;
    return 1;
}

class pdfium_document final : public document {
  public:
    pdfium_document(std::vector<uint8_t> bytes, FPDF_DOCUMENT parsed) noexcept
        : bytes_(std::move(bytes)), parsed_(parsed)
    {
    }
    ~pdfium_document() override
    {
        const std::lock_guard lock(library_gate());
        FPDF_CloseDocument(parsed_);
    }

    arc_status_t geometry(uint32_t index, const call_context& context, page_geometry& out) override
    {
        std::unique_lock lock(library_gate(), std::defer_lock);
        if (const auto status = enter(lock, context); status != ARC_OK)
            return status;
        if (index > static_cast<uint32_t>(INT_MAX))
            return ARC_NOT_FOUND;
        page_owner page(FPDF_LoadPage(parsed_, static_cast<int>(index)));
        if (!page.get())
            return ARC_CORRUPT;
        const int rotation = FPDFPage_GetRotation(page.get());
        if (rotation < 0 || rotation > 3)
            return ARC_CORRUPT;
        out = {static_cast<uint32_t>(rotation) * 90U, FPDF_GetPageWidth(page.get()), FPDF_GetPageHeight(page.get())};
        return context.check();
    }

    arc_status_t text(uint32_t index, const call_context& context, page_text& out) override
    {
        std::unique_lock lock(library_gate(), std::defer_lock);
        if (const auto status = enter(lock, context); status != ARC_OK)
            return status;
        if (index > static_cast<uint32_t>(INT_MAX))
            return ARC_NOT_FOUND;
        page_owner page(FPDF_LoadPage(parsed_, static_cast<int>(index)));
        if (!page.get())
            return ARC_CORRUPT;
        text_owner text(FPDFText_LoadPage(page.get()));
        if (!text.get())
            return ARC_CORRUPT;
        const int count = FPDFText_CountChars(text.get());
        if (count < 0)
            return ARC_CORRUPT;
        // Reserve only the output budget; PDFium's private allocation is additionally OS-bounded.
        const uint64_t budget = std::min(context.limits().max_memory_bytes, context.limits().max_output_bytes);
        if (static_cast<uint64_t>(count) > max_page_text_units ||
            static_cast<uint64_t>(count) > budget / (sizeof(text_box) + 2 * sizeof(char16_t)))
            return ARC_RESOURCE_LIMIT;
        out.text.reserve(static_cast<size_t>(count));
        out.boxes.reserve(static_cast<size_t>(count));
        for (int i = 0; i < count; ++i) {
            if (const auto status = context.check(); status != ARC_OK)
                return status;
            const auto scalar = FPDFText_GetUnicode(text.get(), i);
            // Unmapped characters are explicit replacement characters, never embedded NULs. Refuse
            // invalid scalar values rather than emitting malformed UTF-16 across the ABI.
            if (scalar > 0x10FFFF || (scalar >= 0xD800 && scalar <= 0xDFFF))
                return ARC_CORRUPT;
            const auto start = static_cast<uint32_t>(out.text.size());
            if (scalar > 0xFFFF) {
                const auto pair = scalar - 0x10000;
                out.text.push_back(static_cast<char16_t>(0xD800 + (pair >> 10)));
                out.text.push_back(static_cast<char16_t>(0xDC00 + (pair & 0x3FF)));
            } else {
                out.text.push_back(static_cast<char16_t>(scalar == 0 ? 0xFFFD : scalar));
            }
            if (out.text.size() > max_page_text_units)
                return ARC_RESOURCE_LIMIT;
            double left = 0, right = 0, bottom = 0, top = 0;
            if (!FPDFText_GetCharBox(text.get(), i, &left, &right, &bottom, &top))
                return ARC_CORRUPT;
            if (!std::isfinite(left) || !std::isfinite(right) || !std::isfinite(bottom) || !std::isfinite(top) ||
                right < left || top < bottom)
                return ARC_CORRUPT;
            out.boxes.push_back(
                {start, static_cast<uint32_t>(out.text.size()) - start, left, bottom, right - left, top - bottom});
        }
        return context.check();
    }

    arc_status_t render(uint32_t index, uint32_t full_width, uint32_t full_height, const region& tile,
                        uint64_t row_stride, uint8_t* out, uint64_t out_size, const call_context& context) override
    {
        std::unique_lock lock(library_gate(), std::defer_lock);
        if (const auto status = enter(lock, context); status != ARC_OK)
            return status;
        if (index > static_cast<uint32_t>(INT_MAX))
            return ARC_NOT_FOUND;
        if (!out || tile.width == 0 || tile.height == 0 || full_width > INT_MAX || full_height > INT_MAX ||
            tile.width > INT_MAX || tile.height > INT_MAX || tile.x > INT_MAX || tile.y > INT_MAX ||
            row_stride > INT_MAX || row_stride < static_cast<uint64_t>(tile.width) * 4 ||
            (static_cast<uint64_t>(tile.height) - 1) * row_stride + static_cast<uint64_t>(tile.width) * 4 > out_size)
            return ARC_INVALID_ARGUMENT;
        page_owner page(FPDF_LoadPage(parsed_, static_cast<int>(index)));
        if (!page.get())
            return ARC_CORRUPT;
        bitmap_owner bitmap(FPDFBitmap_CreateEx(static_cast<int>(tile.width), static_cast<int>(tile.height),
                                                FPDFBitmap_BGRA, out, static_cast<int>(row_stride)));
        if (!bitmap.get())
            return ARC_OUT_OF_MEMORY;
        if (!FPDFBitmap_FillRect(bitmap.get(), 0, 0, static_cast<int>(tile.width), static_cast<int>(tile.height),
                                 0xFFFFFFFF))
            return ARC_INTERNAL;
        IFSDK_PAUSE pause{1, pause_now, nullptr};
        render_owner close_render(page.get());
        int state = FPDF_RenderPageBitmap_Start(
            bitmap.get(), page.get(), -static_cast<int>(tile.x), -static_cast<int>(tile.y),
            static_cast<int>(full_width), static_cast<int>(full_height), 0, FPDF_RENDER_LIMITEDIMAGECACHE, &pause);
        while (state == FPDF_RENDER_TOBECONTINUED) {
            if (const auto status = context.check(); status != ARC_OK)
                return status;
            state = FPDF_RenderPage_Continue(page.get(), &pause);
        }
        if (state != FPDF_RENDER_DONE)
            return ARC_CORRUPT;
        // ABI tiles are RGBA8; PDFium writes BGRA8. Preserve padded rows and check cancellation during conversion.
        for (uint32_t y = 0; y < tile.height; ++y) {
            if (const auto status = context.check(); status != ARC_OK)
                return status;
            auto* row = out + static_cast<uint64_t>(y) * row_stride;
            for (uint32_t x = 0; x < tile.width; ++x)
                std::swap(row[x * 4], row[x * 4 + 2]);
        }
        return context.check();
    }

  private:
    std::vector<uint8_t> bytes_; // FPDF_LoadMemDocument64 borrows these bytes for the whole document lifetime.
    FPDF_DOCUMENT parsed_;
};

class pdfium_backend final : public backend {
  public:
    arc_status_t open(std::shared_ptr<byte_source> source, std::string_view password, const call_context& context,
                      std::unique_ptr<document>& out, uint32_t& pages) override
    {
        if (!source)
            return ARC_INVALID_ARGUMENT;
        const auto length = source->length();
        if (length == 0)
            return ARC_CORRUPT;
        if (length > context.limits().max_input_bytes || length > context.limits().max_memory_bytes ||
            length > static_cast<uint64_t>(SIZE_MAX))
            return ARC_RESOURCE_LIMIT;
        std::vector<uint8_t> bytes(static_cast<size_t>(length));
        uint64_t offset = 0;
        while (offset < length) {
            if (const auto status = context.check(); status != ARC_OK)
                return status;
            const auto requested = std::min<uint64_t>(length - offset, 64 * 1024);
            uint64_t read = 0;
            const auto status = source->read_at(offset, bytes.data() + offset, requested, &read);
            if (status != ARC_OK)
                return status;
            if (read == 0 || read > requested)
                return ARC_IO;
            offset += read;
        }
        std::unique_lock lock(library_gate(), std::defer_lock);
        if (const auto status = enter(lock, context); status != ARC_OK)
            return status;
        initialise();
        const std::string owned_password(password);
        FPDF_DOCUMENT parsed =
            FPDF_LoadMemDocument64(bytes.data(), bytes.size(), password.empty() ? nullptr : owned_password.c_str());
        if (!parsed)
            return FPDF_GetLastError() == FPDF_ERR_PASSWORD ? ARC_PERMISSION_DENIED : ARC_CORRUPT;
        const int count = FPDF_GetPageCount(parsed);
        if (count <= 0 || static_cast<uint64_t>(count) > max_pages) {
            FPDF_CloseDocument(parsed);
            return count <= 0 ? ARC_CORRUPT : ARC_RESOURCE_LIMIT;
        }
        if (const auto status = context.check(); status != ARC_OK) {
            FPDF_CloseDocument(parsed);
            return status;
        }
        // Allocation can throw. Close while still holding the global lock, without invoking the
        // document's locking destructor inside this critical section.
        try {
            out = std::make_unique<pdfium_document>(std::move(bytes), parsed);
        } catch (...) {
            FPDF_CloseDocument(parsed);
            throw;
        }
        pages = static_cast<uint32_t>(count);
        return ARC_OK;
    }
};

} // namespace

std::shared_ptr<backend> linked_backend()
{
    static const auto instance = std::make_shared<pdfium_backend>();
    return instance;
}

} // namespace arc::pdf
