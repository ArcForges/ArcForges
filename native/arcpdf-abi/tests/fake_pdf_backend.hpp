// SPDX-License-Identifier: AGPL-3.0-only
// TEST ONLY. A scripted PDF backend that stands in for PDFium so the owned engine's limits, validation, handle,
// cancellation, deadline and output-encoding code is exercised against hostile backend behaviour. It parses no real
// PDF, is compiled only into the arcpdf test executables, and is never linked into the shipped library.
#ifndef ARC_PDF_FAKE_BACKEND_HPP
#define ARC_PDF_FAKE_BACKEND_HPP

#include "pdf_backend.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <thread>

namespace arc::pdf::testing {

struct fake_page final {
    page_geometry geometry{0, 612.0, 792.0};
    page_text content;
};

struct fake_script final {
    std::vector<fake_page> pages;
    std::string required_password; // empty: not encrypted
    bool throw_on_open = false;
    bool throw_bad_alloc_on_open = false;
    bool throw_on_render = false;
    bool null_document = false;
    bool open_hangs_until_stopped = false; // loops on context.check()
    bool render_hangs_until_stopped = false;
    bool render_ignores_deadline_ms = false; // sleeps render_sleep_ms and returns OK
    uint32_t render_sleep_ms = 0;
    bool render_fails_after_writing = false; // writes the whole tile, then reports failure
    arc_status_t open_status = ARC_OK;       // returned instead of opening when not ARC_OK
    arc_status_t geometry_status = ARC_OK;
    arc_status_t text_status = ARC_OK;
    uint32_t reported_pages = 0;       // 0: pages.size()
    std::function<void()> on_geometry; // runs inside every geometry call
    uint64_t consumed_bytes = 0;       // set by open: bytes read through the source
    std::atomic<int> alive_documents{0};
    std::atomic<int> render_calls{0};
    std::atomic<int> text_calls{0};
    std::atomic<int> geometry_calls{0};
};

inline arc_status_t wait_for_stop(const call_context& context)
{
    for (;;) {
        const arc_status_t status = context.check();
        if (status != ARC_OK) {
            return status;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

class fake_document final : public document {
  public:
    explicit fake_document(std::shared_ptr<fake_script> script) : script_(std::move(script))
    {
        ++script_->alive_documents;
    }
    ~fake_document() override
    {
        --script_->alive_documents;
    }

    arc_status_t geometry(uint32_t index, const call_context&, page_geometry& out) override
    {
        ++script_->geometry_calls;
        if (script_->on_geometry) {
            script_->on_geometry();
        }
        if (script_->geometry_status != ARC_OK) {
            return script_->geometry_status;
        }
        out = script_->pages.at(index).geometry;
        return ARC_OK;
    }

    arc_status_t text(uint32_t index, const call_context&, page_text& out) override
    {
        ++script_->text_calls;
        if (script_->text_status != ARC_OK) {
            return script_->text_status;
        }
        out = script_->pages.at(index).content;
        return ARC_OK;
    }

    // Pixel (column, row) of the full grid is {column & 255, row & 255, page & 255, 255}.
    arc_status_t render(uint32_t index, uint32_t, uint32_t, const region& tile, uint64_t row_stride, uint8_t* out,
                        uint64_t out_size, const call_context& context) override
    {
        ++script_->render_calls;
        if (script_->throw_on_render) {
            throw std::runtime_error("render raised");
        }
        if (script_->render_hangs_until_stopped) {
            return wait_for_stop(context);
        }
        if (script_->render_ignores_deadline_ms) {
            std::this_thread::sleep_for(std::chrono::milliseconds(script_->render_sleep_ms));
        }
        for (uint32_t row = 0; row < tile.height; ++row) {
            for (uint32_t column = 0; column < tile.width; ++column) {
                const uint64_t offset = row * row_stride + static_cast<uint64_t>(column) * 4;
                if (offset + 4 > out_size) {
                    return ARC_INTERNAL; // the engine promised exactly the bytes up to the last pixel
                }
                out[offset + 0] = static_cast<uint8_t>((tile.x + column) & 255U);
                out[offset + 1] = static_cast<uint8_t>((tile.y + row) & 255U);
                out[offset + 2] = static_cast<uint8_t>(index & 255U);
                out[offset + 3] = 255;
            }
        }
        return script_->render_fails_after_writing ? ARC_CORRUPT : ARC_OK;
    }

  private:
    std::shared_ptr<fake_script> script_;
};

class fake_backend final : public backend {
  public:
    explicit fake_backend(std::shared_ptr<fake_script> script) : script_(std::move(script))
    {
    }

    arc_status_t open(std::shared_ptr<byte_source> source, std::string_view password, const call_context& context,
                      std::unique_ptr<document>& out, uint32_t& pages) override
    {
        if (script_->throw_bad_alloc_on_open) {
            throw std::bad_alloc();
        }
        if (script_->throw_on_open) {
            throw std::runtime_error("open raised");
        }
        if (script_->open_hangs_until_stopped) {
            return wait_for_stop(context);
        }
        if (script_->open_status != ARC_OK) {
            return script_->open_status;
        }
        // Read the whole input through the source in small steps: proves the callbacks are honoured end to end.
        uint8_t block[512];
        uint64_t offset = 0;
        std::string head;
        for (;;) {
            uint64_t done = 0;
            const arc_status_t status = source->read_at(offset, block, sizeof(block), &done);
            if (status != ARC_OK) {
                return status;
            }
            if (done == 0) {
                break;
            }
            if (head.size() < 8) {
                head.append(reinterpret_cast<const char*>(block), static_cast<size_t>(std::min<uint64_t>(done, 8)));
            }
            offset += done;
        }
        script_->consumed_bytes = offset;
        if (head.rfind("FAKEPDF", 0) != 0) {
            return ARC_CORRUPT;
        }
        if (!script_->required_password.empty() && password != script_->required_password) {
            return ARC_PERMISSION_DENIED;
        }
        if (script_->null_document) {
            out.reset();
        } else {
            out = std::make_unique<fake_document>(script_);
        }
        pages = script_->reported_pages != 0 ? script_->reported_pages : static_cast<uint32_t>(script_->pages.size());
        return ARC_OK;
    }

  private:
    std::shared_ptr<fake_script> script_;
};

} // namespace arc::pdf::testing

#endif
