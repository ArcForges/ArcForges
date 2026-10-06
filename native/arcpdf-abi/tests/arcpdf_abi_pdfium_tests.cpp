// SPDX-License-Identifier: AGPL-3.0-only
// Offline component tests over the actual admitted PDFium. They prove no OS isolation; that is the
// opt-in helper harness. The PDF is first-party and assembled with a valid cross-reference table.
#include <arc/arc_pdf_abi.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {
int failures = 0;
#define CHECK(expression)                                                                                              \
    do {                                                                                                               \
        if (!(expression)) {                                                                                           \
            std::fprintf(stderr, "FAILED %d: %s\n", __LINE__, #expression);                                            \
            ++failures;                                                                                                \
        }                                                                                                              \
    } while (false)

std::string unhex(const std::string& hex)
{
    std::string bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        bytes += static_cast<char>(digit(hex[i]) * 16 + digit(hex[i + 1]));
    }
    return bytes;
}

std::string fixture(bool encrypted = false)
{
    // First-party deterministic R2/40-bit password fixture: standard padding, owner arc-owner,
    // user arc-user, permission -4 and document ID 00112233445566778899aabbccddeeff. These encrypted
    // constants were generated from the same first-party stream with Python stdlib MD5 and RC4;
    // no third-party PDF or generator bytes are copied, and no weak encryption enters production.
    const std::string stream = encrypted ? unhex("bed315236e09e0f39ee077220257777ad2868cb77fb31cd510d32914508b01068"
                                                 "e78195ec06d624d5874bcfa1b21c9d5c377c1005bf75121f282ef19094ad5f1b7fa")
                                         : "1 0 0 rg 0 0 72 72 re f\nBT /F1 14 Tf 8 40 Td (ArcScope PDF) Tj ET\n";
    std::vector<std::string> objects = {
        "<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 144 72] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        "<< /Length " + std::to_string(stream.size()) + " >>\nstream\n" + stream + "endstream",
        encrypted ? "<< /S /JavaScript /JS <f3c69743db7dfa55cf34d67474ddc1b239054cd61b798240484246> >>"
                  : "<< /S /JavaScript /JS (app.alert('must never run')) >>",
    };
    if (encrypted)
        objects.push_back("<< /Filter /Standard /V 1 /R 2 /Length 40 /P -4 "
                          "/O <27f3cda7518ec227f683ccacc4e1e3c7876b381734985a4adf62aa104ea25a82> "
                          "/U <b68204f92eb06b1d8830e361922fdaf2cef04c0e3d9a7b3f9704ebbc8137d555> >>");
    std::string pdf = "%PDF-1.7\n";
    std::vector<size_t> offsets;
    for (size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(pdf.size());
        pdf += std::to_string(i + 1) + " 0 obj\n" + objects[i] + "\nendobj\n";
    }
    const auto xref = pdf.size();
    pdf += "xref\n0 " + std::to_string(objects.size() + 1) + "\n0000000000 65535 f \n";
    for (const auto offset : offsets) {
        char entry[40];
        std::snprintf(entry, sizeof(entry), "%010llu 00000 n \n", static_cast<unsigned long long>(offset));
        pdf += entry;
    }
    pdf += "trailer\n<< /Size " + std::to_string(objects.size() + 1) + " /Root 1 0 R " +
           (encrypted ? "/Encrypt 7 0 R /ID [<00112233445566778899aabbccddeeff><00112233445566778899aabbccddeeff>] "
                      : "") +
           ">>\nstartxref\n" + std::to_string(xref) + "\n%%EOF\n";
    return pdf;
}

struct input final {
    std::string bytes;
    std::atomic<int> reads{0};
    bool fail = false;
    bool short_read = false;
    bool slow_read = false;
};

arc_status_t ARC_ABI_CALL read_at(void* value, uint64_t offset, void* destination, uint64_t requested, uint64_t* read)
{
    auto& data = *static_cast<input*>(value);
    ++data.reads;
    *read = 0;
    if (data.fail)
        return ARC_IO;
    if (data.slow_read)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (offset > data.bytes.size() || requested > data.bytes.size() - offset)
        return ARC_IO;
    std::memcpy(destination, data.bytes.data() + offset, static_cast<size_t>(requested));
    *read = data.short_read ? requested - 1 : requested;
    return ARC_OK;
}

arc_limits_v1 limits()
{
    return {sizeof(arc_limits_v1), 1, 64 * 1024 * 1024, 128 * 1024 * 1024, 64 * 1024 * 1024, 4096, 4096, 1024, 5000};
}

arc_status_t open(input& data, arc_handle_t& handle, uint32_t& pages, const arc_cancel_token_t* cancel = nullptr,
                  const arc_limits_v1* custom = nullptr, const std::string& password = {})
{
    arc_io_v1 io{};
    io.struct_size = sizeof(io);
    io.struct_version = 1;
    io.context = &data;
    io.length = data.bytes.size();
    io.max_length = data.bytes.size();
    io.read_at = read_at;
    const auto bound = limits();
    return arc_pdf_open(&io, {password.data(), password.size()}, custom ? custom : &bound, &handle, &pages, cancel);
}

arc_bool_t ARC_ABI_CALL cancelled(void*)
{
    return 1;
}

arc_bool_t ARC_ABI_CALL cancelled_after_read(void* value)
{
    return static_cast<input*>(value)->reads.load() > 0 ? 1 : 0;
}

void actual_pdf()
{
    input data{fixture()};
    arc_handle_t handle = 0;
    uint32_t pages = 0;
    CHECK(open(data, handle, pages) == ARC_OK);
    CHECK(pages == 1 && handle != 0 && data.reads > 0);
    if (!handle)
        return;
    // PDFium borrows the backend's private copy, never the caller context after open.
    data.bytes.clear();
    data.fail = true;
    arc_pdf_page_v1 page{sizeof(arc_pdf_page_v1), 1, 0, 0, 0, 0};
    CHECK(arc_pdf_page_info(handle, 0, &page) == ARC_OK);
    CHECK(page.width_points == 144 && page.height_points == 72 && page.rotation == 0);
    arc_mut_buffer_t query{};
    CHECK(arc_pdf_text(handle, 0, 0, 100, &query, nullptr) == ARC_BUFFER_TOO_SMALL);
    std::vector<char> text(static_cast<size_t>(query.required));
    arc_mut_buffer_t buffer{text.data(), text.size(), 0};
    CHECK(arc_pdf_text(handle, 0, 0, 100, &buffer, nullptr) == ARC_OK);
    const std::string json(text.data(), static_cast<size_t>(buffer.required));
    CHECK(json.find("ArcScope PDF") != std::string::npos && json.find("\"boxes\":[{") != std::string::npos);
    const arc_region_v1 tile{sizeof(arc_region_v1), 1, 0, 0, 16, 16, 0, 0, 64};
    std::vector<uint8_t> pixels(16 * 64, 0);
    arc_mut_buffer_t output{pixels.data(), pixels.size(), 0};
    CHECK(arc_pdf_render(handle, &page, &tile, 144, 72, &output, nullptr) == ARC_OK);
    CHECK(output.required == pixels.size());
    CHECK(pixels[0] == 255 && pixels[1] == 0 && pixels[2] == 0 && pixels[3] == 255); // red, RGBA
    const arc_region_v1 edge{sizeof(arc_region_v1), 1, 140, 68, 4, 4, 0, 0, 16};
    std::vector<uint8_t> edge_pixels(64, 0);
    arc_mut_buffer_t edge_output{edge_pixels.data(), edge_pixels.size(), 0};
    CHECK(arc_pdf_render(handle, &page, &edge, 144, 72, &edge_output, nullptr) == ARC_OK);
    CHECK(edge_pixels[0] == 255 && edge_pixels[1] == 255 && edge_pixels[2] == 255);
    CHECK(arc_pdf_page_info(handle, 1, &page) == ARC_NOT_FOUND);
    CHECK(arc_pdf_close(handle) == ARC_OK);
    CHECK(arc_pdf_close(handle) == ARC_CLOSED);
}

void password_pdf()
{
    input data{fixture(true)};
    arc_handle_t handle = 999;
    uint32_t pages = 999;
    for (const std::string password : {std::string(), std::string("wrong-password")}) {
        CHECK(open(data, handle, pages, nullptr, nullptr, password) == ARC_PERMISSION_DENIED);
        CHECK(handle == 0 && pages == 0);
    }
    for (const std::string password : {std::string("arc-user"), std::string("arc-owner")}) {
        CHECK(open(data, handle, pages, nullptr, nullptr, password) == ARC_OK);
        CHECK(handle != 0 && pages == 1);
        if (!handle)
            continue;
        arc_mut_buffer_t query{};
        CHECK(arc_pdf_text(handle, 0, 0, 100, &query, nullptr) == ARC_BUFFER_TOO_SMALL);
        std::vector<char> text(static_cast<size_t>(query.required));
        arc_mut_buffer_t buffer{text.data(), text.size(), 0};
        CHECK(arc_pdf_text(handle, 0, 0, 100, &buffer, nullptr) == ARC_OK);
        CHECK(std::string(text.data(), static_cast<size_t>(buffer.required)).find("ArcScope PDF") != std::string::npos);
        CHECK(arc_pdf_close(handle) == ARC_OK);
    }
}

void errors()
{
    for (const auto& bytes : {std::string("not a PDF"), std::string("%PDF-1.7\n1 0 obj\n"), std::string()}) {
        input data{bytes};
        arc_handle_t handle = 999;
        uint32_t pages = 999;
        CHECK(open(data, handle, pages) == ARC_CORRUPT);
        CHECK(handle == 0 && pages == 0);
    }
    input data{fixture()};
    data.fail = true;
    arc_handle_t handle = 0;
    uint32_t pages = 0;
    CHECK(open(data, handle, pages) == ARC_IO && handle == 0 && pages == 0);
    data.fail = false;
    data.short_read = true;
    CHECK(open(data, handle, pages) == ARC_IO && handle == 0 && pages == 0);
    data.short_read = false;
    auto bound = limits();
    bound.max_input_bytes = data.bytes.size() - 1;
    CHECK(open(data, handle, pages, nullptr, &bound) == ARC_RESOURCE_LIMIT && handle == 0 && pages == 0);
    bound = limits();
    bound.timeout_ms = 1;
    data.slow_read = true;
    CHECK(open(data, handle, pages, nullptr, &bound) == ARC_RESOURCE_LIMIT && handle == 0 && pages == 0);
    data.slow_read = false;
    data.reads = 0;
    arc_cancel_token_t after_read{sizeof(arc_cancel_token_t), 1, cancelled_after_read, &data};
    CHECK(open(data, handle, pages, &after_read) == ARC_CANCELLED && data.reads > 0 && handle == 0 && pages == 0);
    arc_cancel_token_t cancel{sizeof(arc_cancel_token_t), 1, cancelled, nullptr};
    CHECK(open(data, handle, pages, &cancel) == ARC_CANCELLED && handle == 0 && pages == 0);
    CHECK(open(data, handle, pages) == ARC_OK);
    if (!handle)
        return;
    arc_pdf_page_v1 page{sizeof(arc_pdf_page_v1), 1, 0, 0, 0, 0};
    CHECK(arc_pdf_page_info(handle, 0, &page) == ARC_OK);
    const arc_region_v1 tile{sizeof(arc_region_v1), 1, 0, 0, 16, 16, 0, 0, 64};
    std::vector<uint8_t> pixels(1024, 0xEE);
    arc_mut_buffer_t output{pixels.data(), pixels.size(), 0};
    CHECK(arc_pdf_render(handle, &page, &tile, 144, 72, &output, &cancel) == ARC_CANCELLED);
    CHECK(output.required == 0 && std::all_of(pixels.begin(), pixels.end(), [](uint8_t x) { return x == 0xEE; }));
    CHECK(arc_pdf_close(handle) == ARC_OK);
}

void parallel_documents()
{
    std::atomic<int> errors{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
        threads.emplace_back([&] {
            for (int i = 0; i < 20; ++i) {
                input data{fixture()};
                arc_handle_t handle = 0;
                uint32_t pages = 0;
                if (open(data, handle, pages) != ARC_OK) {
                    ++errors;
                    continue;
                }
                arc_pdf_page_v1 page{sizeof(arc_pdf_page_v1), 1, 0, 0, 0, 0};
                if (arc_pdf_page_info(handle, 0, &page) != ARC_OK || page.width_points != 144)
                    ++errors;
                arc_mut_buffer_t query{};
                if (arc_pdf_text(handle, 0, 0, 100, &query, nullptr) != ARC_BUFFER_TOO_SMALL || query.required == 0)
                    ++errors;
                if (arc_pdf_close(handle) != ARC_OK)
                    ++errors;
            }
        });
    for (auto& thread : threads)
        thread.join();
    CHECK(errors == 0);
}
} // namespace

int main()
{
    actual_pdf();
    password_pdf();
    errors();
    parallel_documents();
    if (failures)
        return 1;
    std::puts(
        "Actual PDFium page/text/tile/error/lifetime/concurrency component checks passed; no OS isolation claim.");
    return 0;
}
