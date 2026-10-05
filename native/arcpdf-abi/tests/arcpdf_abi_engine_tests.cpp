// SPDX-License-Identifier: AGPL-3.0-only
// Engine tests: the owned arc_pdf_* surface against a scripted fake backend (see fake_pdf_backend.hpp). They prove the
// limits, validation, handle lifetime, cancellation, deadline and output-encoding code. They prove nothing about PDFium.
#include <arc/arc_pdf_abi.h>

#include "fake_pdf_backend.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <limits>
#include <string>
#include <thread>
#include <vector>

using namespace arc::pdf;
using namespace arc::pdf::testing;

namespace {

std::shared_ptr<fake_script> g_script;
std::shared_ptr<backend> g_backend;
int g_failures = 0;

#define CHECK(expression)                                                                                              \
    do {                                                                                                               \
        if (!(expression)) {                                                                                           \
            std::fprintf(stderr, "FAILED %s:%d: %s\n", __FILE__, __LINE__, #expression);                               \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (false)

#define CHECK_STATUS(expected, expression)                                                                             \
    do {                                                                                                               \
        const arc_status_t actual_status = (expression);                                                               \
        if (actual_status != (expected)) {                                                                             \
            std::fprintf(stderr, "FAILED %s:%d: %s returned %d, expected %d\n", __FILE__, __LINE__, #expression,        \
                         static_cast<int>(actual_status), static_cast<int>(expected));                                 \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (false)

struct input_bytes final {
    std::string bytes;
    uint64_t short_reads = 0; // when nonzero, every read returns at most this many bytes
    arc_status_t read_status = ARC_OK;
    bool overrun = false;
};

arc_status_t ARC_ABI_CALL read_input(void* context, uint64_t offset, void* destination, uint64_t requested,
                                     uint64_t* done)
{
    auto* input = static_cast<input_bytes*>(context);
    if (input->read_status != ARC_OK) {
        return input->read_status;
    }
    if (input->overrun) {
        *done = requested + 1;
        return ARC_OK;
    }
    uint64_t count = std::min<uint64_t>(requested, input->bytes.size() - offset);
    if (input->short_reads != 0) {
        count = std::min(count, input->short_reads);
    }
    std::memcpy(destination, input->bytes.data() + offset, static_cast<size_t>(count));
    *done = count;
    return ARC_OK;
}

arc_io_v1 io_for(input_bytes& input)
{
    arc_io_v1 io{};
    io.struct_size = sizeof(arc_io_v1);
    io.struct_version = 1;
    io.context = &input;
    io.length = input.bytes.size();
    io.max_length = input.bytes.size();
    io.read_at = read_input;
    return io;
}

arc_limits_v1 limits_for(uint32_t timeout_ms = 5000, uint32_t max_items = 1024)
{
    arc_limits_v1 limits{};
    limits.struct_size = sizeof(arc_limits_v1);
    limits.struct_version = 1;
    limits.max_input_bytes = 64ULL * 1024 * 1024;
    limits.max_memory_bytes = 512ULL * 1024 * 1024;
    limits.max_output_bytes = 3ULL * 64 * 1024 * 1024;
    limits.max_width = 16384;
    limits.max_height = 16384;
    limits.max_items = max_items;
    limits.timeout_ms = timeout_ms;
    return limits;
}

arc_string_view_t view(const char* text)
{
    return arc_string_view_t{text, std::strlen(text)};
}

fake_page page_with(const std::u16string& text, std::vector<text_box> boxes = {}, page_geometry geometry = {0, 612.0, 792.0})
{
    fake_page page;
    page.geometry = geometry;
    page.content.text = text;
    page.content.boxes = std::move(boxes);
    return page;
}

void reset(std::vector<fake_page> pages)
{
    g_script = std::make_shared<fake_script>();
    g_script->pages = std::move(pages);
    g_backend = std::make_shared<fake_backend>(g_script);
}

struct opened final {
    arc_handle_t handle = 0;
    uint32_t pages = 0;
};

arc_status_t open_document(input_bytes& input, opened& out, const arc_limits_v1& limits = limits_for(),
                           arc_string_view_t password = {}, const arc_cancel_token_t* cancel = nullptr)
{
    const arc_io_v1 io = io_for(input);
    return arc_pdf_open(&io, password, &limits, &out.handle, &out.pages, cancel);
}

opened open_ok(const arc_limits_v1& limits = limits_for())
{
    input_bytes input{"FAKEPDF1\nbody"};
    opened document;
    CHECK_STATUS(ARC_OK, open_document(input, document, limits));
    return document;
}

std::string fetch_text(arc_handle_t document, uint32_t page, uint32_t start, uint32_t count, arc_status_t* status_out = nullptr)
{
    arc_mut_buffer_t query{};
    arc_status_t status = arc_pdf_text(document, page, start, count, &query, nullptr);
    if (status != ARC_BUFFER_TOO_SMALL) {
        if (status_out != nullptr) {
            *status_out = status;
        }
        return {};
    }
    std::string buffer(static_cast<size_t>(query.required), '\0');
    arc_mut_buffer_t output{buffer.data(), buffer.size(), 0};
    status = arc_pdf_text(document, page, start, count, &output, nullptr);
    if (status_out != nullptr) {
        *status_out = status;
    }
    CHECK(output.required == buffer.size());
    return status == ARC_OK ? buffer : std::string{};
}

arc_pdf_page_v1 page_record()
{
    arc_pdf_page_v1 page{};
    page.struct_size = sizeof(arc_pdf_page_v1);
    page.struct_version = 1;
    return page;
}

arc_region_v1 region_of(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint64_t stride = 0)
{
    arc_region_v1 region{};
    region.struct_size = sizeof(arc_region_v1);
    region.struct_version = 1;
    region.x = x;
    region.y = y;
    region.width = width;
    region.height = height;
    region.row_stride = stride;
    return region;
}

struct counting_cancel final {
    std::atomic<int> polls{0};
    int cancel_after = 0; // cancelled once polls exceeds this
};

arc_bool_t ARC_ABI_CALL cancel_after_polls(void* user)
{
    auto* state = static_cast<counting_cancel*>(user);
    return ++state->polls > state->cancel_after ? 1 : 0;
}

arc_cancel_token_t token_for(counting_cancel& state)
{
    arc_cancel_token_t token{};
    token.struct_size = sizeof(arc_cancel_token_t);
    token.struct_version = 1;
    token.is_cancelled = cancel_after_polls;
    token.user_data = &state;
    return token;
}

// The same 12-character tail the engine uses for the surrogate cases.
const std::u16string pair = u"\xD83D\xDE00"; // U+1F600

void test_preamble()
{
    reset({});
    uint32_t major = 0;
    uint32_t minor = 0;
    CHECK_STATUS(ARC_OK, arc_pdf_get_abi_version(&major, &minor));
    CHECK(major == 1 && minor == 1);
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_get_abi_version(nullptr, &minor));
    arc_mut_buffer_t query{};
    CHECK_STATUS(ARC_BUFFER_TOO_SMALL, arc_pdf_get_build_info(&query));
    std::string info(static_cast<size_t>(query.required), '\0');
    arc_mut_buffer_t output{info.data(), info.size(), 0};
    CHECK_STATUS(ARC_OK, arc_pdf_get_build_info(&output));
    CHECK(info.rfind("ArcPdfNative;abi=1.1;backend=linked", 0) == 0);
    arc_error_info_t error{};
    error.struct_size = sizeof(arc_error_info_t);
    error.struct_version = 1;
    CHECK_STATUS(ARC_BUFFER_TOO_SMALL, arc_pdf_get_last_error(&error));
    CHECK(error.status == ARC_INVALID_ARGUMENT);
}

void test_open_validation()
{
    reset({page_with(u"a")});
    input_bytes input{"FAKEPDF1\nbody"};
    const arc_limits_v1 limits = limits_for();
    arc_io_v1 io = io_for(input);
    opened out;

    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(nullptr, {}, &limits, &out.handle, &out.pages, nullptr));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&io, {}, nullptr, &out.handle, &out.pages, nullptr));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&io, {}, &limits, nullptr, &out.pages, nullptr));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&io, {}, &limits, &out.handle, nullptr, nullptr));

    arc_io_v1 bad = io;
    bad.struct_size = sizeof(arc_io_v1) - 1;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&bad, {}, &limits, &out.handle, &out.pages, nullptr));
    bad = io;
    bad.struct_version = 2;
    CHECK_STATUS(ARC_VERSION_MISMATCH, arc_pdf_open(&bad, {}, &limits, &out.handle, &out.pages, nullptr));
    bad = io;
    bad.read_at = nullptr;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&bad, {}, &limits, &out.handle, &out.pages, nullptr));
    bad = io;
    bad.length = 0;
    CHECK_STATUS(ARC_CORRUPT, arc_pdf_open(&bad, {}, &limits, &out.handle, &out.pages, nullptr));
    bad = io;
    bad.length = 100;
    bad.max_length = 50;
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_open(&bad, {}, &limits, &out.handle, &out.pages, nullptr));
    CHECK(out.handle == 0 && out.pages == 0);

    arc_limits_v1 zero = limits;
    zero.max_items = 0;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&io, {}, &zero, &out.handle, &out.pages, nullptr));
    zero = limits;
    zero.timeout_ms = 0;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&io, {}, &zero, &out.handle, &out.pages, nullptr));
    arc_limits_v1 over = limits;
    over.max_width = 65536;
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_open(&io, {}, &over, &out.handle, &out.pages, nullptr));
    over = limits;
    over.timeout_ms = 30001;
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_open(&io, {}, &over, &out.handle, &out.pages, nullptr));
    over = limits;
    over.max_input_bytes = 256ULL * 1024 * 1024 + 1;
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_open(&io, {}, &over, &out.handle, &out.pages, nullptr));
    over = limits;
    over.max_input_bytes = 4; // smaller than the input
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_open(&io, {}, &over, &out.handle, &out.pages, nullptr));

    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_open(&io, arc_string_view_t{nullptr, 3}, &limits, &out.handle, &out.pages, nullptr));
    const std::string long_password(1025, 'p');
    CHECK_STATUS(ARC_INVALID_ARGUMENT,
                 arc_pdf_open(&io, arc_string_view_t{long_password.data(), long_password.size()}, &limits, &out.handle, &out.pages, nullptr));
    CHECK(out.handle == 0 && out.pages == 0);
    CHECK(g_script->alive_documents == 0);
}

void test_open_backend_behaviour()
{
    input_bytes input{"FAKEPDF1\nbody"};
    opened out;

    reset({page_with(u"a")});
    input_bytes wrong{"%PDF-1.7 but not the fake"};
    CHECK_STATUS(ARC_CORRUPT, open_document(wrong, out));

    reset({page_with(u"a")});
    g_script->required_password = "s3cret";
    CHECK_STATUS(ARC_PERMISSION_DENIED, open_document(input, out));
    CHECK_STATUS(ARC_PERMISSION_DENIED, open_document(input, out, limits_for(), view("nope")));
    CHECK_STATUS(ARC_OK, open_document(input, out, limits_for(), view("s3cret")));
    CHECK(out.pages == 1 && out.handle != 0);
    CHECK_STATUS(ARC_OK, arc_pdf_close(out.handle));

    reset({page_with(u"a")});
    g_script->throw_bad_alloc_on_open = true;
    CHECK_STATUS(ARC_OUT_OF_MEMORY, open_document(input, out));
    reset({page_with(u"a")});
    g_script->throw_on_open = true;
    CHECK_STATUS(ARC_INTERNAL, open_document(input, out));
    reset({page_with(u"a")});
    g_script->open_status = ARC_BUFFER_TOO_SMALL; // a positive code is not in a backend's closed set
    CHECK_STATUS(ARC_INTERNAL, open_document(input, out));
    reset({page_with(u"a")});
    g_script->open_status = static_cast<arc_status_t>(-99);
    CHECK_STATUS(ARC_INTERNAL, open_document(input, out));
    reset({page_with(u"a")});
    g_script->open_status = ARC_RESOURCE_LIMIT;
    CHECK_STATUS(ARC_RESOURCE_LIMIT, open_document(input, out));
    reset({page_with(u"a")});
    g_script->null_document = true;
    CHECK_STATUS(ARC_INTERNAL, open_document(input, out));
    reset({});
    CHECK_STATUS(ARC_CORRUPT, open_document(input, out)); // zero pages
    reset({page_with(u"a")});
    g_script->reported_pages = (1U << 24) + 1;
    CHECK_STATUS(ARC_RESOURCE_LIMIT, open_document(input, out));
    CHECK(out.handle == 0 && out.pages == 0);
    CHECK(g_script->alive_documents == 0);
}

void test_io_callbacks()
{
    reset({page_with(u"a")});
    opened out;
    input_bytes shorts{std::string("FAKEPDF1\n") + std::string(3000, 'x'), 7};
    CHECK_STATUS(ARC_OK, open_document(shorts, out));
    CHECK(g_script->consumed_bytes == shorts.bytes.size());
    CHECK_STATUS(ARC_OK, arc_pdf_close(out.handle));

    input_bytes failing{"FAKEPDF1\nbody"};
    failing.read_status = ARC_IO;
    CHECK_STATUS(ARC_IO, open_document(failing, out));
    input_bytes cancelled{"FAKEPDF1\nbody"};
    cancelled.read_status = ARC_CANCELLED;
    CHECK_STATUS(ARC_CANCELLED, open_document(cancelled, out));
    input_bytes overrun{"FAKEPDF1\nbody"};
    overrun.overrun = true;
    CHECK_STATUS(ARC_IO, open_document(overrun, out)); // done > requested is a defect of the caller's callback
    CHECK(g_script->alive_documents == 0);
}

void test_handle_lifetime()
{
    reset({page_with(u"a")});
    opened first = open_ok();
    CHECK(first.handle != 0);
    arc_pdf_page_v1 page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(first.handle, 0, &page));
    CHECK_STATUS(ARC_OK, arc_pdf_close(first.handle));
    CHECK(g_script->alive_documents == 0);
    CHECK_STATUS(ARC_CLOSED, arc_pdf_close(first.handle));
    page = page_record();
    CHECK_STATUS(ARC_CLOSED, arc_pdf_page_info(first.handle, 0, &page));
    arc_mut_buffer_t out{};
    CHECK_STATUS(ARC_CLOSED, arc_pdf_text(first.handle, 0, 0, 10, &out, nullptr));
    CHECK_STATUS(ARC_CLOSED, arc_pdf_close(0));
    CHECK_STATUS(ARC_CLOSED, arc_pdf_close(UINT64_C(0xFFFFFFFFFFFFFFFF)));

    // The 64-document library limit, and no growth over repeated open/close.
    std::vector<opened> held;
    for (int i = 0; i < 64; ++i) {
        held.push_back(open_ok());
        CHECK(held.back().handle != 0);
    }
    input_bytes input{"FAKEPDF1\nbody"};
    opened refused;
    CHECK_STATUS(ARC_RESOURCE_LIMIT, open_document(input, refused));
    CHECK(refused.handle == 0 && g_script->alive_documents == 64);
    for (const opened& document : held) {
        CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));
    }
    CHECK(g_script->alive_documents == 0);
    for (int i = 0; i < 1000; ++i) {
        const opened document = open_ok();
        CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));
    }
    CHECK(g_script->alive_documents == 0);
}

void test_page_info()
{
    reset({page_with(u"a", {}, {0, 612.0, 792.0}), page_with(u"b", {}, {90, 300.5, 400.25})});
    const opened document = open_ok();
    CHECK(document.pages == 2);
    arc_pdf_page_v1 page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(document.handle, 1, &page));
    CHECK(page.page_index == 1 && page.rotation == 90 && page.width_points == 300.5 && page.height_points == 400.25);
    page = page_record();
    CHECK_STATUS(ARC_NOT_FOUND, arc_pdf_page_info(document.handle, 2, &page));
    CHECK(page.width_points == 0 && page.height_points == 0);
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_page_info(document.handle, 0, nullptr));
    arc_pdf_page_v1 small = page_record();
    small.struct_size = 16;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_page_info(document.handle, 0, &small));
    arc_pdf_page_v1 future = page_record();
    future.struct_version = 2;
    CHECK_STATUS(ARC_VERSION_MISMATCH, arc_pdf_page_info(document.handle, 0, &future));
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    const auto hostile = [](page_geometry geometry) {
        reset({page_with(u"a", {}, geometry)});
        const opened doc = open_ok();
        arc_pdf_page_v1 record = page_record();
        const arc_status_t status = arc_pdf_page_info(doc.handle, 0, &record);
        CHECK(record.width_points == 0 && record.height_points == 0 && record.rotation == 0);
        CHECK_STATUS(ARC_OK, arc_pdf_close(doc.handle));
        return status;
    };
    CHECK_STATUS(ARC_CORRUPT, hostile({0, std::nan(""), 792.0}));
    CHECK_STATUS(ARC_CORRUPT, hostile({0, 612.0, std::numeric_limits<double>::infinity()}));
    CHECK_STATUS(ARC_CORRUPT, hostile({0, 0.0, 792.0}));
    CHECK_STATUS(ARC_CORRUPT, hostile({0, -5.0, 792.0}));
    CHECK_STATUS(ARC_CORRUPT, hostile({0, 2000000.0, 792.0}));
    CHECK_STATUS(ARC_CORRUPT, hostile({45, 612.0, 792.0}));
    CHECK_STATUS(ARC_CORRUPT, hostile({360, 612.0, 792.0}));

    reset({page_with(u"a")});
    g_script->geometry_status = ARC_CORRUPT;
    const opened failing = open_ok();
    arc_pdf_page_v1 record = page_record();
    CHECK_STATUS(ARC_CORRUPT, arc_pdf_page_info(failing.handle, 0, &record));
    CHECK_STATUS(ARC_OK, arc_pdf_close(failing.handle));
}

void test_text_basic_and_paging()
{
    reset({page_with(u"hello world", {{0, 5, 1, 2, 3, 4}, {6, 5, 10.5, 2, 30, 4}})});
    const opened document = open_ok();
    arc_status_t status = ARC_OK;
    std::string json = fetch_text(document.handle, 0, 0, 65536, &status);
    CHECK_STATUS(ARC_OK, status);
    CHECK(json == "{\"version\":1,\"page\":0,\"start\":0,\"text\":\"hello world\",\"boxes\":["
                  "{\"start\":0,\"length\":5,\"x\":1,\"y\":2,\"width\":3,\"height\":4},"
                  "{\"start\":6,\"length\":5,\"x\":10.5,\"y\":2,\"width\":30,\"height\":4}]}");
    // Chunk of five: only the box wholly inside; next points at the following position.
    json = fetch_text(document.handle, 0, 0, 5, &status);
    CHECK_STATUS(ARC_OK, status);
    CHECK(json == "{\"version\":1,\"page\":0,\"start\":0,\"next\":5,\"text\":\"hello\",\"boxes\":["
                  "{\"start\":0,\"length\":5,\"x\":1,\"y\":2,\"width\":3,\"height\":4}]}");
    json = fetch_text(document.handle, 0, 5, 3, &status);
    CHECK(json == "{\"version\":1,\"page\":0,\"start\":5,\"next\":8,\"text\":\" wo\",\"boxes\":[]}");
    json = fetch_text(document.handle, 0, 8, 100, &status);
    CHECK(json == "{\"version\":1,\"page\":0,\"start\":8,\"text\":\"rld\",\"boxes\":[]}");
    json = fetch_text(document.handle, 0, 11, 10, &status); // at the end: empty chunk, no next
    CHECK_STATUS(ARC_OK, status);
    CHECK(json == "{\"version\":1,\"page\":0,\"start\":11,\"text\":\"\",\"boxes\":[]}");

    CHECK_STATUS(ARC_INVALID_ARGUMENT, [&] { fetch_text(document.handle, 0, 12, 10, &status); return status; }());
    CHECK_STATUS(ARC_INVALID_ARGUMENT, [&] { fetch_text(document.handle, 0, 0, 0, &status); return status; }());
    CHECK_STATUS(ARC_INVALID_ARGUMENT, [&] { fetch_text(document.handle, 0, 0, 65537, &status); return status; }());
    CHECK_STATUS(ARC_NOT_FOUND, [&] { fetch_text(document.handle, 1, 0, 10, &status); return status; }());

    // Too-small buffer reports the exact size and writes nothing; the retry succeeds with the same size.
    char small[8] = {};
    arc_mut_buffer_t tight{small, sizeof(small), 0};
    CHECK_STATUS(ARC_BUFFER_TOO_SMALL, arc_pdf_text(document.handle, 0, 0, 65536, &tight, nullptr));
    CHECK(tight.required > sizeof(small) && small[0] == '\0');
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_text(document.handle, 0, 0, 10, nullptr, nullptr));
    arc_mut_buffer_t nulldata{nullptr, 5, 0};
    CHECK_STATUS(ARC_INVALID_ARGUMENT, arc_pdf_text(document.handle, 0, 0, 10, &nulldata, nullptr));
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));
}

void test_text_surrogates_and_escaping()
{
    const std::u16string text = u"a" + pair + u"b" + pair;
    reset({page_with(text, {{0, 1, 0, 0, 1, 1}, {1, 2, 1, 0, 2, 1}})});
    const opened document = open_ok();
    arc_status_t status = ARC_OK;
    // A one-unit window that lands on a pair takes the whole pair so every chunk makes progress.
    std::string json = fetch_text(document.handle, 0, 1, 1, &status);
    CHECK_STATUS(ARC_OK, status);
    CHECK(json.find("\"next\":3") != std::string::npos);
    CHECK(json.find("\"text\":\"\xF0\x9F\x98\x80\"") != std::string::npos);
    // A window that would end inside the pair backs up before it.
    json = fetch_text(document.handle, 0, 0, 2, &status);
    CHECK(json.find("\"next\":1") != std::string::npos && json.find("\"text\":\"a\"") != std::string::npos);
    // A start inside the pair is refused.
    CHECK_STATUS(ARC_INVALID_ARGUMENT, [&] { fetch_text(document.handle, 0, 2, 5, &status); return status; }());
    // Walking the whole page by 2-unit windows reproduces the text exactly.
    std::string rebuilt;
    uint32_t start = 0;
    for (int guard = 0; guard < 100; ++guard) {
        json = fetch_text(document.handle, 0, start, 2, &status);
        CHECK_STATUS(ARC_OK, status);
        const size_t open = json.find("\"text\":\"") + 8;
        const size_t close = json.find("\",\"boxes\"");
        rebuilt += json.substr(open, close - open);
        const size_t next = json.find("\"next\":");
        if (next == std::string::npos || next > json.find("\"text\"")) {
            break;
        }
        start = static_cast<uint32_t>(std::stoul(json.substr(next + 7)));
    }
    CHECK(rebuilt == "a\xF0\x9F\x98\x80" "b\xF0\x9F\x98\x80");
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    const std::u16string odd = std::u16string(u"q\"\\\n") + char16_t(0x01) + char16_t(0xD800) + u"x" + char16_t(0xDC00) + char16_t(0x00E9);
    reset({page_with(odd)});
    const opened escaped = open_ok();
    json = fetch_text(escaped.handle, 0, 0, 100, &status);
    CHECK_STATUS(ARC_OK, status);
    CHECK(json == "{\"version\":1,\"page\":0,\"start\":0,\"text\":\"q\\\"\\\\\\u000a\\u0001\xEF\xBF\xBD" "x\xEF\xBF\xBD\xC3\xA9\",\"boxes\":[]}");
    CHECK_STATUS(ARC_OK, arc_pdf_close(escaped.handle));
}

void test_text_limits_and_hostile_backend()
{
    // Box budget: with max_items 2 a chunk of five boxes is cut before the third box.
    reset({page_with(u"aa bb cc dd ee", {{0, 2, 0, 0, 1, 1}, {3, 2, 0, 0, 1, 1}, {6, 2, 0, 0, 1, 1}, {9, 2, 0, 0, 1, 1}, {12, 2, 0, 0, 1, 1}})});
    opened document = open_ok(limits_for(5000, 2));
    arc_status_t status = ARC_OK;
    std::string json = fetch_text(document.handle, 0, 0, 65536, &status);
    CHECK_STATUS(ARC_OK, status);
    CHECK(json.find("\"next\":6") != std::string::npos);
    CHECK(json.find("\"start\":3,\"length\":2") != std::string::npos && json.find("\"start\":6,\"length\":2") == std::string::npos);
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    // Many boxes at the very start of a window still make progress.
    reset({page_with(u"abcd", {{0, 1, 0, 0, 1, 1}, {0, 1, 0, 0, 1, 1}, {0, 2, 0, 0, 1, 1}})});
    document = open_ok(limits_for(5000, 2));
    json = fetch_text(document.handle, 0, 0, 4, &status);
    CHECK_STATUS(ARC_OK, status); // progress by one unit; a box that crosses the chunk end is not carried (documented pager rule)
    CHECK(json.find("\"next\":1") != std::string::npos);
    CHECK(json.find("\"length\":2") == std::string::npos);
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    const auto hostile = [](std::u16string text, std::vector<text_box> boxes) {
        reset({page_with(text, std::move(boxes))});
        const opened doc = open_ok();
        arc_status_t status = ARC_OK;
        const std::string json = fetch_text(doc.handle, 0, 0, 100, &status);
        CHECK(json.empty());
        CHECK_STATUS(ARC_OK, arc_pdf_close(doc.handle));
        return status;
    };
    CHECK_STATUS(ARC_CORRUPT, hostile(u"abc", {{2, 1, 0, 0, 1, 1}, {0, 1, 0, 0, 1, 1}}));              // unordered
    CHECK_STATUS(ARC_CORRUPT, hostile(u"abc", {{2, 5, 0, 0, 1, 1}}));                                   // past the text
    CHECK_STATUS(ARC_CORRUPT, hostile(u"abc", {{0, 0, 0, 0, 1, 1}}));                                   // empty box
    CHECK_STATUS(ARC_CORRUPT, hostile(u"abc", {{0, 1, std::nan(""), 0, 1, 1}}));                        // not finite
    CHECK_STATUS(ARC_CORRUPT, hostile(u"abc", {{0, 1, 0, 0, -1, 1}}));                                  // negative extent
    CHECK_STATUS(ARC_CORRUPT, hostile(u"abc", {{0, 1, 0, 0, std::numeric_limits<double>::infinity(), 1}}));
    CHECK_STATUS(ARC_RESOURCE_LIMIT, hostile(std::u16string((16U * 1024 * 1024) + 1, u'x'), {}));

    reset({page_with(u"abc")});
    g_script->text_status = ARC_CORRUPT;
    document = open_ok();
    CHECK_STATUS(ARC_CORRUPT, [&] { fetch_text(document.handle, 0, 0, 10, &status); return status; }());
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    // The page text is fetched once and reused across chunks of the same page.
    reset({page_with(u"abcdef"), page_with(u"ghi")});
    document = open_ok();
    for (uint32_t start = 0; start < 6; ++start) {
        fetch_text(document.handle, 0, start, 1, &status);
        CHECK_STATUS(ARC_OK, status);
    }
    CHECK(g_script->text_calls == 1);
    fetch_text(document.handle, 1, 0, 1, &status);
    CHECK(g_script->text_calls == 2);
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));
}

void test_render()
{
    reset({page_with(u"a"), page_with(u"b", {}, {90, 300.0, 400.0})});
    const opened document = open_ok();
    arc_pdf_page_v1 page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(document.handle, 1, &page));

    // 4x2 tile at (10, 20) of a 100x200 grid, packed.
    const arc_region_v1 tile = region_of(10, 20, 4, 2);
    std::vector<uint8_t> pixels(4 * 4 * 2, 0xEE);
    arc_mut_buffer_t buffer{pixels.data(), pixels.size(), 0};
    CHECK_STATUS(ARC_OK, arc_pdf_render(document.handle, &page, &tile, 100, 200, &buffer, nullptr));
    CHECK(buffer.required == 32);
    CHECK(pixels[0] == 10 && pixels[1] == 20 && pixels[2] == 1 && pixels[3] == 255);
    CHECK(pixels[4 * 4 + 0] == 10 && pixels[4 * 4 + 1] == 21);
    CHECK(pixels[(4 * 4 + 3 * 4) + 0] == 13);

    // A stride wider than the row: required covers (height - 1) strides plus one row, and no byte past it is touched.
    const arc_region_v1 strided = region_of(0, 0, 3, 2, 20);
    std::vector<uint8_t> big(64, 0xEE);
    arc_mut_buffer_t strided_buffer{big.data(), big.size(), 0};
    CHECK_STATUS(ARC_OK, arc_pdf_render(document.handle, &page, &strided, 100, 200, &strided_buffer, nullptr));
    CHECK(strided_buffer.required == 20 + 12);
    CHECK(big[31] == 255 && big[32] == 0xEE && big[63] == 0xEE);
    CHECK(big[12] == 0xEE); // the gap between rows is not written

    // Too small: exact required size reported, nothing written.
    std::vector<uint8_t> tiny(8, 0xEE);
    arc_mut_buffer_t tiny_buffer{tiny.data(), tiny.size(), 0};
    CHECK_STATUS(ARC_BUFFER_TOO_SMALL, arc_pdf_render(document.handle, &page, &tile, 100, 200, &tiny_buffer, nullptr));
    CHECK(tiny_buffer.required == 32 && tiny[0] == 0xEE);

    // Validation.
    const auto render = [&](const arc_region_v1& region, uint32_t width, uint32_t height, const arc_pdf_page_v1* record = nullptr) {
        std::vector<uint8_t> out(1 << 20, 0xEE);
        arc_mut_buffer_t b{out.data(), out.size(), 0};
        const arc_status_t status = arc_pdf_render(document.handle, record == nullptr ? &page : record, &region, width, height, &b, nullptr);
        if (status != ARC_OK) {
            CHECK(std::all_of(out.begin(), out.end(), [](uint8_t v) { return v == 0xEE || v == 0; }));
        }
        return status;
    };
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(0, 0, 0, 4), 100, 100));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(0, 0, 4, 0), 100, 100));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(0, 0, 4, 4), 0, 100));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(98, 0, 4, 4), 100, 100));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(0, 98, 4, 4), 100, 100));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(UINT32_MAX, 0, 4, 4), 100, 100));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(0, 0, 4, 4, 15), 100, 100));
    arc_region_v1 samples = region_of(0, 0, 4, 4);
    samples.first_sample = 1;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(samples, 100, 100));
    arc_region_v1 bad_record = region_of(0, 0, 4, 4);
    bad_record.struct_version = 3;
    CHECK_STATUS(ARC_VERSION_MISMATCH, render(bad_record, 100, 100));
    CHECK_STATUS(ARC_RESOURCE_LIMIT, render(region_of(0, 0, 4, 4), 16385, 100));
    CHECK_STATUS(ARC_RESOURCE_LIMIT, render(region_of(0, 0, 4, 4), 100, 16385));
    arc_pdf_page_v1 scaled = page;
    scaled.width_points *= 2;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(0, 0, 4, 4), 100, 100, &scaled));
    arc_pdf_page_v1 rotated = page;
    rotated.rotation = 0;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, render(region_of(0, 0, 4, 4), 100, 100, &rotated));
    arc_pdf_page_v1 other = page;
    other.page_index = 7;
    CHECK_STATUS(ARC_NOT_FOUND, render(region_of(0, 0, 4, 4), 100, 100, &other));
    CHECK_STATUS(ARC_INVALID_ARGUMENT, [&] {
        arc_mut_buffer_t none{};
        return arc_pdf_render(document.handle, nullptr, &tile, 100, 200, &none, nullptr);
    }());
    CHECK_STATUS(ARC_INVALID_ARGUMENT, [&] { return arc_pdf_render(document.handle, &page, &tile, 100, 200, nullptr, nullptr); }());
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    // A grid beyond the pixel bound even though each side is within the dimension limit.
    arc_limits_v1 wide = limits_for();
    wide.max_width = 65535;
    wide.max_height = 65535;
    reset({page_with(u"a")});
    const opened huge = open_ok(wide);
    arc_pdf_page_v1 huge_page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(huge.handle, 0, &huge_page));
    std::vector<uint8_t> small_out(64);
    arc_mut_buffer_t small_buffer{small_out.data(), small_out.size(), 0};
    const arc_region_v1 corner = region_of(0, 0, 2, 2);
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_render(huge.handle, &huge_page, &corner, 20000, 20000, &small_buffer, nullptr));
    CHECK(g_script->render_calls == 0);
    CHECK_STATUS(ARC_OK, arc_pdf_close(huge.handle));

    // The output limit: a tile larger than max_output_bytes is refused before the backend is called.
    arc_limits_v1 narrow = limits_for();
    narrow.max_output_bytes = 16;
    reset({page_with(u"a")});
    const opened bounded = open_ok(narrow);
    arc_pdf_page_v1 bounded_page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(bounded.handle, 0, &bounded_page));
    std::vector<uint8_t> room(64);
    arc_mut_buffer_t room_buffer{room.data(), room.size(), 0};
    const arc_region_v1 five = region_of(0, 0, 5, 1);
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_render(bounded.handle, &bounded_page, &five, 100, 100, &room_buffer, nullptr));
    CHECK(g_script->render_calls == 0);
    CHECK_STATUS(ARC_OK, arc_pdf_close(bounded.handle));
}

void test_render_failures_leave_no_partial_output()
{
    reset({page_with(u"a")});
    g_script->render_fails_after_writing = true;
    opened document = open_ok();
    arc_pdf_page_v1 page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(document.handle, 0, &page));
    const arc_region_v1 tile = region_of(0, 0, 8, 8);
    std::vector<uint8_t> out(8 * 8 * 4 + 16, 0xEE);
    arc_mut_buffer_t buffer{out.data(), out.size(), 0};
    CHECK_STATUS(ARC_CORRUPT, arc_pdf_render(document.handle, &page, &tile, 64, 64, &buffer, nullptr));
    CHECK(g_script->render_calls == 1);
    CHECK(std::all_of(out.begin(), out.begin() + 8 * 8 * 4, [](uint8_t v) { return v == 0; })); // pixels wiped
    CHECK(out[8 * 8 * 4] == 0xEE);                                                              // nothing past the tile touched
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    reset({page_with(u"a")});
    g_script->throw_on_render = true;
    document = open_ok();
    page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(document.handle, 0, &page));
    out.assign(out.size(), 0xEE);
    buffer = {out.data(), out.size(), 0};
    CHECK_STATUS(ARC_INTERNAL, arc_pdf_render(document.handle, &page, &tile, 64, 64, &buffer, nullptr));
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));
}

void test_cancellation_and_deadline()
{
    // Cancelled before the call: the backend is never reached.
    reset({page_with(u"a")});
    counting_cancel now_cancelled{0, -1};
    arc_cancel_token_t token = token_for(now_cancelled);
    input_bytes input{"FAKEPDF1\nbody"};
    opened out;
    CHECK_STATUS(ARC_CANCELLED, open_document(input, out, limits_for(), {}, &token));
    CHECK(g_script->alive_documents == 0 && out.handle == 0);

    arc_cancel_token_t invalid = token;
    invalid.struct_size = 8;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, open_document(input, out, limits_for(), {}, &invalid));
    arc_cancel_token_t no_callback = token;
    no_callback.is_cancelled = nullptr;
    CHECK_STATUS(ARC_INVALID_ARGUMENT, open_document(input, out, limits_for(), {}, &no_callback));

    // A parser that spins is stopped by a cancellation that arrives mid-call.
    reset({page_with(u"a")});
    g_script->open_hangs_until_stopped = true;
    counting_cancel later{0, 20};
    token = token_for(later);
    CHECK_STATUS(ARC_CANCELLED, open_document(input, out, limits_for(), {}, &token));
    CHECK(later.polls > 20 && g_script->alive_documents == 0);

    // The deadline stops a spinning parser with no cancellation at all.
    reset({page_with(u"a")});
    g_script->open_hangs_until_stopped = true;
    const auto before = std::chrono::steady_clock::now();
    CHECK_STATUS(ARC_RESOURCE_LIMIT, open_document(input, out, limits_for(100)));
    const auto elapsed = std::chrono::steady_clock::now() - before;
    CHECK(elapsed >= std::chrono::milliseconds(90) && elapsed < std::chrono::seconds(10));

    // A render that spins is cancelled and its buffer is wiped; a render that ignores the deadline is refused afterwards.
    reset({page_with(u"a")});
    g_script->render_hangs_until_stopped = true;
    opened document = open_ok();
    arc_pdf_page_v1 page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(document.handle, 0, &page));
    const arc_region_v1 tile = region_of(0, 0, 4, 4);
    std::vector<uint8_t> pixels(64, 0xEE);
    arc_mut_buffer_t buffer{pixels.data(), pixels.size(), 0};
    counting_cancel render_cancel{0, 10};
    token = token_for(render_cancel);
    CHECK_STATUS(ARC_CANCELLED, arc_pdf_render(document.handle, &page, &tile, 64, 64, &buffer, &token));
    CHECK(std::all_of(pixels.begin(), pixels.end(), [](uint8_t v) { return v == 0; }));
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    reset({page_with(u"a")});
    g_script->render_ignores_deadline_ms = true;
    g_script->render_sleep_ms = 250;
    document = open_ok(limits_for(60));
    page = page_record();
    CHECK_STATUS(ARC_OK, arc_pdf_page_info(document.handle, 0, &page));
    pixels.assign(64, 0xEE);
    buffer = {pixels.data(), pixels.size(), 0};
    CHECK_STATUS(ARC_RESOURCE_LIMIT, arc_pdf_render(document.handle, &page, &tile, 64, 64, &buffer, nullptr));
    CHECK(std::all_of(pixels.begin(), pixels.end(), [](uint8_t v) { return v == 0; }));
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));

    // Text honours a token too.
    reset({page_with(u"abc")});
    document = open_ok();
    counting_cancel text_cancel{0, -1};
    token = token_for(text_cancel);
    arc_mut_buffer_t query{};
    CHECK_STATUS(ARC_CANCELLED, arc_pdf_text(document.handle, 0, 0, 10, &query, &token));
    CHECK(g_script->text_calls == 0);
    CHECK_STATUS(ARC_OK, arc_pdf_close(document.handle));
}

void test_concurrent_use_and_close()
{
    reset({page_with(u"abcdefghij", {{0, 3, 0, 0, 1, 1}})});
    const opened document = open_ok();
    std::atomic<int> successes{0};
    std::atomic<int> closed{0};
    std::atomic<int> unexpected{0};
    std::vector<std::thread> workers;
    for (int t = 0; t < 8; ++t) {
        workers.emplace_back([&] {
            for (int i = 0; i < 300; ++i) {
                arc_status_t status = ARC_OK;
                const std::string json = fetch_text(document.handle, 0, static_cast<uint32_t>(i % 5), 4, &status);
                if (status == ARC_OK && !json.empty()) {
                    ++successes;
                } else if (status == ARC_CLOSED) {
                    ++closed;
                } else {
                    ++unexpected;
                }
            }
        });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const arc_status_t close_status = arc_pdf_close(document.handle);
    for (std::thread& worker : workers) {
        worker.join();
    }
    CHECK_STATUS(ARC_OK, close_status);
    CHECK(unexpected == 0 && successes + closed == 8 * 300 && successes > 0);
    CHECK(g_script->alive_documents == 0);
}

} // namespace

std::shared_ptr<arc::pdf::backend> arc::pdf::linked_backend()
{
    return g_backend;
}

int main()
{
    test_preamble();
    test_open_validation();
    test_open_backend_behaviour();
    test_io_callbacks();
    test_handle_lifetime();
    test_page_info();
    test_text_basic_and_paging();
    test_text_surrogates_and_escaping();
    test_text_limits_and_hostile_backend();
    test_render();
    test_render_failures_leave_no_partial_output();
    test_cancellation_and_deadline();
    test_concurrent_use_and_close();
    if (g_failures != 0) {
        std::fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    std::puts("arcpdf_abi_engine_tests: all checks passed");
    return 0;
}
