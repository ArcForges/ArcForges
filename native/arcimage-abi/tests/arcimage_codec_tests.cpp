// SPDX-License-Identifier: AGPL-3.0-only
// Behavioural and failure tests for the functional ArcImageNative codec family. Fixtures are generated
// in memory by OpenImageIO writers during the run and are never shipped (decision D1).
#include <arc/arc_slate_image_abi.h>

#include <OpenImageIO/filesystem.h>
#include <OpenImageIO/imageio.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

int failures = 0;
int checks = 0;

void expect(bool condition, const char* what)
{
    ++checks;
    if (!condition) {
        ++failures;
        std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

bool contains(const std::string& text, const char* needle)
{
    return text.find(needle) != std::string::npos;
}

// In-memory source served through the arc_io_v1 callbacks. Failure modes are injected per call.
struct source {
    const std::vector<unsigned char>* bytes = nullptr;
    int calls = 0;
    int fail_after = -1;
    int short_after = -1;
    int sleep_ms = 0;
};

arc_status_t ARC_ABI_CALL read_at(void* context, uint64_t offset, void* destination, uint64_t requested,
                                  uint64_t* done)
{
    auto* state = static_cast<source*>(context);
    ++state->calls;
    *done = 0;
    if (state->fail_after >= 0 && state->calls > state->fail_after) {
        return ARC_IO;
    }
    if (state->sleep_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(state->sleep_ms));
    }
    const uint64_t size = state->bytes->size();
    if (offset >= size) {
        return ARC_OK;
    }
    uint64_t count = std::min<uint64_t>(requested, size - offset);
    if (state->short_after >= 0 && state->calls > state->short_after && count > 1) {
        count /= 2; // a short read that is not at the end of the source
    }
    std::memcpy(destination, state->bytes->data() + offset, static_cast<size_t>(count));
    *done = count;
    return ARC_OK;
}

arc_io_v1 make_io(source& state)
{
    arc_io_v1 io{};
    io.struct_size = sizeof(arc_io_v1);
    io.struct_version = 1;
    io.context = &state;
    io.length = state.bytes->size();
    io.max_length = io.length;
    io.read_at = read_at;
    return io;
}

struct cancel_state {
    int calls = 0;
    int cancel_from = -1;
};

arc_bool_t ARC_ABI_CALL is_cancelled(void* user_data)
{
    auto* state = static_cast<cancel_state*>(user_data);
    ++state->calls;
    return (state->cancel_from >= 0 && state->calls >= state->cancel_from) ? 1 : 0;
}

arc_cancel_token_t make_token(cancel_state& state)
{
    arc_cancel_token_t token{};
    token.struct_size = sizeof(arc_cancel_token_t);
    token.struct_version = 1;
    token.is_cancelled = is_cancelled;
    token.user_data = &state;
    return token;
}

arc_image_options_v1 make_options(uint32_t format, uint32_t subimage = 0, uint32_t mip = 0)
{
    arc_image_options_v1 options{};
    options.struct_size = sizeof(arc_image_options_v1);
    options.struct_version = 1;
    options.subimage = subimage;
    options.mip = mip;
    options.format = format;
    options.limits.struct_size = sizeof(arc_limits_v1);
    options.limits.struct_version = 1;
    options.limits.max_input_bytes = UINT64_C(1) << 30;
    options.limits.max_memory_bytes = UINT64_C(1) << 30;
    options.limits.max_output_bytes = UINT64_C(64) << 20;
    options.limits.max_width = 65535;
    options.limits.max_height = 65535;
    options.limits.max_items = 64;
    options.limits.timeout_ms = 60000;
    return options;
}

arc_status_t open_image(const arc_io_v1& io, const arc_image_options_v1& options, const arc_cancel_token_t* cancel,
                        arc_handle_t& handle, std::string& metadata, size_t metadata_capacity = 65536)
{
    std::vector<char> buffer(metadata_capacity);
    arc_mut_buffer_t output{};
    output.data = buffer.data();
    output.capacity = buffer.size();
    const arc_status_t status = arc_image_open(&io, &options, &handle, &output, cancel);
    if (status == ARC_OK) {
        metadata.assign(buffer.data(), static_cast<size_t>(output.required));
    }
    return status;
}

arc_status_t read_region(arc_handle_t handle, uint32_t x, uint32_t y, uint32_t w, uint32_t h, size_t bytes_per_pixel,
                         std::vector<uint8_t>& pixels, const arc_cancel_token_t* cancel = nullptr)
{
    arc_region_v1 region{};
    region.struct_size = sizeof(arc_region_v1);
    region.struct_version = 1;
    region.x = x;
    region.y = y;
    region.width = w;
    region.height = h;
    pixels.assign(static_cast<size_t>(w) * h * bytes_per_pixel, 0);
    arc_mut_buffer_t output{};
    output.data = pixels.data();
    output.capacity = pixels.size();
    return arc_image_read(handle, &region, &output, cancel);
}

// Encodes an in-memory image with an OpenImageIO writer. The writer uses the same proxy path as the reader.
std::vector<unsigned char> encode(const char* hint, const OIIO::ImageSpec& spec, OIIO::TypeDesc type, const void* pixels)
{
    std::vector<unsigned char> bytes;
    OIIO::Filesystem::IOVecOutput proxy(bytes);
    auto output = OIIO::ImageOutput::create(hint, &proxy);
    if (!output) {
        return {};
    }
    if (!output->open(hint, spec)) {
        return {};
    }
    output->write_image(type, pixels);
    output->close();
    return bytes;
}

std::vector<uint8_t> rgba_pattern(uint32_t width, uint32_t height, uint32_t channels)
{
    std::vector<uint8_t> pixels(static_cast<size_t>(width) * height * channels);
    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            for (uint32_t c = 0; c < channels; ++c) {
                pixels[(static_cast<size_t>(y) * width + x) * channels + c] =
                    static_cast<uint8_t>((x * 37U + y * 91U + c * 53U) & 255U);
            }
        }
    }
    return pixels;
}

OIIO::ImageSpec rgba8_spec(uint32_t width, uint32_t height)
{
    OIIO::ImageSpec spec(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::UINT8);
    spec.channelnames = {"R", "G", "B", "A"};
    spec.alpha_channel = 3;
    return spec;
}

std::vector<unsigned char> encode_png_rgba8(uint32_t width, uint32_t height, const std::vector<uint8_t>& pixels)
{
    return encode("fixture.png", rgba8_spec(width, height), OIIO::TypeDesc::UINT8, pixels.data());
}

uint32_t crc32(const unsigned char* data, size_t count)
{
    uint32_t value = 0xFFFFFFFFU;
    for (size_t index = 0; index < count; ++index) {
        value ^= data[index];
        for (int bit = 0; bit < 8; ++bit) {
            value = (value >> 1U) ^ (0xEDB88320U & (0U - (value & 1U)));
        }
    }
    return ~value;
}

void append_be32(std::vector<unsigned char>& out, uint32_t value)
{
    out.push_back(static_cast<unsigned char>(value >> 24U));
    out.push_back(static_cast<unsigned char>(value >> 16U));
    out.push_back(static_cast<unsigned char>(value >> 8U));
    out.push_back(static_cast<unsigned char>(value));
}

void append_chunk(std::vector<unsigned char>& out, const char* type, const std::vector<unsigned char>& data)
{
    append_be32(out, static_cast<uint32_t>(data.size()));
    const size_t start = out.size();
    out.insert(out.end(), type, type + 4);
    out.insert(out.end(), data.begin(), data.end());
    append_be32(out, crc32(out.data() + start, out.size() - start));
}

// A PNG whose header declares a 65535 x 65535 RGBA image with no real pixel data. It is refused from
// the header alone, before any decode allocation.
std::vector<unsigned char> decompression_bomb_png()
{
    std::vector<unsigned char> bytes = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    std::vector<unsigned char> header;
    append_be32(header, 65535);
    append_be32(header, 65535);
    header.push_back(8);
    header.push_back(6);
    header.push_back(0);
    header.push_back(0);
    header.push_back(0);
    append_chunk(bytes, "IHDR", header);
    // One empty zlib stored block, so the stream is structurally complete but holds no pixel data.
    append_chunk(bytes, "IDAT", {0x78, 0x01, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01});
    append_chunk(bytes, "IEND", {});
    return bytes;
}


// ---- Tests -------------------------------------------------------------------------------------

void test_probe_and_build_info()
{
    uint32_t major = 0;
    uint32_t minor = 0;
    expect(arc_image_get_abi_version(&major, &minor) == ARC_OK && major == 1 && minor == 1,
           "functional image ABI reports major 1 minor 1");
    expect(arc_image_get_abi_version(nullptr, &minor) == ARC_INVALID_ARGUMENT, "null version output is refused");

    arc_mut_buffer_t query{};
    expect(arc_image_get_build_info(&query) == ARC_BUFFER_TOO_SMALL && query.required > 0,
           "build info reports its size");
    std::vector<char> text(static_cast<size_t>(query.required));
    arc_mut_buffer_t output{};
    output.data = text.data();
    output.capacity = text.size();
    expect(arc_image_get_build_info(&output) == ARC_OK, "build info copies");
    const std::string json(text.data(), text.size());
    expect(contains(json, "\"capabilities\":[\"image.open\",\"image.read\",\"image.close\"]"),
           "build info carries the closed capability list");
    expect(contains(json, "\"formats\":[\"png\",\"tiff\",\"exr\"]"), "build info carries the format allowlist");
}

void test_png_rgba8_round_trip()
{
    const uint32_t width = 7;
    const uint32_t height = 5;
    const std::vector<uint8_t> source = rgba_pattern(width, height, 4);
    const auto bytes = encode_png_rgba8(width, height, source);
    expect(!bytes.empty(), "PNG fixture encodes");

    struct source state {};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    const arc_status_t status = open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata);
    expect(status == ARC_OK && handle != 0, "PNG opens as rgba8");
    expect(contains(metadata, "\"format\":\"png\"") && contains(metadata, "\"outputFormat\":\"rgba8\""),
           "metadata names the codec and output format");
    expect(contains(metadata, "\"premultiplyOnRead\"") && contains(metadata, "\"unpremultiply\""),
           "straight PNG alpha is associated on read and unpremultiplied for rgba8");
    expect(contains(metadata, "\"unpremultiplyPrecision\""), "rgba8 output from alpha reports the precision loss");

    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_OK, "full-image region reads");
    expect(pixels == source, "8-bit RGBA round trip is byte exact");
    expect(arc_image_close(handle) == ARC_OK, "image closes");
    expect(arc_image_close(handle) == ARC_CLOSED, "double close reports CLOSED");
}

void test_png_rgb_fills_alpha()
{
    const uint32_t width = 4;
    const uint32_t height = 3;
    const std::vector<uint8_t> rgb = rgba_pattern(width, height, 3);
    OIIO::ImageSpec spec(static_cast<int>(width), static_cast<int>(height), 3, OIIO::TypeDesc::UINT8);
    spec.channelnames = {"R", "G", "B"};
    const auto bytes = encode("fixture.png", spec, OIIO::TypeDesc::UINT8, rgb.data());
    expect(!bytes.empty(), "RGB PNG fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK, "RGB PNG opens");
    expect(contains(metadata, "\"alpha\":\"none\"") && contains(metadata, "\"alphaFilled\""),
           "missing alpha is reported as filled");
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_OK, "RGB PNG reads as rgba8");
    bool exact = true;
    for (size_t pixel = 0; pixel < static_cast<size_t>(width) * height; ++pixel) {
        for (size_t c = 0; c < 3; ++c) {
            exact = exact && pixels[pixel * 4 + c] == rgb[pixel * 3 + c];
        }
        exact = exact && pixels[pixel * 4 + 3] == 255;
    }
    expect(exact, "RGB samples are preserved and alpha is filled with 255");
    arc_image_close(handle);
}

void test_png_16bit_reports_bit_depth_loss()
{
    const uint32_t width = 2;
    const uint32_t height = 2;
    std::vector<uint16_t> samples(static_cast<size_t>(width) * height * 4);
    for (size_t index = 0; index < samples.size(); ++index) {
        samples[index] = static_cast<uint16_t>(index * 4099U);
    }
    OIIO::ImageSpec spec(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::UINT16);
    spec.channelnames = {"R", "G", "B", "A"};
    spec.alpha_channel = 3;
    const auto bytes = encode("fixture.png", spec, OIIO::TypeDesc::UINT16, samples.data());
    expect(!bytes.empty(), "16-bit PNG fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK, "16-bit PNG opens");
    expect(contains(metadata, "\"bitDepthReduction\""), "16-bit to rgba8 reports bit-depth reduction");
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_OK, "16-bit PNG reads as rgba8");
    const double expected = samples[0] / 65535.0 * 255.0;
    expect(std::abs(static_cast<double>(pixels[0]) - expected) <= 1.0, "16-bit samples map to 8-bit within one step");
    arc_image_close(handle);
}

void test_png_linear_float_and_premultiply()
{
    const uint32_t width = 2;
    const uint32_t height = 1;
    // Two straight-alpha pixels: opaque white and white at alpha 128.
    const std::vector<uint8_t> pixels = {255, 255, 255, 255, 255, 255, 255, 128};
    const auto bytes = encode_png_rgba8(width, height, pixels);
    expect(!bytes.empty(), "straight-alpha PNG fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED), nullptr, handle, metadata) == ARC_OK,
           "PNG opens as linear premultiplied float");
    expect(contains(metadata, "\"premultiplyOnRead\""), "straight PNG alpha is associated on read");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, width, height, 16, raw) == ARC_OK, "float region reads");
    float values[8] = {};
    std::memcpy(values, raw.data(), sizeof(values));
    expect(std::abs(values[3] - 1.0F) < 1e-6F && std::abs(values[0] - 1.0F) < 1e-6F, "opaque pixel is unchanged");
    expect(std::abs(values[7] - 128.0F / 255.0F) < 1e-5F && std::abs(values[4] - 128.0F / 255.0F) < 1e-5F,
           "premultiplied colour equals colour times alpha");
    arc_image_close(handle);
}

void test_exr_float_round_trip()
{
    const uint32_t width = 5;
    const uint32_t height = 4;
    std::vector<float> samples(static_cast<size_t>(width) * height * 4);
    for (size_t index = 0; index < samples.size(); ++index) {
        samples[index] = static_cast<float>(index) * 0.25F - 3.0F;
    }
    OIIO::ImageSpec spec(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::FLOAT);
    spec.channelnames = {"R", "G", "B", "A"};
    spec.alpha_channel = 3;
    const auto bytes = encode("fixture.exr", spec, OIIO::TypeDesc::FLOAT, samples.data());
    expect(!bytes.empty(), "EXR fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED), nullptr, handle, metadata) == ARC_OK,
           "EXR opens as float32 interleaved");
    expect(contains(metadata, "\"format\":\"exr\"") && contains(metadata, "\"channelMapping\":\"named\""),
           "EXR metadata names the codec and mapping");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, width, height, 16, raw) == ARC_OK, "EXR float region reads");
    std::vector<float> decoded(samples.size());
    std::memcpy(decoded.data(), raw.data(), raw.size());
    expect(decoded == samples, "EXR float32 channels round trip exactly");
    arc_image_close(handle);
}

void test_exr_premultiplied_source_is_not_premultiplied_again()
{
    OIIO::ImageSpec spec(1, 1, 4, OIIO::TypeDesc::FLOAT);
    spec.channelnames = {"R", "G", "B", "A"};
    spec.alpha_channel = 3;
    const float pixel[4] = {0.4F, 0.4F, 0.4F, 0.5F};
    const auto bytes = encode("fixture.exr", spec, OIIO::TypeDesc::FLOAT, pixel);
    expect(!bytes.empty(), "premultiplied EXR fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED), nullptr, handle, metadata) == ARC_OK,
           "EXR opens as linear float");
    expect(!contains(metadata, "\"premultiply\"") && contains(metadata, "\"alpha\":\"premultiplied\""),
           "EXR associated alpha is not premultiplied again");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, 1, 1, 16, raw) == ARC_OK, "premultiplied EXR reads");
    float values[4] = {};
    std::memcpy(values, raw.data(), sizeof(values));
    expect(std::abs(values[0] - 0.4F) < 1e-6F && std::abs(values[3] - 0.5F) < 1e-6F,
           "associated colour and alpha pass through unchanged");
    arc_image_close(handle);
}

void test_tiled_tiff_edge_tiles_and_coverage()
{
    const uint32_t width = 40;
    const uint32_t height = 35;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    OIIO::ImageSpec spec = rgba8_spec(width, height);
    spec.tile_width = 16;
    spec.tile_height = 16;
    const auto bytes = encode("fixture.tif", spec, OIIO::TypeDesc::UINT8, source_pixels.data());
    expect(!bytes.empty(), "tiled TIFF fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK, "tiled TIFF opens");
    expect(contains(metadata, "\"tiled\":true") && contains(metadata, "\"tileWidth\":16"), "tiling is reported");

    // Tile-grid raster order, edge tiles included. Each region must match the source block exactly.
    bool blocks_match = true;
    for (uint32_t y = 0; y < height; y += 16) {
        for (uint32_t x = 0; x < width; x += 16) {
            const uint32_t w = std::min<uint32_t>(16, width - x);
            const uint32_t h = std::min<uint32_t>(16, height - y);
            std::vector<uint8_t> block;
            blocks_match = blocks_match && read_region(handle, x, y, w, h, 4, block) == ARC_OK;
            for (uint32_t row = 0; row < h; ++row) {
                const size_t source_offset = ((static_cast<size_t>(y) + row) * width + x) * 4;
                blocks_match = blocks_match && std::memcmp(block.data() + static_cast<size_t>(row) * w * 4,
                                                           source_pixels.data() + source_offset,
                                                           static_cast<size_t>(w) * 4) == 0;
            }
        }
    }
    expect(blocks_match, "tiled reads with edge tiles reproduce every pixel");

    // Coverage is complete now, so any further region overlaps covered pixels.
    std::vector<uint8_t> scratch;
    expect(read_region(handle, 0, 0, 4, 4, 4, scratch) == ARC_INVALID_ARGUMENT,
           "a region over covered pixels is refused");
    expect(read_region(handle, 40, 0, 1, 1, 4, scratch) == ARC_INVALID_ARGUMENT, "an out-of-bounds region is refused");
    arc_image_close(handle);
}

void test_coverage_order_and_no_state_change()
{
    const uint32_t width = 32;
    const uint32_t height = 16;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    const auto bytes = encode_png_rgba8(width, height, source_pixels);
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK, "PNG opens for coverage");

    std::vector<uint8_t> block;
    expect(read_region(handle, 16, 0, 16, 8, 4, block) == ARC_INVALID_ARGUMENT,
           "a region that skips the raster cursor is refused");
    expect(read_region(handle, 0, 0, 16, 8, 4, block) == ARC_OK, "the raster cursor region is accepted");
    expect(read_region(handle, 8, 0, 8, 8, 4, block) == ARC_INVALID_ARGUMENT, "an overlapping region is refused");
    expect(read_region(handle, 0, 8, 32, 8, 4, block) == ARC_INVALID_ARGUMENT,
           "a region below an uncovered row band is refused");
    expect(read_region(handle, 16, 0, 16, 8, 4, block) == ARC_OK, "refusals left the cursor unchanged");
    expect(read_region(handle, 0, 8, 32, 8, 4, block) == ARC_OK, "the next band completes the image");
    expect(read_region(handle, 0, 0, 32, 16, 4, block) == ARC_INVALID_ARGUMENT, "a complete image refuses more reads");
    arc_image_close(handle);
}

void test_buffer_too_small_consumes_nothing()
{
    const auto bytes = encode_png_rgba8(4, 4, rgba_pattern(4, 4, 4));
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    const arc_status_t short_metadata =
        open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata, 1);
    expect(short_metadata == ARC_BUFFER_TOO_SMALL && handle == 0, "a short metadata buffer consumes no handle");
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "the same open succeeds with a large buffer");

    arc_region_v1 region{};
    region.struct_size = sizeof(arc_region_v1);
    region.struct_version = 1;
    region.width = 4;
    region.height = 4;
    std::vector<uint8_t> small(8);
    arc_mut_buffer_t output{};
    output.data = small.data();
    output.capacity = small.size();
    expect(arc_image_read(handle, &region, &output, nullptr) == ARC_BUFFER_TOO_SMALL && output.required == 64,
           "a short pixel buffer reports the required size");
    std::vector<uint8_t> full;
    expect(read_region(handle, 0, 0, 4, 4, 4, full) == ARC_OK,
           "after a short buffer the same region still reads and was not consumed");
    arc_image_close(handle);
}

void test_unsupported_and_corrupt_content()
{
    const std::vector<unsigned char> bmp = {'B', 'M', 0, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0};
    const std::vector<unsigned char> jpeg = {0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, 'J', 'F', 'I', 'F'};
    const std::vector<unsigned char> text = {'h', 'e', 'l', 'l', 'o'};
    const std::vector<const std::vector<unsigned char>*> cases = {&bmp, &jpeg, &text};
    for (const auto* bytes : cases) {
        source state{};
        state.bytes = bytes;
        const arc_io_v1 io = make_io(state);
        arc_handle_t handle = 0xFF;
        std::string metadata;
        expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_UNSUPPORTED && handle == 0,
               "content outside the PNG, TIFF and EXR allowlist is unsupported with no handle");
    }

    const auto png = encode_png_rgba8(8, 8, rgba_pattern(8, 8, 4));
    std::vector<unsigned char> truncated(png.begin(), png.begin() + 40);
    source state{};
    state.bytes = &truncated;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    const arc_status_t status = open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata);
    expect((status == ARC_CORRUPT || status == ARC_IO) && handle == 0, "a truncated PNG is refused as corrupt");
}

void test_limits_and_decompression_bomb()
{
    const auto png = encode_png_rgba8(64, 64, rgba_pattern(64, 64, 4));
    source state{};
    state.bytes = &png;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;

    arc_image_options_v1 narrow = make_options(ARC_FORMAT_RGBA8);
    narrow.limits.max_width = 32;
    expect(open_image(io, narrow, nullptr, handle, metadata) == ARC_RESOURCE_LIMIT && handle == 0,
           "a width above the caller limit is refused before decode");

    arc_image_options_v1 tiny_memory = make_options(ARC_FORMAT_RGBA8);
    tiny_memory.limits.max_memory_bytes = 512;
    expect(open_image(io, tiny_memory, nullptr, handle, metadata) == ARC_RESOURCE_LIMIT && handle == 0,
           "a scanline band above the memory limit is refused before decode");

    arc_handle_t open_handle = 0;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, open_handle, metadata) == ARC_OK,
           "the fixture opens with defaults");
    arc_image_options_v1 zero_limit = make_options(ARC_FORMAT_RGBA8);
    zero_limit.limits.max_output_bytes = 0;
    expect(open_image(io, zero_limit, nullptr, handle, metadata) == ARC_INVALID_ARGUMENT,
           "a zero limit is refused as an invalid argument");
    arc_image_options_v1 above_profile = make_options(ARC_FORMAT_RGBA8);
    above_profile.limits.max_output_bytes = (UINT64_C(64) << 20) + 1;
    expect(open_image(io, above_profile, nullptr, handle, metadata) == ARC_INVALID_ARGUMENT,
           "a limit above the producer profile is refused");
    expect(arc_image_close(open_handle) == ARC_OK, "the default-limit handle closes");

    const auto bomb = decompression_bomb_png();
    source bomb_state{};
    bomb_state.bytes = &bomb;
    const arc_io_v1 bomb_io = make_io(bomb_state);
    const arc_status_t bomb_status = open_image(bomb_io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata);
    expect(bomb_status == ARC_RESOURCE_LIMIT && handle == 0,
           "a 65535 x 65535 PNG header is refused from the header alone");
}

void test_region_validation_and_output_limit()
{
    const auto png = encode_png_rgba8(8, 8, rgba_pattern(8, 8, 4));
    source state{};
    state.bytes = &png;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    arc_image_options_v1 capped = make_options(ARC_FORMAT_RGBA8);
    capped.limits.max_output_bytes = 16;
    expect(open_image(io, capped, nullptr, handle, metadata) == ARC_OK, "capped fixture opens");

    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, 4, 4, 4, pixels) == ARC_RESOURCE_LIMIT,
           "a region above the output limit is refused");
    expect(read_region(handle, 0, 0, 2, 2, 4, pixels) == ARC_OK, "a region within the output limit reads");
    arc_image_close(handle);

    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK, "fixture reopens");
    arc_region_v1 region{};
    region.struct_size = sizeof(arc_region_v1);
    region.struct_version = 1;
    region.width = 2;
    region.height = 2;
    region.first_sample = 1;
    arc_mut_buffer_t output{};
    output.data = pixels.data();
    output.capacity = pixels.size();
    expect(arc_image_read(handle, &region, &output, nullptr) == ARC_INVALID_ARGUMENT,
           "sample fields on an image region are refused");
    region.first_sample = 0;
    region.row_stride = 7;
    expect(arc_image_read(handle, &region, &output, nullptr) == ARC_INVALID_ARGUMENT,
           "a non-packed row stride is refused");
    arc_image_close(handle);
}

void test_options_and_subimage_selection()
{
    const auto png = encode_png_rgba8(4, 4, rgba_pattern(4, 4, 4));
    source state{};
    state.bytes = &png;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(0), nullptr, handle, metadata) == ARC_INVALID_ARGUMENT,
           "an unknown output format key is refused");
    arc_image_options_v1 reserved = make_options(ARC_FORMAT_RGBA8);
    reserved.reserved = 1;
    expect(open_image(io, reserved, nullptr, handle, metadata) == ARC_INVALID_ARGUMENT,
           "a non-zero reserved field is refused");
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8, 1, 0), nullptr, handle, metadata) == ARC_NOT_FOUND,
           "a missing subimage is not found");
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8, 0, 1), nullptr, handle, metadata) == ARC_NOT_FOUND,
           "a missing mip level is not found");
    expect(handle == 0, "failed opens leave no handle");
}

void test_cancellation_and_deadline()
{
    const auto png = encode_png_rgba8(16, 16, rgba_pattern(16, 16, 4));
    source state{};
    state.bytes = &png;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;

    cancel_state cancelled{};
    cancelled.cancel_from = 1;
    arc_cancel_token_t token = make_token(cancelled);
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), &token, handle, metadata) == ARC_CANCELLED && handle == 0,
           "a cancelled open returns CANCELLED with no handle");

    cancel_state later{};
    later.cancel_from = 6;
    arc_cancel_token_t late_token = make_token(later);
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK, "fixture opens");
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, 16, 8, 4, pixels, &late_token) == ARC_CANCELLED,
           "a read cancelled at a callback boundary returns CANCELLED");
    expect(read_region(handle, 0, 0, 16, 8, 4, pixels) == ARC_OK, "the cancelled read did not consume coverage");
    arc_image_close(handle);

    source slow{};
    slow.bytes = &png;
    slow.sleep_ms = 20;
    const arc_io_v1 slow_io = make_io(slow);
    arc_image_options_v1 quick = make_options(ARC_FORMAT_RGBA8);
    quick.limits.timeout_ms = 1;
    expect(open_image(slow_io, quick, nullptr, handle, metadata) == ARC_RESOURCE_LIMIT && handle == 0,
           "a deadline that expires during the open is refused");
}

void test_callback_failures()
{
    const auto png = encode_png_rgba8(16, 16, rgba_pattern(16, 16, 4));

    source failing{};
    failing.bytes = &png;
    failing.fail_after = 1;
    const arc_io_v1 failing_io = make_io(failing);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(failing_io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_IO && handle == 0,
           "a failing read callback surfaces as IO with no handle");

    source short_read{};
    short_read.bytes = &png;
    short_read.short_after = 1;
    const arc_io_v1 short_io = make_io(short_read);
    expect(open_image(short_io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) != ARC_OK && handle == 0,
           "a short read that is not at the end of the source is refused");

    source ok{};
    ok.bytes = &png;
    ok.fail_after = 0;
    const arc_io_v1 ok_io = make_io(ok);
    ok.fail_after = -1;
    expect(open_image(ok_io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "a source that succeeds opens");
    arc_image_close(handle);
}

void test_handle_lifecycle_and_limit()
{
    const auto png = encode_png_rgba8(4, 4, rgba_pattern(4, 4, 4));
    source state{};
    state.bytes = &png;
    const arc_io_v1 io = make_io(state);
    std::vector<arc_handle_t> handles;
    std::string metadata;
    for (int index = 0; index < 64; ++index) {
        arc_handle_t handle = 0;
        if (open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) != ARC_OK) {
            break;
        }
        handles.push_back(handle);
    }
    expect(handles.size() == 64, "64 image handles open per library context");
    arc_handle_t overflow = 0;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, overflow, metadata) == ARC_RESOURCE_LIMIT &&
               overflow == 0,
           "a 65th handle is refused with RESOURCE_LIMIT");
    for (const arc_handle_t handle : handles) {
        expect(arc_image_close(handle) == ARC_OK, "each handle closes once");
    }
    std::vector<uint8_t> pixels;
    expect(read_region(handles.front(), 0, 0, 1, 1, 4, pixels) == ARC_CLOSED, "a stale handle reads as CLOSED");
    expect(arc_image_close(0) == ARC_CLOSED, "the zero handle is never valid");

    arc_error_info_t error{};
    error.struct_size = sizeof(arc_error_info_t);
    error.struct_version = 1;
    uint8_t message[256] = {};
    error.message_utf8.data = message;
    error.message_utf8.capacity = sizeof(message);
    expect(arc_image_get_last_error(&error) == ARC_OK && error.correlation_id != 0,
           "the last error snapshot is readable after failures");
}

} // namespace

int main()
{
    test_probe_and_build_info();
    test_png_rgba8_round_trip();
    test_png_rgb_fills_alpha();
    test_png_16bit_reports_bit_depth_loss();
    test_png_linear_float_and_premultiply();
    test_exr_float_round_trip();
    test_exr_premultiplied_source_is_not_premultiplied_again();
    test_tiled_tiff_edge_tiles_and_coverage();
    test_coverage_order_and_no_state_change();
    test_buffer_too_small_consumes_nothing();
    test_unsupported_and_corrupt_content();
    test_limits_and_decompression_bomb();
    test_region_validation_and_output_limit();
    test_options_and_subimage_selection();
    test_cancellation_and_deadline();
    test_callback_failures();
    test_handle_lifecycle_and_limit();
    std::printf("arcimage codec checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
