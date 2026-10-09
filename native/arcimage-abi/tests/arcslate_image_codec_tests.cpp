// SPDX-License-Identifier: AGPL-3.0-only
// Behavioural and failure tests for the functional ArcImageNative codec family. Fixtures are generated
// in memory by OpenImageIO writers during the run and are never shipped (decision D1).
#include <arc/arc_slate_image_abi.h>

#include <Imath/half.h>

#include <OpenImageIO/filesystem.h>
#include <OpenImageIO/imagebufalgo.h>
#include <OpenImageIO/imageio.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
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

bool contains(const std::string& text, const std::string& needle)
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

arc_status_t ARC_ABI_CALL read_at(void* context, uint64_t offset, void* destination, uint64_t requested, uint64_t* done)
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
// Fixtures hold straight (unassociated) alpha unless the caller says otherwise. OpenImageIO's PNG writer
// assumes associated input and rewrites colour unless the spec marks the alpha unassociated, and its TIFF
// writer labels the alpha from the same attribute. Marking the spec keeps the stored bytes equal to the pixels.
std::vector<unsigned char> encode(const char* hint, OIIO::ImageSpec spec, OIIO::TypeDesc type, const void* pixels,
                                  bool straight_alpha = true)
{
    const std::string_view name(hint);
    if (straight_alpha && spec.alpha_channel != -1 && (name.ends_with(".png") || name.ends_with(".tif"))) {
        spec.attribute("oiio:UnassociatedAlpha", 1);
    }
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

// A PNG whose IHDR declares an RGBA8 image of the given size, with one empty stored block and no pixel data.
std::vector<unsigned char> png_header_only(uint32_t width, uint32_t height)
{
    std::vector<unsigned char> bytes = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    std::vector<unsigned char> header;
    append_be32(header, width);
    append_be32(header, height);
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

// A PNG whose header declares a 65535 x 65535 RGBA image. It is refused from the header alone.
std::vector<unsigned char> decompression_bomb_png()
{
    return png_header_only(65535, 65535);
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

    struct source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    const arc_status_t status = open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata);
    expect(status == ARC_OK && handle != 0, "PNG opens as rgba8");
    expect(contains(metadata, "\"format\":\"png\"") && contains(metadata, "\"outputFormat\":\"rgba8\""),
           "metadata names the codec and output format");
    expect(contains(metadata, "\"alpha\":\"straight\""), "straight PNG alpha is read as straight");
    expect(!contains(metadata, "\"premultiplyOnRead\"") && !contains(metadata, "\"unpremultiply\""),
           "straight PNG alpha is passed to rgba8 without a premultiply or unpremultiply step");
    expect(!contains(metadata, "\"unpremultiplyPrecision\""),
           "rgba8 output from straight alpha reports no precision loss");

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

void test_tiff_associated_alpha_is_not_premultiplied_again()
{
    // Stored with associated alpha (the TIFF marks it associated, so no unassociated attribute is reported).
    const std::vector<uint8_t> pixel = {102, 102, 102, 128};
    const auto bytes = encode("fixture.tif", rgba8_spec(1, 1), OIIO::TypeDesc::UINT8, pixel.data(), false);
    expect(!bytes.empty(), "associated TIFF fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED), nullptr, handle, metadata) == ARC_OK,
           "associated TIFF opens as linear premultiplied float");
    expect(contains(metadata, "\"alpha\":\"premultiplied\"") && !contains(metadata, "\"premultiplyOnRead\""),
           "associated TIFF alpha is reported as premultiplied and not premultiplied again");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, 1, 1, 16, raw) == ARC_OK, "associated TIFF float region reads");
    float values[4] = {};
    std::memcpy(values, raw.data(), sizeof(values));
    expect(std::abs(values[0] - 102.0F / 255.0F) < 1e-6F && std::abs(values[3] - 128.0F / 255.0F) < 1e-6F,
           "associated TIFF colour and alpha pass through unchanged");
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
                blocks_match =
                    blocks_match && std::memcmp(block.data() + static_cast<size_t>(row) * w * 4,
                                                source_pixels.data() + source_offset, static_cast<size_t>(w) * 4) == 0;
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
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "PNG opens for coverage");

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
    const arc_status_t short_metadata = open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata, 1);
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

void test_unsupported_content()
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
        expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_UNSUPPORTED &&
                   handle == 0,
               "content outside the PNG, TIFF and EXR allowlist is unsupported with no handle");
    }
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

// ---- Helpers for bit depth, edges, corruption, cancellation, coverage and subimages -------------

bool all_bytes(const std::vector<uint8_t>& bytes, uint8_t value)
{
    return std::all_of(bytes.begin(), bytes.end(), [value](uint8_t byte) { return byte == value; });
}

// True when a packed block equals the same rectangle of an expected image that is expected_width pixels wide.
bool region_matches(const std::vector<uint8_t>& block, const std::vector<uint8_t>& expected, uint32_t expected_width,
                    uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t bytes_per_pixel)
{
    if (block.size() != static_cast<size_t>(w) * h * bytes_per_pixel) {
        return false;
    }
    for (uint32_t row = 0; row < h; ++row) {
        const size_t offset = ((static_cast<size_t>(y) + row) * expected_width + x) * bytes_per_pixel;
        if (std::memcmp(block.data() + static_cast<size_t>(row) * w * bytes_per_pixel, expected.data() + offset,
                        static_cast<size_t>(w) * bytes_per_pixel) != 0) {
            return false;
        }
    }
    return true;
}

std::vector<float> float_pattern(uint32_t width, uint32_t height, uint32_t channels, float offset)
{
    std::vector<float> values(static_cast<size_t>(width) * height * channels);
    for (size_t index = 0; index < values.size(); ++index) {
        values[index] = static_cast<float>((index * 7U + 3U) % 97U) * 0.25F + offset;
    }
    return values;
}

std::vector<uint8_t> as_bytes(const std::vector<float>& values)
{
    std::vector<uint8_t> bytes(values.size() * sizeof(float));
    std::memcpy(bytes.data(), values.data(), bytes.size());
    return bytes;
}

// True when float32 output equals each 16-bit sample divided by 65535, to within 1e-6.
bool decodes_as_unorm16(const std::vector<uint8_t>& raw, const std::vector<uint16_t>& samples)
{
    if (raw.size() != samples.size() * sizeof(float)) {
        return false;
    }
    for (size_t index = 0; index < samples.size(); ++index) {
        float value = 0.0F;
        std::memcpy(&value, raw.data() + index * sizeof(float), sizeof(float));
        if (std::abs(value - static_cast<float>(samples[index]) / 65535.0F) > 1e-6F) {
            return false;
        }
    }
    return true;
}

// One subimage, or one mip level of the preceding subimage when mip_level is set, for encode_parts.
struct part {
    OIIO::ImageSpec spec;
    OIIO::TypeDesc type;
    const void* pixels;
    bool mip_level;
};

// Removes a temporary fixture file when it leaves scope.
struct temporary_file final {
    std::filesystem::path path;
    ~temporary_file()
    {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
};

// A fresh temporary path with the given extension.
std::filesystem::path temporary_fixture_path(const char* extension)
{
    static int sequence = 0;
    return std::filesystem::temp_directory_path() /
           ("arcslate_image_codec_fixture_" + std::to_string(++sequence) + extension);
}

// Writes the parts in order and returns the resulting bytes. The first part creates the file and later parts
// append. OpenImageIO's EXR writer refuses to append subimages or mip levels through an IOProxy, so these
// fixtures go through a temporary file that is read back and removed. The shim itself only ever sees the bytes.
std::vector<unsigned char> encode_parts(const char* extension, const std::vector<part>& parts)
{
    const temporary_file cleanup{temporary_fixture_path(extension)};
    const std::string name = cleanup.path.string();
    auto output = OIIO::ImageOutput::create(name);
    if (!output) {
        return {};
    }
    // A format that cannot append subimages must be given every subimage spec when the file is first opened.
    std::vector<OIIO::ImageSpec> subimage_specs;
    for (const part& item : parts) {
        if (!item.mip_level) {
            subimage_specs.push_back(item.spec);
        }
    }
    const bool declare_subimages =
        subimage_specs.size() > 1 && output->supports("multiimage") && !output->supports("appendsubimage");
    for (size_t index = 0; index < parts.size(); ++index) {
        const part& item = parts[index];
        bool opened = false;
        if (index == 0 && declare_subimages) {
            opened = output->open(name, static_cast<int>(subimage_specs.size()), subimage_specs.data());
        } else if (index == 0) {
            opened = output->open(name, item.spec, OIIO::ImageOutput::Create);
        } else {
            opened =
                output->open(name, item.spec,
                             item.mip_level ? OIIO::ImageOutput::AppendMIPLevel : OIIO::ImageOutput::AppendSubimage);
        }
        if (!opened) {
            std::fprintf(stderr, "fixture part %zu open failed (declared=%d mip=%d): %s\n", index,
                         declare_subimages ? 1 : 0, item.mip_level ? 1 : 0, OIIO::geterror().c_str());
            return {};
        }
        if (!output->write_image(item.type, item.pixels)) {
            std::fprintf(stderr, "fixture part %zu write failed: %s\n", index, OIIO::geterror().c_str());
            return {};
        }
    }
    output->close();
    output.reset();

    std::ifstream file(cleanup.path, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }
    const auto size = static_cast<size_t>(file.tellg());
    std::vector<unsigned char> bytes(size);
    file.seekg(0);
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    return file ? bytes : std::vector<unsigned char>{};
}

// Damaged or truncated input must be refused as CORRUPT, either at open or on the first full read, and the
// refused read must write no pixels.
void expect_corrupt(const std::vector<unsigned char>& bytes, uint32_t width, uint32_t height, const char* what)
{
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    const arc_status_t opened = open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata);
    if (opened != ARC_OK) {
        expect(opened == ARC_CORRUPT && handle == 0, what);
        return;
    }
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_CORRUPT && all_bytes(pixels, 0), what);
    arc_image_close(handle);
}

// A copy of a PNG whose IDAT payload is damaged. The header still parses, and the chunk CRC fails on read.
std::vector<unsigned char> png_with_damaged_pixels(const std::vector<unsigned char>& good)
{
    std::vector<unsigned char> bytes = good;
    const size_t idat = std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()).find("IDAT");
    if (idat != std::string_view::npos && idat + 6 < bytes.size()) {
        bytes[idat + 6] ^= 0x5A; // inside the zlib stream, after its two-byte header
    }
    return bytes;
}

// Reads a fixture one pixel at a time in raster order. Every pixel must match, the image is complete afterwards,
// and a further pixel is refused.
void read_pixels_one_by_one(const std::vector<unsigned char>& bytes, uint32_t width, uint32_t height,
                            const std::vector<uint8_t>& expected)
{
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "fixture opens for single-pixel reads");
    bool every_pixel = true;
    std::vector<uint8_t> pixel;
    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            every_pixel = every_pixel && read_region(handle, x, y, 1, 1, 4, pixel) == ARC_OK &&
                          region_matches(pixel, expected, width, x, y, 1, 1, 4);
        }
    }
    expect(every_pixel, "single-pixel raster reads reproduce every pixel once");
    std::vector<uint8_t> extra;
    expect(read_region(handle, 0, 0, 1, 1, 4, extra) == ARC_INVALID_ARGUMENT,
           "a complete image refuses a further pixel");
    arc_image_close(handle);
}

// ---- Tests: bit depth and metadata ---------------------------------------------------------------

void test_png16_float_identity_round_trip()
{
    const uint32_t width = 3;
    const uint32_t height = 2;
    std::vector<uint16_t> samples(static_cast<size_t>(width) * height * 4);
    for (size_t index = 0; index < samples.size(); ++index) {
        samples[index] = static_cast<uint16_t>(index * 2731U);
    }
    OIIO::ImageSpec spec(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::UINT16);
    spec.channelnames = {"R", "G", "B", "A"};
    spec.alpha_channel = 3;
    const auto bytes = encode("fixture.png", spec, OIIO::TypeDesc::UINT16, samples.data());
    expect(!bytes.empty(), "16-bit PNG fixture encodes for float output");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED), nullptr, handle, metadata) == ARC_OK,
           "16-bit PNG opens as float32 interleaved");
    expect(contains(metadata, "\"sourceBitsMax\":16") && contains(metadata, "\"type\":\"uint16\"") &&
               contains(metadata, "\"loss\":[]") && contains(metadata, "\"bytesPerPixel\":16"),
           "float32 output from 16-bit PNG reports the source depth and no loss");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, width, height, 16, raw) == ARC_OK, "16-bit float32 region reads");
    expect(decodes_as_unorm16(raw, samples), "16-bit samples map to float32 by 1/65535 without loss");
    arc_image_close(handle);
}

void test_tiff8_straight_round_trip()
{
    const uint32_t width = 6;
    const uint32_t height = 4;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    const auto bytes = encode("fixture.tif", rgba8_spec(width, height), OIIO::TypeDesc::UINT8, source_pixels.data());
    expect(!bytes.empty(), "8-bit TIFF fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "8-bit untiled TIFF opens as rgba8");
    expect(contains(metadata, "\"format\":\"tiff\"") && contains(metadata, "\"tiled\":false") &&
               contains(metadata, "\"alpha\":\"straight\"") && contains(metadata, "\"sourceBitsMax\":8"),
           "8-bit TIFF metadata reports the codec, layout, straight alpha and depth");
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_OK &&
               region_matches(pixels, source_pixels, width, 0, 0, width, height, 4),
           "8-bit untiled TIFF round trip is byte exact");
    arc_image_close(handle);
}

void test_tiff16_and_float_identity_round_trip()
{
    const uint32_t width = 5;
    const uint32_t height = 3;
    std::vector<uint16_t> samples(static_cast<size_t>(width) * height * 4);
    for (size_t index = 0; index < samples.size(); ++index) {
        samples[index] = static_cast<uint16_t>(index * 1000U);
    }
    OIIO::ImageSpec sixteen(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::UINT16);
    sixteen.channelnames = {"R", "G", "B", "A"};
    sixteen.alpha_channel = 3;
    const auto sixteen_bytes = encode("fixture.tif", sixteen, OIIO::TypeDesc::UINT16, samples.data());
    expect(!sixteen_bytes.empty(), "16-bit TIFF fixture encodes");
    {
        source state{};
        state.bytes = &sixteen_bytes;
        const arc_io_v1 io = make_io(state);
        arc_handle_t handle = 0;
        std::string metadata;
        expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED), nullptr, handle, metadata) == ARC_OK &&
                   contains(metadata, "\"format\":\"tiff\"") && contains(metadata, "\"sourceBitsMax\":16"),
               "16-bit TIFF opens as float32 and reports its source depth");
        std::vector<uint8_t> raw;
        expect(read_region(handle, 0, 0, width, height, 16, raw) == ARC_OK && decodes_as_unorm16(raw, samples),
               "16-bit TIFF samples map to float32 by 1/65535 without loss");
        arc_image_close(handle);
    }

    const std::vector<float> floats = float_pattern(width, height, 4, -3.0F);
    OIIO::ImageSpec single(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::FLOAT);
    single.channelnames = {"R", "G", "B", "A"};
    single.alpha_channel = 3;
    const auto float_bytes = encode("fixture.tif", single, OIIO::TypeDesc::FLOAT, floats.data());
    expect(!float_bytes.empty(), "float TIFF fixture encodes");
    source state{};
    state.bytes = &float_bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED), nullptr, handle, metadata) == ARC_OK &&
               contains(metadata, "\"type\":\"float\"") && contains(metadata, "\"sourceBitsMax\":32"),
           "float TIFF opens as float32 and reports its type");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, width, height, 16, raw) == ARC_OK &&
               region_matches(raw, as_bytes(floats), width, 0, 0, width, height, 16),
           "float TIFF channels round trip exactly");
    arc_image_close(handle);
}

void test_exr_half_round_trip_and_rgba8_clamp()
{
    const uint32_t width = 4;
    const uint32_t height = 3;
    std::vector<half> halves(static_cast<size_t>(width) * height * 4);
    std::vector<float> expected(halves.size());
    for (size_t index = 0; index < halves.size(); ++index) {
        // Multiples of one eighth are exact in half precision over this range.
        halves[index] = half((static_cast<float>(index) - 20.0F) * 0.125F);
        expected[index] = static_cast<float>(halves[index]);
    }
    OIIO::ImageSpec spec(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::HALF);
    spec.channelnames = {"R", "G", "B", "A"};
    spec.alpha_channel = 3;
    const auto bytes = encode("fixture.exr", spec, OIIO::TypeDesc::HALF, halves.data());
    expect(!bytes.empty(), "half-float EXR fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED), nullptr, handle, metadata) == ARC_OK &&
               contains(metadata, "\"type\":\"half\"") && contains(metadata, "\"sourceBitsMax\":16"),
           "half-float EXR opens as float32 and reports its half type");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, width, height, 16, raw) == ARC_OK &&
               region_matches(raw, as_bytes(expected), width, 0, 0, width, height, 16),
           "half-float channels convert to float32 exactly");
    arc_image_close(handle);

    // rgba8 clamps out-of-range values and rounds to nearest. Alpha is one, so unpremultiplying leaves colour
    // unchanged.
    const float clamp_values[16] = {-0.5F, 0.0F, 0.5F, 1.0F, 2.0F, 1.0F, 0.25F, 1.0F,
                                    0.0F,  0.0F, 0.0F, 1.0F, 0.5F, 0.5F, 0.5F,  1.0F};
    std::vector<half> clamp(16);
    for (size_t index = 0; index < clamp.size(); ++index) {
        clamp[index] = half(clamp_values[index]);
    }
    const std::vector<uint8_t> clamp_expected = {0, 0, 128, 255, 255, 255, 64, 255, 0, 0, 0, 255, 128, 128, 128, 255};
    OIIO::ImageSpec clamp_spec(4, 1, 4, OIIO::TypeDesc::HALF);
    clamp_spec.channelnames = {"R", "G", "B", "A"};
    clamp_spec.alpha_channel = 3;
    const auto clamp_bytes = encode("fixture.exr", clamp_spec, OIIO::TypeDesc::HALF, clamp.data());
    expect(!clamp_bytes.empty(), "clamping EXR fixture encodes");
    source clamp_state{};
    clamp_state.bytes = &clamp_bytes;
    const arc_io_v1 clamp_io = make_io(clamp_state);
    expect(open_image(clamp_io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK &&
               contains(metadata, "\"rangeClamp\"") && contains(metadata, "\"bitDepthReduction\""),
           "half-float to rgba8 reports range clamping and bit-depth reduction");
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, 4, 1, 4, pixels) == ARC_OK &&
               region_matches(pixels, clamp_expected, 4, 0, 0, 4, 1, 4),
           "rgba8 clamps to [0, 1] and rounds to nearest");
    arc_image_close(handle);
}

// ---- Tests: edge tiles and single-pixel regions --------------------------------------------------

void test_edge_tiles_and_one_pixel_regions()
{
    // 17 x 9 with 16 x 16 tiles: the last tile column is one pixel wide and the last tile row is partial.
    const uint32_t width = 17;
    const uint32_t height = 9;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    OIIO::ImageSpec spec = rgba8_spec(width, height);
    spec.tile_width = 16;
    spec.tile_height = 16;
    const auto tiled = encode("fixture.tif", spec, OIIO::TypeDesc::UINT8, source_pixels.data());
    expect(!tiled.empty(), "partial-edge tiled TIFF fixture encodes");
    read_pixels_one_by_one(tiled, width, height, source_pixels);

    // Two regions split at the tile boundary: the first ends before the one-pixel edge tile, the second crosses it.
    source state{};
    state.bytes = &tiled;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "partial-edge tiled TIFF opens for block reads");
    std::vector<uint8_t> block;
    expect(read_region(handle, 0, 0, 15, height, 4, block) == ARC_OK &&
               region_matches(block, source_pixels, width, 0, 0, 15, height, 4),
           "a region that ends before the last tile column reads exactly");
    expect(read_region(handle, 15, 0, 2, height, 4, block) == ARC_OK &&
               region_matches(block, source_pixels, width, 15, 0, 2, height, 4),
           "a region that crosses the tile boundary into the one-pixel edge reads exactly");
    expect(read_region(handle, 0, 0, 1, 1, 4, block) == ARC_INVALID_ARGUMENT,
           "block reads cover the image once, so a further pixel is refused");
    arc_image_close(handle);

    // Scanline PNG, one pixel at a time.
    const uint32_t png_width = 5;
    const uint32_t png_height = 3;
    const std::vector<uint8_t> png_pixels = rgba_pattern(png_width, png_height, 4);
    read_pixels_one_by_one(encode_png_rgba8(png_width, png_height, png_pixels), png_width, png_height, png_pixels);
}

// ---- Tests: coverage (decision D3) ---------------------------------------------------------------

void test_coverage_refusals_keep_the_cursor()
{
    const uint32_t width = 16;
    const uint32_t height = 12;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    const auto bytes = encode_png_rgba8(width, height, source_pixels);
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "PNG opens for coverage refusals");

    std::vector<uint8_t> block;
    expect(read_region(handle, 0, 0, 8, 4, 4, block) == ARC_OK &&
               region_matches(block, source_pixels, width, 0, 0, 8, 4, 4),
           "the first block is accepted");
    expect(read_region(handle, 0, 0, 8, 4, 4, block) == ARC_INVALID_ARGUMENT,
           "an identical block overlaps covered pixels");
    expect(read_region(handle, 4, 0, 8, 4, 4, block) == ARC_INVALID_ARGUMENT,
           "a block that starts inside the covered prefix overlaps it");
    expect(read_region(handle, 8, 1, 8, 2, 4, block) == ARC_INVALID_ARGUMENT,
           "a block below the first pending row is out of raster order");
    expect(read_region(handle, 8, 0, 0, 4, 4, block) == ARC_INVALID_ARGUMENT, "an empty block is refused");
    expect(read_region(handle, 8, 0, 16, 4, 4, block) == ARC_INVALID_ARGUMENT,
           "a block past the right edge is refused");
    expect(read_region(handle, 8, 0, 8, 4, 4, block) == ARC_OK &&
               region_matches(block, source_pixels, width, 8, 0, 8, 4, 4),
           "the refusals left the cursor where it was");
    expect(read_region(handle, 0, 4, 16, 4, 4, block) == ARC_OK &&
               region_matches(block, source_pixels, width, 0, 4, 16, 4, 4),
           "the next band starts on the first pending row");
    expect(read_region(handle, 0, 8, 16, 4, 4, block) == ARC_OK &&
               region_matches(block, source_pixels, width, 0, 8, 16, 4, 4),
           "the last band completes the image");
    expect(read_region(handle, 0, 0, 1, 1, 4, block) == ARC_INVALID_ARGUMENT,
           "a complete image refuses every further block");
    arc_image_close(handle);
}

// ---- Tests: output buffers -----------------------------------------------------------------------

void test_buffer_one_byte_short_consumes_nothing()
{
    const uint32_t width = 8;
    const uint32_t height = 8;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    const auto bytes = encode_png_rgba8(width, height, source_pixels);
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "fixture opens for the one-byte-short buffer check");

    const uint64_t needed = static_cast<uint64_t>(width) * height * 4;
    std::vector<uint8_t> short_buffer(static_cast<size_t>(needed - 1), 0x5A);
    arc_region_v1 region{};
    region.struct_size = sizeof(arc_region_v1);
    region.struct_version = 1;
    region.width = width;
    region.height = height;
    arc_mut_buffer_t output{};
    output.data = short_buffer.data();
    output.capacity = short_buffer.size();
    expect(arc_image_read(handle, &region, &output, nullptr) == ARC_BUFFER_TOO_SMALL && output.required == needed,
           "a buffer one byte short reports the exact required size");
    expect(all_bytes(short_buffer, 0x5A), "a short buffer is not written");
    std::vector<uint8_t> full;
    expect(read_region(handle, 0, 0, width, height, 4, full) == ARC_OK &&
               region_matches(full, source_pixels, width, 0, 0, width, height, 4),
           "the full region reads exactly after the short attempt");
    arc_image_close(handle);
}

// ---- Tests: formats, corruption, failure and cancellation ----------------------------------------

void test_unsupported_formats_and_empty_input()
{
    const std::vector<unsigned char> gif = {'G', 'I', 'F', '8', '9', 'a', 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    const std::vector<unsigned char> webp = {'R', 'I', 'F', 'F', 0x10, 0x00, 0x00, 0x00,
                                             'W', 'E', 'B', 'P', 'V',  'P',  '8',  ' '};
    const std::vector<unsigned char> jpeg2000 = {0xFF, 0x4F, 0xFF, 0x51, 0x00, 0x2F};
    const std::vector<unsigned char> empty;
    const std::vector<const std::vector<unsigned char>*> cases = {&gif, &webp, &jpeg2000, &empty};
    for (const auto* bytes : cases) {
        source state{};
        state.bytes = bytes;
        const arc_io_v1 io = make_io(state);
        arc_handle_t handle = 0xFF;
        std::string metadata;
        expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_UNSUPPORTED &&
                   handle == 0,
               "GIF, WebP, JPEG 2000 and empty input are UNSUPPORTED with no handle");
    }
}

void test_truncated_and_corrupt_input_is_corrupt()
{
    const uint32_t width = 8;
    const uint32_t height = 8;
    const auto png = encode_png_rgba8(width, height, rgba_pattern(width, height, 4));
    expect(png.size() > 64, "PNG fixture is large enough to truncate");

    const std::vector<unsigned char> truncated_png(png.begin(), png.begin() + 40);
    expect_corrupt(truncated_png, width, height, "a truncated PNG is refused as CORRUPT with no output");

    const std::vector<unsigned char> signature_only(png.begin(), png.begin() + 8);
    expect_corrupt(signature_only, width, height, "a PNG with only its signature is refused as CORRUPT");

    std::vector<unsigned char> bad_header_crc = png;
    bad_header_crc[29] ^=
        0xFF; // the IHDR CRC starts after the 8-byte signature, 4-byte length, 4-byte type and 13 data bytes
    expect_corrupt(bad_header_crc, width, height, "a PNG with a damaged IHDR CRC is refused as CORRUPT");

    expect_corrupt(png_with_damaged_pixels(png), width, height,
                   "a PNG with damaged pixel data fails CORRUPT on read with no output");

    const auto tiff =
        encode("fixture.tif", rgba8_spec(width, height), OIIO::TypeDesc::UINT8, rgba_pattern(width, height, 4).data());
    expect(!tiff.empty(), "TIFF fixture encodes for corruption checks");
    const std::vector<unsigned char> truncated_tiff(tiff.begin(), tiff.begin() + static_cast<long>(tiff.size() / 2));
    expect_corrupt(truncated_tiff, width, height, "a truncated TIFF is refused as CORRUPT with no output");

    const auto exr = encode(
        "fixture.exr",
        [] {
            OIIO::ImageSpec exr_spec(8, 8, 4, OIIO::TypeDesc::FLOAT);
            exr_spec.channelnames = {"R", "G", "B", "A"};
            exr_spec.alpha_channel = 3;
            return exr_spec;
        }(),
        OIIO::TypeDesc::FLOAT, float_pattern(8, 8, 4, 0.0F).data());
    expect(!exr.empty(), "EXR fixture encodes for corruption checks");
    const std::vector<unsigned char> truncated_exr(exr.begin(), exr.begin() + static_cast<long>(exr.size() / 2));
    expect_corrupt(truncated_exr, width, height, "a truncated EXR is refused as CORRUPT with no output");

    std::vector<unsigned char> bad_exr_version = exr;
    bad_exr_version[4] = 0xFF; // the version field after the 4-byte magic
    bad_exr_version[5] = 0xFF;
    expect_corrupt(bad_exr_version, width, height, "an EXR with an invalid version field is refused as CORRUPT");
}

void test_failed_codec_and_callback_failure_keep_coverage()
{
    const uint32_t width = 64;
    const uint32_t height = 64;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    OIIO::ImageSpec spec = rgba8_spec(width, height);
    spec.tile_width = 16;
    spec.tile_height = 16;
    const auto bytes = encode("fixture.tif", spec, OIIO::TypeDesc::UINT8, source_pixels.data());
    expect(!bytes.empty(), "tiled TIFF fixture encodes for the failed-codec check");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "fixture opens for the failed-codec check");

    state.fail_after = state.calls; // the next source callback fails in the middle of the decode
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_IO && all_bytes(pixels, 0),
           "a failing callback during decode is IO and writes no pixels");
    state.fail_after = -1;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_OK &&
               region_matches(pixels, source_pixels, width, 0, 0, width, height, 4),
           "the failed read consumed no coverage, and the retry is exact");
    arc_image_close(handle);
}

void test_decompression_bomb_refused_before_decode()
{
    // A pixel count above the hard profile (16385 x 16385) is refused from the header alone.
    const auto over_profile = png_header_only(16385, 16385);
    source over_state{};
    over_state.bytes = &over_profile;
    const arc_io_v1 over_io = make_io(over_state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(over_io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_RESOURCE_LIMIT &&
               handle == 0,
           "a header above the pixel profile is refused as RESOURCE_LIMIT with no handle");

    // Inside the pixel profile, one 16-row band of 16384-wide RGBA32F rows needs about 4 MiB, above a 1 MiB limit.
    // The refusal happens before any row is decoded, so the pixels stay untouched.
    const auto wide = png_header_only(16384, 16384);
    source wide_state{};
    wide_state.bytes = &wide;
    const arc_io_v1 wide_io = make_io(wide_state);
    arc_image_options_v1 tight = make_options(ARC_FORMAT_RGBA8);
    tight.limits.max_memory_bytes = UINT64_C(1) << 20;
    expect(open_image(wide_io, tight, nullptr, handle, metadata) == ARC_OK,
           "a header within the pixel profile opens when the row band fits the memory limit");
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, 1, 16, 4, pixels) == ARC_RESOURCE_LIMIT && all_bytes(pixels, 0),
           "a row band above the memory limit is refused before any row decodes");
    arc_image_close(handle);

    // Tile memory is checked at open. A 16 x 16 RGBA8 tile needs 4096 bytes of float working memory.
    OIIO::ImageSpec tile_spec = rgba8_spec(16, 16);
    tile_spec.tile_width = 16;
    tile_spec.tile_height = 16;
    const std::vector<uint8_t> tile_pixels = rgba_pattern(16, 16, 4);
    const auto tiled = encode("fixture.tif", tile_spec, OIIO::TypeDesc::UINT8, tile_pixels.data());
    expect(!tiled.empty(), "single-tile TIFF fixture encodes");
    source tile_state{};
    tile_state.bytes = &tiled;
    const arc_io_v1 tile_io = make_io(tile_state);
    arc_image_options_v1 just_under = make_options(ARC_FORMAT_RGBA8);
    just_under.limits.max_memory_bytes = 4095;
    expect(open_image(tile_io, just_under, nullptr, handle, metadata) == ARC_RESOURCE_LIMIT && handle == 0,
           "a tile one byte above the memory limit is refused at open");
    arc_image_options_v1 exact = make_options(ARC_FORMAT_RGBA8);
    exact.limits.max_memory_bytes = 4096;
    expect(open_image(tile_io, exact, nullptr, handle, metadata) == ARC_OK, "a tile exactly at the memory limit opens");
    arc_image_close(handle);
}

void test_cancellation_at_every_tile_and_callback_boundary()
{
    const uint32_t width = 64;
    const uint32_t height = 64;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    OIIO::ImageSpec spec = rgba8_spec(width, height);
    spec.tile_width = 16;
    spec.tile_height = 16;
    const auto bytes = encode("fixture.tif", spec, OIIO::TypeDesc::UINT8, source_pixels.data());
    expect(!bytes.empty(), "tiled TIFF fixture encodes for the cancellation sweep");
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    std::string metadata;

    // One uncancelled full read counts its cancellation checks. Each tile and each callback is a boundary.
    cancel_state counter{};
    arc_cancel_token_t counting = make_token(counter);
    arc_handle_t handle = 0;
    std::vector<uint8_t> pixels;
    expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, handle, metadata) == ARC_OK,
           "tiled fixture opens for the cancellation sweep");
    expect(read_region(handle, 0, 0, width, height, 4, pixels, &counting) == ARC_OK &&
               region_matches(pixels, source_pixels, width, 0, 0, width, height, 4),
           "the uncancelled read is exact");
    const int boundaries = counter.calls;
    arc_image_close(handle);
    expect(boundaries >= 16, "each of the 16 tiles is a cancellation boundary");

    // Cancelling at any boundary returns CANCELLED, writes no pixels and consumes no coverage.
    for (int cancel_at = 1; cancel_at <= boundaries; ++cancel_at) {
        cancel_state cancelled{};
        cancelled.cancel_from = cancel_at;
        arc_cancel_token_t token = make_token(cancelled);
        arc_handle_t fresh = 0;
        expect(open_image(io, make_options(ARC_FORMAT_RGBA8), nullptr, fresh, metadata) == ARC_OK,
               "fixture reopens for each cancellation point");
        expect(read_region(fresh, 0, 0, width, height, 4, pixels, &token) == ARC_CANCELLED && all_bytes(pixels, 0),
               "a read cancelled at a boundary is CANCELLED with no pixels written");
        expect(read_region(fresh, 0, 0, width, height, 4, pixels) == ARC_OK &&
                   region_matches(pixels, source_pixels, width, 0, 0, width, height, 4),
               "a cancelled read consumed no coverage");
        arc_image_close(fresh);
    }
}

void test_read_deadline_refuses_before_commit()
{
    const uint32_t width = 64;
    const uint32_t height = 64;
    const std::vector<uint8_t> source_pixels = rgba_pattern(width, height, 4);
    OIIO::ImageSpec spec = rgba8_spec(width, height);
    spec.tile_width = 16;
    spec.tile_height = 16;
    const auto bytes = encode("fixture.tif", spec, OIIO::TypeDesc::UINT8, source_pixels.data());
    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_image_options_v1 timed = make_options(ARC_FORMAT_RGBA8);
    timed.limits.timeout_ms = 100;
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, timed, nullptr, handle, metadata) == ARC_OK, "fixture opens within its deadline");

    // Each source callback now takes 40 ms, so the 100 ms deadline passes between tiles.
    state.sleep_ms = 40;
    std::vector<uint8_t> pixels;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_RESOURCE_LIMIT && all_bytes(pixels, 0),
           "a read that passes its deadline between tiles is RESOURCE_LIMIT with no pixels written");
    state.sleep_ms = 0;
    expect(read_region(handle, 0, 0, width, height, 4, pixels) == ARC_OK &&
               region_matches(pixels, source_pixels, width, 0, 0, width, height, 4),
           "the timed-out read consumed no coverage");
    arc_image_close(handle);
}

// ---- Tests: EXR subimages and mip levels within bounds -------------------------------------------

void test_exr_multipart_subimages_within_bounds()
{
    // OpenImageIO's EXR writer accepts parts only when they share one size, so both parts are 6 x 3 RGBA with
    // different samples.
    const std::vector<float> first = float_pattern(6, 3, 4, -3.0F);
    const std::vector<float> second = float_pattern(6, 3, 4, 2.0F);
    OIIO::ImageSpec part_spec(6, 3, 4, OIIO::TypeDesc::FLOAT);
    part_spec.channelnames = {"R", "G", "B", "A"};
    part_spec.alpha_channel = 3;
    const auto bytes = encode_parts(".exr", {part{part_spec, OIIO::TypeDesc::FLOAT, first.data(), false},
                                             part{part_spec, OIIO::TypeDesc::FLOAT, second.data(), false}});
    expect(!bytes.empty(), "two-part EXR fixture encodes");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED, 1, 0), nullptr, handle, metadata) == ARC_OK &&
               contains(metadata, "\"subimage\":1") && contains(metadata, "\"subimages\":2") &&
               contains(metadata, "\"width\":6") && contains(metadata, "\"height\":3"),
           "the second part opens with its own index and the subimage count");
    std::vector<uint8_t> raw;
    expect(read_region(handle, 0, 0, 6, 3, 16, raw) == ARC_OK &&
               region_matches(raw, as_bytes(second), 6, 0, 0, 6, 3, 16),
           "the second part reads exactly");
    arc_image_close(handle);

    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED, 0, 0), nullptr, handle, metadata) == ARC_OK &&
               contains(metadata, "\"subimage\":0") && contains(metadata, "\"subimages\":2"),
           "the first part opens with the same subimage count");
    expect(read_region(handle, 0, 0, 6, 3, 16, raw) == ARC_OK &&
               region_matches(raw, as_bytes(first), 6, 0, 0, 6, 3, 16),
           "the first part reads exactly, and differently from the second");
    arc_image_close(handle);

    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED, 2, 0), nullptr, handle, metadata) ==
                   ARC_NOT_FOUND &&
               handle == 0,
           "a subimage past the last part is NOT_FOUND");

    arc_image_options_v1 one_item = make_options(ARC_FORMAT_FLOAT32_INTERLEAVED, 0, 0);
    one_item.limits.max_items = 1;
    expect(open_image(io, one_item, nullptr, handle, metadata) == ARC_RESOURCE_LIMIT && handle == 0,
           "two subimages exceed a one-item limit before any decode");
}

void test_exr_mip_levels_within_bounds()
{
    const uint32_t width = 32;
    const uint32_t height = 16;
    const std::vector<float> base = float_pattern(width, height, 4, -1.0F);
    OIIO::ImageSpec spec(static_cast<int>(width), static_cast<int>(height), 4, OIIO::TypeDesc::FLOAT);
    spec.channelnames = {"R", "G", "B", "A"};
    spec.alpha_channel = 3;
    OIIO::ImageBuf input(spec);
    input.set_pixels(OIIO::ROI(0, static_cast<int>(width), 0, static_cast<int>(height), 0, 1, 0, 4),
                     OIIO::TypeDesc::FLOAT, base.data());

    // OpenImageIO's texture writer produces a tiled, mipmapped EXR. Its own reader is the oracle for every level.
    const temporary_file cleanup{temporary_fixture_path(".exr")};
    const bool written = OIIO::ImageBufAlgo::make_texture(OIIO::ImageBufAlgo::MakeTxTexture, input,
                                                          cleanup.path.string(), OIIO::ImageSpec());
    expect(written, "the texture writer produces a mipmapped EXR fixture");
    if (!written) {
        (void)OIIO::geterror();
        return;
    }

    std::vector<std::vector<float>> levels;
    std::vector<OIIO::ImageSpec> level_specs;
    {
        auto oracle = OIIO::ImageInput::open(cleanup.path.string());
        expect(oracle != nullptr, "the oracle reader opens the mipmapped fixture");
        for (int mip = 0; oracle && oracle->seek_subimage(0, mip); ++mip) {
            const OIIO::ImageSpec level = oracle->spec(0, mip);
            std::vector<float> pixels(static_cast<size_t>(level.width) * level.height * 4);
            expect(oracle->read_image(0, mip, 0, 4, OIIO::TypeDesc::FLOAT, pixels.data()),
                   "the oracle reads every mip level");
            levels.push_back(std::move(pixels));
            level_specs.push_back(level);
        }
    }
    expect(levels.size() >= 2, "the fixture has a base level and at least one mip level");

    std::ifstream file(cleanup.path, std::ios::binary | std::ios::ate);
    const auto size = file ? static_cast<size_t>(file.tellg()) : size_t{0};
    std::vector<unsigned char> bytes(size);
    if (file) {
        file.seekg(0);
        file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    }
    expect(!bytes.empty(), "the mipmapped fixture bytes are read back");

    source state{};
    state.bytes = &bytes;
    const arc_io_v1 io = make_io(state);
    const auto mip_count = static_cast<uint32_t>(levels.size());
    for (uint32_t mip = 0; mip < mip_count; ++mip) {
        const auto level_width = static_cast<uint32_t>(level_specs[mip].width);
        const auto level_height = static_cast<uint32_t>(level_specs[mip].height);
        arc_handle_t handle = 0;
        std::string metadata;
        expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED, 0, mip), nullptr, handle, metadata) ==
                       ARC_OK &&
                   contains(metadata, "\"mip\":" + std::to_string(mip)) &&
                   contains(metadata, "\"mips\":" + std::to_string(mip_count)) &&
                   contains(metadata, "\"width\":" + std::to_string(level_width)) &&
                   contains(metadata, "\"height\":" + std::to_string(level_height)),
               "a mip level opens with its own dimensions and the mip count");
        std::vector<uint8_t> raw;
        expect(read_region(handle, 0, 0, level_width, level_height, 16, raw) == ARC_OK &&
                   region_matches(raw, as_bytes(levels[mip]), level_width, 0, 0, level_width, level_height, 16),
               "a mip level reads exactly as the oracle reads it");
        arc_image_close(handle);
    }

    arc_handle_t handle = 0;
    std::string metadata;
    expect(open_image(io, make_options(ARC_FORMAT_FLOAT32_INTERLEAVED, 0, mip_count), nullptr, handle, metadata) ==
                   ARC_NOT_FOUND &&
               handle == 0,
           "a mip level past the last one is NOT_FOUND");

    arc_image_options_v1 one_item = make_options(ARC_FORMAT_FLOAT32_INTERLEAVED, 0, 0);
    one_item.limits.max_items = 1;
    expect(open_image(io, one_item, nullptr, handle, metadata) == ARC_RESOURCE_LIMIT && handle == 0,
           "a mip count above a one-item limit is refused before any decode");
}

// ---- Registration -------------------------------------------------------------------------------
// Each entry is one CTest target (arcslate_image_abi.codec.<name>) in native/arcimage-abi/CMakeLists.txt.
// Keep the two lists in step.

struct test_case final {
    const char* name;
    void (*run)();
};

constexpr test_case test_cases[] = {
    {"probe", test_probe_and_build_info},
    {"png_rgba8", test_png_rgba8_round_trip},
    {"png_rgb_fills_alpha", test_png_rgb_fills_alpha},
    {"png16_bit_loss", test_png_16bit_reports_bit_depth_loss},
    {"png16_float_identity", test_png16_float_identity_round_trip},
    {"png_linear_premultiply", test_png_linear_float_and_premultiply},
    {"tiff8_straight", test_tiff8_straight_round_trip},
    {"tiff16_float_identity", test_tiff16_and_float_identity_round_trip},
    {"exr_float", test_exr_float_round_trip},
    {"exr_half_clamp", test_exr_half_round_trip_and_rgba8_clamp},
    {"exr_premultiplied", test_exr_premultiplied_source_is_not_premultiplied_again},
    {"tiff_associated", test_tiff_associated_alpha_is_not_premultiplied_again},
    {"tiled_tiff_edges", test_tiled_tiff_edge_tiles_and_coverage},
    {"edge_one_pixel", test_edge_tiles_and_one_pixel_regions},
    {"coverage_order", test_coverage_order_and_no_state_change},
    {"coverage_refusals", test_coverage_refusals_keep_the_cursor},
    {"buffer_too_small", test_buffer_too_small_consumes_nothing},
    {"buffer_one_byte_short", test_buffer_one_byte_short_consumes_nothing},
    {"unsupported_content", test_unsupported_content},
    {"unsupported_formats", test_unsupported_formats_and_empty_input},
    {"corrupt_input", test_truncated_and_corrupt_input_is_corrupt},
    {"failed_codec", test_failed_codec_and_callback_failure_keep_coverage},
    {"limits_bomb", test_limits_and_decompression_bomb},
    {"bomb_before_decode", test_decompression_bomb_refused_before_decode},
    {"region_validation", test_region_validation_and_output_limit},
    {"options_subimage", test_options_and_subimage_selection},
    {"cancellation", test_cancellation_and_deadline},
    {"cancel_each_boundary", test_cancellation_at_every_tile_and_callback_boundary},
    {"read_deadline", test_read_deadline_refuses_before_commit},
    {"callback_failures", test_callback_failures},
    {"handle_lifecycle", test_handle_lifecycle_and_limit},
    {"exr_multipart", test_exr_multipart_subimages_within_bounds},
    {"exr_mips", test_exr_mip_levels_within_bounds},
};

} // namespace

// With no argument every test runs. With one argument, only the test of that name runs, so CTest can list each.
int main(int argc, char** argv)
{
    if (argc > 2) {
        std::fprintf(stderr, "usage: arcslate_image_codec_tests [test-name]\n");
        return 2;
    }
    const std::string_view wanted = argc == 2 ? std::string_view(argv[1]) : std::string_view();
    int selected = 0;
    for (const test_case& test : test_cases) {
        if (!wanted.empty() && wanted != test.name) {
            continue;
        }
        ++selected;
        test.run();
        (void)OIIO::geterror(); // clears OpenImageIO's pending message so it is not printed at exit
    }
    if (selected == 0) {
        std::fprintf(stderr, "unknown codec test: %s\n", argv[1]);
        return 2;
    }
    (void)OIIO::geterror();
    std::printf("ArcImageNative codec checks: %d, failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
