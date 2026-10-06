// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in codec runtime diagnostics. Never registered as a hosted CI runtime test.
#include <OpenImageIO/imageio.h>
#include <algorithm>
#include <arc/arc_slate_image_abi.h>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}
struct input {
    std::vector<unsigned char> bytes;
    bool fail = false;
    arc_status_t failure = ARC_IO;
    uint32_t delay_ms = 0;
    bool short_read = false;
    std::atomic<bool> block{false};
    std::atomic<bool> entered{false};
    std::mutex gate;
    std::condition_variable changed;
    std::function<void()> on_read;
};
arc_status_t ARC_ABI_CALL read(void* context, uint64_t offset, void* destination, uint64_t count, uint64_t* done)
{
    auto& data = *static_cast<input*>(context);
    *done = 0;
    if (data.fail)
        return data.failure;
    if (data.on_read)
        data.on_read();
    if (data.delay_ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(data.delay_ms));
    if (data.block) {
        data.entered = true;
        data.changed.notify_all();
        std::unique_lock lock(data.gate);
        data.changed.wait(lock, [&] { return !data.block; });
    }
    const auto available = std::min<uint64_t>(count, data.bytes.size() - std::min<uint64_t>(offset, data.bytes.size()));
    *done = data.short_read && available ? available - 1 : available;
    std::memcpy(destination, data.bytes.data() + offset, static_cast<size_t>(*done));
    return ARC_OK;
}
arc_bool_t ARC_ABI_CALL cancelled(void* context)
{
    return static_cast<std::atomic<bool>*>(context)->load() ? 1 : 0;
}
arc_image_options_v1 options(uint32_t format = ARC_FORMAT_RGBA8)
{
    arc_image_options_v1 value{};
    value.struct_size = sizeof(value);
    value.struct_version = 1;
    value.format = format;
    value.limits = {.struct_size = sizeof(arc_limits_v1),
                    .struct_version = 1,
                    .max_input_bytes = 64 * 1024 * 1024,
                    .max_memory_bytes = 512 * 1024 * 1024,
                    .max_output_bytes = 64 * 1024 * 1024,
                    .max_width = 65535,
                    .max_height = 65535,
                    .max_items = 4096,
                    .timeout_ms = 30000};
    return value;
}
arc_io_v1 io(input& data)
{
    return {.struct_size = sizeof(arc_io_v1),
            .struct_version = 1,
            .context = &data,
            .length = data.bytes.size(),
            .max_length = data.bytes.size(),
            .read_at = read};
}
std::string last_error()
{
    char message[4096]{};
    arc_error_info_t error{
        .struct_size = sizeof(arc_error_info_t), .struct_version = 1, .message_utf8 = {message, sizeof(message), 0}};
    arc_image_get_last_error(&error);
    return std::string(message, static_cast<size_t>(error.message_utf8.required));
}
arc_handle_t open(input& data, arc_image_options_v1 config, std::string* json = nullptr)
{
    auto source = io(data);
    arc_handle_t handle = UINT64_MAX;
    arc_mut_buffer_t query{};
    auto status = arc_image_open(&source, &config, &handle, &query, nullptr);
    if (status != ARC_BUFFER_TOO_SMALL)
        throw std::runtime_error("metadata query: " + std::to_string(status) + " " + last_error());
    require(handle == 0 && query.required > 0 && query.required <= 65536, "query leaked handle or invalid size");
    std::vector<char> metadata(static_cast<size_t>(query.required));
    arc_mut_buffer_t output{metadata.data(), metadata.size(), 0};
    status = arc_image_open(&source, &config, &handle, &output, nullptr);
    if (status != ARC_OK)
        throw std::runtime_error("open: " + std::to_string(status) + " " + last_error());
    require(handle != 0 && output.required == metadata.size(), "open missing owned output");
    if (json)
        *json = std::string(metadata.begin(), metadata.end());
    return handle;
}
std::vector<unsigned char> fixture(const std::filesystem::path& directory, const std::string& extension, bool tiled,
                                   std::string_view compression = "none")
{
    const auto file = directory / ("image." + extension);
    auto writer = OIIO::ImageOutput::create(file.string());
    require(writer != nullptr, "fixture codec missing");
    OIIO::ImageSpec spec(19, 17, 4, extension == "exr" ? OIIO::TypeDesc::HALF : OIIO::TypeDesc::UINT16);
    spec.attribute("oiio:ColorSpace", "Linear");
    spec.attribute("oiio:UnassociatedAlpha", 1);
    if (extension == "tif")
        spec.attribute("compression", std::string(compression));
    spec.alpha_channel = 3;
    if (tiled) {
        spec.tile_width = 16;
        spec.tile_height = 16;
        spec.tile_depth = 1;
    }
    require(writer->open(file.string(), spec), "fixture open failed");
    std::vector<float> pixels(19 * 17 * 4);
    for (int y = 0; y < 17; ++y)
        for (int x = 0; x < 19; ++x) {
            const auto index = static_cast<size_t>((y * 19 + x) * 4);
            pixels[index] = static_cast<float>(x) / 20;
            pixels[index + 1] = static_cast<float>(y) / 20;
            pixels[index + 2] = 0.25F;
            pixels[index + 3] = 0.5F;
            if (extension == "exr")
                for (int c = 0; c < 3; ++c)
                    pixels[index + static_cast<size_t>(c)] *= 0.5F;
        }
    require(writer->write_image(OIIO::TypeDesc::FLOAT, pixels.data()), "fixture write failed");
    require(writer->close(), "fixture close failed");
    std::ifstream stream(file, std::ios::binary);
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(stream), {});
}
void codec_tests(const std::filesystem::path& directory)
{
    for (const auto& [extension, compression] :
         {std::pair{"png", "none"}, {"tif", "none"}, {"tif", "zip"}, {"tif", "lzma"}, {"exr", "none"}}) {
        input data;
        data.bytes = fixture(directory, extension, std::string_view(extension) != "png", compression);
        std::string metadata;
        auto handle = open(data, options(), &metadata);
        require(metadata.find("\"bits\":16") != std::string::npos, "native source bit depth lost");
        require(metadata.find("\"width\":19") != std::string::npos, "metadata dimensions lost");
        arc_region_v1 region{.struct_size = sizeof(region),
                             .struct_version = 1,
                             .x = 15,
                             .y = 15,
                             .width = 4,
                             .height = 2,
                             .row_stride = 24};
        arc_mut_buffer_t query{};
        require(arc_image_read(handle, &region, &query, nullptr) == ARC_BUFFER_TOO_SMALL && query.required == 48,
                "tile query wrong");
        std::vector<unsigned char> pixels(48, 0xD7);
        arc_mut_buffer_t buffer{pixels.data(), 47, 0};
        require(arc_image_read(handle, &region, &buffer, nullptr) == ARC_BUFFER_TOO_SMALL && pixels[0] == 0xD7,
                "small output modified");
        buffer.capacity = 48;
        const auto read_status = arc_image_read(handle, &region, &buffer, nullptr);
        if (read_status != ARC_OK)
            throw std::runtime_error(std::string(extension) + " edge tile: " + std::to_string(read_status) + " " +
                                     last_error());
        const auto expected_red = std::string_view(extension) == "exr" ? 96 : 191;
        require(std::abs(static_cast<int>(pixels[0]) - expected_red) <= 1 && pixels[3] >= 127 && pixels[3] <= 128 &&
                    pixels[16] == 0,
                "tile pixels/stride/alpha wrong");
        require(arc_image_read(handle, &region, &buffer, nullptr) == ARC_OK,
                "repeated ROI must retain brokered input after codec rewind");
        region.y = 0;
        require(arc_image_read(handle, &region, &buffer, nullptr) == ARC_OK,
                "backwards ROI must retain brokered input after codec rewind");
        region.y = 15;
        std::atomic<bool> signal{true};
        arc_cancel_token_t token{
            .struct_size = sizeof(token), .struct_version = 1, .is_cancelled = cancelled, .user_data = &signal};
        std::fill(pixels.begin(), pixels.end(), 0xD7);
        require(arc_image_read(handle, &region, &buffer, &token) == ARC_CANCELLED && buffer.required == 0 &&
                    pixels[0] == 0xD7,
                "cancel returned partial bytes");
        region.x = 19;
        require(arc_image_read(handle, &region, &buffer, nullptr) == ARC_INVALID_ARGUMENT,
                "out of bounds region accepted");
        require(arc_image_close(handle) == ARC_OK && arc_image_close(handle) == ARC_CLOSED, "double close wrong");
        require(arc_image_read(handle, &region, &buffer, nullptr) == ARC_CLOSED, "stale handle accepted");
        auto config = options(ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED);
        handle = open(data, config);
        region.x = 15;
        region.row_stride = 64;
        std::vector<float> floats(32, -1);
        buffer = {floats.data(), floats.size() * sizeof(float), 0};
        require(arc_image_read(handle, &region, &buffer, nullptr) == ARC_OK, "float tile failed");
        require(std::isfinite(floats[0]) && floats[3] > .49F && floats[3] < .51F, "float tile alpha wrong");
        if (std::abs(floats[0] -
                     (metadata.find("\"sourceColorSpace\":\"linear\"") != std::string::npos ? .375F : .261261F)) >=
            .002F)
            throw std::runtime_error(std::string(extension) + " float red=" + std::to_string(floats[0]) + " " +
                                     metadata);
        require(arc_image_close(handle) == ARC_OK, "float reader close failed");
        config = options();
        config.limits.max_width = 18;
        auto source = io(data);
        arc_handle_t refused = UINT64_MAX;
        buffer = {};
        require(arc_image_open(&source, &config, &refused, &buffer, nullptr) == ARC_RESOURCE_LIMIT && refused == 0,
                "decompression dimension bomb not refused");
        config = options();
        config.struct_version = 2;
        require(arc_image_open(&source, &config, &refused, &buffer, nullptr) == ARC_VERSION_MISMATCH,
                "wrong version accepted");
        config = options();
        data.fail = true;
        require(arc_image_open(&source, &config, &refused, &buffer, nullptr) == ARC_IO && refused == 0,
                "failed IO accepted");
        data.failure = -99;
        require(arc_image_open(&source, &config, &refused, &buffer, nullptr) == ARC_IO,
                "unknown callback status escaped closed ABI");
        data.fail = false;
        config.limits.max_input_bytes = data.bytes.size() - 1;
        require(arc_image_open(&source, &config, &refused, &buffer, nullptr) == ARC_RESOURCE_LIMIT,
                "input admission budget reported invalid arguments");
        config = options();
        config.limits.timeout_ms = 1;
        data.delay_ms = 3;
        require(arc_image_open(&source, &config, &refused, &buffer, nullptr) == ARC_RESOURCE_LIMIT && refused == 0,
                "callback deadline did not refuse late result");
        data.delay_ms = 0;
        config = options();
        data.short_read = true;
        require(arc_image_open(&source, &config, &refused, &buffer, nullptr) == ARC_IO, "short callback accepted");
    }
}
void lifetime_tests(const std::filesystem::path& directory)
{
    input data;
    data.bytes = fixture(directory, "tif", true);
    std::vector<arc_handle_t> held;
    for (int i = 0; i < 64; ++i)
        held.push_back(open(data, options()));
    auto source = io(data);
    auto config = options();
    arc_handle_t refused = UINT64_MAX;
    std::vector<char> json(65536);
    arc_mut_buffer_t output{json.data(), json.size(), 0};
    require(arc_image_open(&source, &config, &refused, &output, nullptr) == ARC_RESOURCE_LIMIT && refused == 0 &&
                output.required == 0,
            "handle cap failed");
    for (const auto handle : held)
        require(arc_image_close(handle) == ARC_OK, "handle drain failed");
    auto handle = open(data, options());
    uint32_t callbacks = 0;
    data.on_read = [&] {
        ++callbacks;
        require(arc_image_close(handle) == ARC_BUSY, "callback close must refuse instead of self-draining");
        arc_region_v1 recursive{
            .struct_size = sizeof(recursive), .struct_version = 1, .width = 1, .height = 1, .row_stride = 4};
        unsigned char bytes[4]{0xD7, 0xD7, 0xD7, 0xD7};
        arc_mut_buffer_t recursive_output{bytes, sizeof(bytes), UINT64_MAX};
        require(arc_image_read(handle, &recursive, &recursive_output, nullptr) == ARC_BUSY &&
                    recursive_output.required == 0 && bytes[0] == 0xD7,
                "callback read must refuse before borrowing its own mutex");
    };
    arc_region_v1 first{.struct_size = sizeof(first), .struct_version = 1, .width = 1, .height = 1, .row_stride = 4};
    unsigned char first_bytes[4]{};
    arc_mut_buffer_t first_output{first_bytes, sizeof(first_bytes), 0};
    require(arc_image_read(handle, &first, &first_output, nullptr) == ARC_OK && callbacks > 0,
            "outer callback read must retain ownership after reentrant refusals");
    data.on_read = {};
    require(arc_image_close(handle) == ARC_OK, "reader must close after reentrant refusal drains");
    handle = open(data, options());
    data.block = true;
    auto pending = std::async(std::launch::async, [&] {
        arc_region_v1 region{
            .struct_size = sizeof(region), .struct_version = 1, .width = 2, .height = 2, .row_stride = 8};
        unsigned char pixels[16]{};
        arc_mut_buffer_t target{pixels, sizeof(pixels), 0};
        return arc_image_read(handle, &region, &target, nullptr);
    });
    {
        std::unique_lock lock(data.gate);
        require(data.changed.wait_for(lock, std::chrono::seconds(5), [&] { return data.entered.load(); }),
                "codec did not borrow callback");
    }
    arc_region_v1 region{.struct_size = sizeof(region), .struct_version = 1, .width = 1, .height = 1, .row_stride = 4};
    unsigned char busy_pixels[4]{0xD7, 0xD7, 0xD7, 0xD7};
    arc_mut_buffer_t busy_output{busy_pixels, sizeof(busy_pixels), 0};
    require(arc_image_read(handle, &region, &busy_output, nullptr) == ARC_BUSY && busy_output.required == 0 &&
                busy_pixels[0] == 0xD7,
            "concurrent read did not refuse without output");
    auto closing = std::async(std::launch::async, [&] { return arc_image_close(handle); });
    require(closing.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout,
            "close did not drain borrowed call");
    data.block = false;
    data.changed.notify_all();
    require(pending.get() == ARC_OK && closing.get() == ARC_OK, "borrowed call/close failed");
    input corrupt;
    corrupt.bytes = {137, 80, 78, 71, 13, 10, 26, 10, 0};
    source = io(corrupt);
    output = {};
    require(arc_image_open(&source, &config, &refused, &output, nullptr) == ARC_CORRUPT && refused == 0,
            "malformed codec accepted");
}
void subimage_tests(const std::filesystem::path& directory)
{
    const auto file = directory / "pages.tif";
    auto writer = OIIO::ImageOutput::create(file.string());
    require(writer != nullptr, "multipage TIFF writer missing");
    OIIO::ImageSpec spec(8, 8, 4, OIIO::TypeDesc::UINT16);
    spec.alpha_channel = 3;
    spec.attribute("compression", "zip");
    std::vector<float> pixels(8 * 8 * 4, 0.25F);
    for (size_t i = 3; i < pixels.size(); i += 4)
        pixels[i] = 1.0F;
    require(writer->open(file.string(), spec), "first TIFF page failed");
    require(writer->write_image(OIIO::TypeDesc::FLOAT, pixels.data()), "first TIFF page write failed");
    require(writer->open(file.string(), spec, OIIO::ImageOutput::AppendSubimage), "second TIFF page failed");
    for (size_t i = 0; i < pixels.size(); ++i)
        if (i % 4 != 3)
            pixels[i] = 0.75F;
    require(writer->write_image(OIIO::TypeDesc::FLOAT, pixels.data()) && writer->close(),
            "second TIFF page write failed");
    std::ifstream stream(file, std::ios::binary);
    input data;
    data.bytes = std::vector<unsigned char>(std::istreambuf_iterator<char>(stream), {});
    auto config = options();
    config.subimage = 1;
    std::string metadata;
    const auto handle = open(data, config, &metadata);
    require(metadata.find("\"subimages\":2") != std::string::npos &&
                metadata.find("\"subimage\":1") != std::string::npos,
            "selected TIFF page inventory lost");
    arc_region_v1 region{.struct_size = sizeof(region), .struct_version = 1, .width = 1, .height = 1, .row_stride = 4};
    unsigned char decoded[4]{};
    arc_mut_buffer_t output{decoded, sizeof(decoded), 0};
    require(arc_image_read(handle, &region, &output, nullptr) == ARC_OK && decoded[0] >= 190 && decoded[0] <= 192 &&
                decoded[3] == 255,
            "selected TIFF page pixels wrong");
    require(arc_image_close(handle) == ARC_OK, "selected TIFF page close failed");
    auto source = io(data);
    arc_handle_t refused = UINT64_MAX;
    output = {};
    config.subimage = 2;
    require(arc_image_open(&source, &config, &refused, &output, nullptr) == ARC_NOT_FOUND && refused == 0,
            "missing TIFF page accepted");
    config.subimage = 0;
    config.limits.max_items = 1;
    require(arc_image_open(&source, &config, &refused, &output, nullptr) == ARC_RESOURCE_LIMIT && refused == 0,
            "multipage TIFF item cap failed");
}
void mip_tests(const std::filesystem::path& directory)
{
    const auto file = directory / "mips.exr";
    auto writer = OIIO::ImageOutput::create(file.string());
    require(writer != nullptr, "EXR mip writer missing");
    OIIO::ImageSpec spec(16, 16, 4, OIIO::TypeDesc::HALF);
    spec.alpha_channel = 3;
    spec.tile_width = spec.tile_height = 16;
    spec.tile_depth = 1;
    spec.attribute("textureformat", "Plain Texture");
    for (int mip = 0; mip < 5; ++mip) {
        spec.width = spec.height = 16 >> mip;
        require(
            writer->open(file.string(), spec, mip == 0 ? OIIO::ImageOutput::Create : OIIO::ImageOutput::AppendMIPLevel),
            "EXR mip open failed");
        std::vector<float> pixels(static_cast<size_t>(spec.width * spec.height * 4), .25F + .1F * mip);
        for (size_t i = 3; i < pixels.size(); i += 4)
            pixels[i] = 1.0F;
        require(writer->write_image(OIIO::TypeDesc::FLOAT, pixels.data()), "EXR mip write failed");
    }
    require(writer->close(), "EXR mip close failed");
    writer.reset();
    std::ifstream stream(file, std::ios::binary);
    input data;
    data.bytes = std::vector<unsigned char>(std::istreambuf_iterator<char>(stream), {});
    auto config = options(ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED);
    config.mip = 1;
    std::string metadata;
    const auto handle = open(data, config, &metadata);
    require(metadata.find("\"mips\":5") != std::string::npos && metadata.find("\"width\":8") != std::string::npos,
            "EXR mip inventory or selected dimensions lost");
    arc_region_v1 region{
        .struct_size = sizeof(region), .struct_version = 1, .x = 7, .y = 7, .width = 1, .height = 1, .row_stride = 16};
    float decoded[4]{};
    arc_mut_buffer_t output{decoded, sizeof(decoded), 0};
    require(arc_image_read(handle, &region, &output, nullptr) == ARC_OK && std::abs(decoded[0] - .35F) < .001F &&
                decoded[3] == 1.0F,
            "selected EXR mip corner pixels wrong");
    require(arc_image_close(handle) == ARC_OK, "selected EXR mip close failed");
    auto source = io(data);
    arc_handle_t refused = UINT64_MAX;
    output = {};
    config.mip = 5;
    require(arc_image_open(&source, &config, &refused, &output, nullptr) == ARC_NOT_FOUND && refused == 0,
            "missing EXR mip accepted");
    config.mip = 0;
    config.limits.max_items = 4;
    require(arc_image_open(&source, &config, &refused, &output, nullptr) == ARC_RESOURCE_LIMIT && refused == 0,
            "EXR mip inventory item cap failed");
}
void invalid_float_tests(const std::filesystem::path& directory)
{
    for (int example = 0; example < 3; ++example) {
        const auto file = directory / (example == 2 ? "overflow.tif" : "invalid.exr");
        auto writer = OIIO::ImageOutput::create(file.string());
        require(writer != nullptr, "float error fixture writer missing");
        OIIO::ImageSpec spec(2, 2, 4, OIIO::TypeDesc::FLOAT);
        spec.alpha_channel = 3;
        spec.attribute("oiio:ColorSpace", example == 2 ? "srgb_rec709_scene" : "Linear");
        std::vector<float> pixels(16, 0.25F);
        for (size_t i = 3; i < pixels.size(); i += 4)
            pixels[i] = 1.0F;
        if (example == 0)
            pixels[0] = std::numeric_limits<float>::infinity();
        else if (example == 1)
            pixels[3] = 2.0F;
        else
            pixels[0] = 1.0e30F;
        require(writer->open(file.string(), spec) && writer->write_image(OIIO::TypeDesc::FLOAT, pixels.data()) &&
                    writer->close(),
                "float error fixture write failed");
        writer.reset();
        std::ifstream stream(file, std::ios::binary);
        input data;
        data.bytes = std::vector<unsigned char>(std::istreambuf_iterator<char>(stream), {});
        const auto handle = open(data, options(ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED));
        arc_region_v1 region{
            .struct_size = sizeof(region), .struct_version = 1, .width = 1, .height = 1, .row_stride = 16};
        unsigned char decoded[16];
        std::fill(std::begin(decoded), std::end(decoded), 0xD7);
        arc_mut_buffer_t output{decoded, sizeof(decoded), 0};
        require(arc_image_read(handle, &region, &output, nullptr) == ARC_CORRUPT && output.required == 0 &&
                    std::all_of(std::begin(decoded), std::end(decoded), [](auto value) { return value == 0xD7; }),
                "invalid float profile returned visible pixels");
        require(arc_image_close(handle) == ARC_OK, "float error fixture close failed");
    }
}
} // namespace
int main()
{
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("arc-image-codecs-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(directory);
    try {
        codec_tests(directory);
        subimage_tests(directory);
        mip_tests(directory);
        invalid_float_tests(directory);
        lifetime_tests(directory);
        std::filesystem::remove_all(directory);
        std::cout
            << "PNG/TIFF/EXR precision, edge tiles, failure, limits, cancellation, handle cap and draining passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::filesystem::remove_all(directory);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
