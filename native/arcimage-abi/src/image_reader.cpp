// SPDX-License-Identifier: AGPL-3.0-only
#include "arc_native_abi_internal.hpp"
#include <OpenImageIO/filesystem.h>
#include <OpenImageIO/imageio.h>
#include <algorithm>
#include <arc/arc_slate_image_abi.h>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

// The pinned static OIIO build embeds these plugin factories in the versioned namespace.
// Direct binding excludes dynamic plugin discovery and environment-selected libraries.
OIIO_NAMESPACE_BEGIN
ImageInput* png_input_imageio_create();
ImageInput* tiff_input_imageio_create();
ImageInput* openexr_input_imageio_create();
OIIO_NAMESPACE_END

namespace {
constexpr uint32_t domain = 0x494D4147U;
constexpr uint32_t image_kind = 0x494D4147U;
constexpr uint64_t max_tile = 64ULL * 1024 * 1024;
constexpr uint64_t max_pixels = 268435456;
OIIO::ImageInput::unique_ptr create_codec(std::string_view format)
{
    if (format == "png")
        return OIIO::ImageInput::unique_ptr(OIIO::png_input_imageio_create());
    if (format == "tiff")
        return OIIO::ImageInput::unique_ptr(OIIO::tiff_input_imageio_create());
    if (format == "openexr")
        return OIIO::ImageInput::unique_ptr(OIIO::openexr_input_imageio_create());
    return {};
}
arc_status_t fail(arc_status_t code, const char* text)
{
    return arc::abi::fail(code, text, domain);
}
template <class F> arc_status_t guarded(F&& action) noexcept
{
    try {
        return action();
    } catch (const std::bad_alloc&) {
        return fail(ARC_OUT_OF_MEMORY, "Image allocation failed");
    } catch (...) {
        return fail(ARC_INTERNAL, "Image codec failed");
    }
}
class source final : public OIIO::Filesystem::IOProxy {
  public:
    explicit source(arc_io_v1 io) : IOProxy("", Read), io_(io)
    {
    }
    const char* proxytype() const override
    {
        return "arc-brokered-input";
    }
    size_t size() const override
    {
        return static_cast<size_t>(io_.length);
    }
    bool seek(int64_t position) override
    {
        if (position < 0 || static_cast<uint64_t>(position) > io_.length)
            return false;
        m_pos = position;
        return true;
    }
    size_t read(void* bytes, size_t count) override
    {
        const auto actual = pread(bytes, count, m_pos);
        m_pos += static_cast<int64_t>(actual);
        return actual;
    }
    size_t pread(void* bytes, size_t count, int64_t position) override
    {
        std::lock_guard lock(gate_);
        if (check() != ARC_OK || position < 0 || static_cast<uint64_t>(position) > io_.length)
            return 0;
        count = static_cast<size_t>(std::min<uint64_t>(count, io_.length - static_cast<uint64_t>(position)));
        uint64_t done = 0;
        const auto code = io_.read_at(io_.context, static_cast<uint64_t>(position), bytes, count, &done);
        if ((code != ARC_OK && code != ARC_END_OF_STREAM) || done != count) {
            status = code >= ARC_INTERNAL && code <= ARC_INVALID_ARGUMENT ? code : ARC_IO;
            return 0;
        }
        return static_cast<size_t>(done);
    }
    void begin(const arc_cancel_token_t* token, uint32_t timeout)
    {
        cancel_ = token;
        status = ARC_OK;
        deadline_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    }
    void end()
    {
        cancel_ = nullptr;
    }
    arc_status_t check()
    {
        if (status != ARC_OK)
            return status;
        status = arc::abi::check_cancelled(cancel_);
        if (status == ARC_OK && std::chrono::steady_clock::now() >= deadline_)
            status = ARC_RESOURCE_LIMIT;
        return status;
    }
    arc_status_t status = ARC_OK;

  private:
    arc_io_v1 io_;
    std::mutex gate_;
    const arc_cancel_token_t* cancel_ = nullptr;
    std::chrono::steady_clock::time_point deadline_;
};
struct reader {
    std::unique_ptr<source> input;
    OIIO::ImageInput::unique_ptr codec;
    OIIO::ImageSpec spec;
    arc_image_options_v1 options{};
    std::mutex gate;
    ~reader()
    {
        if (codec)
            codec->close();
    }
};
struct operation {
    source& input;
    operation(source& value, const arc_cancel_token_t* cancel, uint32_t timeout) : input(value)
    {
        input.begin(cancel, timeout);
    }
    ~operation()
    {
        input.end();
    }
};
arc::abi::handle_table& handles()
{
    static arc::abi::handle_table table(64);
    return table;
}
arc_status_t validate_limits(const arc_limits_v1& limit)
{
    auto status = arc::abi::validate_record(&limit, sizeof(limit));
    if (status != ARC_OK)
        return status;
    if (!limit.max_input_bytes || !limit.max_memory_bytes || !limit.max_output_bytes || !limit.max_width ||
        !limit.max_height || !limit.max_items || !limit.timeout_ms)
        return fail(ARC_INVALID_ARGUMENT, "Positive image limits required");
    if (limit.max_input_bytes > 4ULL * 1024 * 1024 * 1024 || limit.max_memory_bytes > 4ULL * 1024 * 1024 * 1024 ||
        limit.max_output_bytes > max_tile || limit.max_width > 65535 || limit.max_height > 65535 ||
        limit.max_items > 4096 || limit.timeout_ms > 30000)
        return fail(ARC_RESOURCE_LIMIT, "Image limits exceed producer profile");
    return ARC_OK;
}
bool valid_utf8(std::string_view value)
{
    for (size_t i = 0; i < value.size();) {
        const auto first = static_cast<unsigned char>(value[i++]);
        if (first == 0)
            return false;
        if (first < 128)
            continue;
        uint32_t code = 0, minimum = 0;
        size_t count = 0;
        if (first >= 0xC2 && first <= 0xDF) {
            code = first & 31U;
            count = 1;
            minimum = 128;
        } else if (first >= 0xE0 && first <= 0xEF) {
            code = first & 15U;
            count = 2;
            minimum = 2048;
        } else if (first >= 0xF0 && first <= 0xF4) {
            code = first & 7U;
            count = 3;
            minimum = 65536;
        } else
            return false;
        if (count > value.size() - i)
            return false;
        for (size_t j = 0; j < count; ++j) {
            const auto next = static_cast<unsigned char>(value[i++]);
            if ((next & 0xC0U) != 0x80U)
                return false;
            code = (code << 6U) | (next & 63U);
        }
        if (code < minimum || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF))
            return false;
    }
    return true;
}
arc_status_t valid_spec(const OIIO::ImageSpec& spec, const arc_limits_v1& limit)
{
    if (spec.width <= 0 || spec.height <= 0 || spec.depth != 1 || spec.deep || spec.nchannels < 1 ||
        spec.nchannels > 64 || spec.channelnames.size() != static_cast<size_t>(spec.nchannels) ||
        spec.alpha_channel >= spec.nchannels || spec.alpha_channel < -1 || spec.tile_width < 0 ||
        spec.tile_height < 0 || (spec.tile_width == 0) != (spec.tile_height == 0) || spec.tile_width > 65535 ||
        spec.tile_height > 65535 || spec.x > INT32_MAX - spec.width || spec.y > INT32_MAX - spec.height)
        return fail(ARC_UNSUPPORTED, "Image geometry or channels unsupported");
    if (static_cast<uint32_t>(spec.width) > limit.max_width || static_cast<uint32_t>(spec.height) > limit.max_height ||
        static_cast<uint64_t>(spec.width) * spec.height > max_pixels)
        return fail(ARC_RESOURCE_LIMIT, "Image dimensions exceed admitted limits");
    if (spec.image_bytes() > limit.max_memory_bytes)
        return fail(ARC_RESOURCE_LIMIT, "Image decode working set exceeds admitted memory");
    for (const auto& name : spec.channelnames) {
        if (name.empty() || name.size() > 256 || !valid_utf8(name))
            return fail(ARC_RESOURCE_LIMIT, "Image channel names exceed bounds");
    }
    const auto color_space = spec.get_string_attribute("oiio:ColorSpace");
    if (color_space.size() > 256 || !valid_utf8(std::string_view(color_space.data(), color_space.size())))
        return fail(ARC_CORRUPT, "Image color metadata is invalid");
    return ARC_OK;
}
std::string quote(const std::string& value)
{
    std::string result = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') {
            result += '\\';
            result += static_cast<char>(c);
        } else if (c < 32) {
            result += "\\u00";
            result += hex[c >> 4];
            result += hex[c & 15];
        } else
            result += static_cast<char>(c);
    }
    return result + '"';
}
bool source_linear(const reader& value)
{
    const auto space = value.spec.get_string_attribute("oiio:ColorSpace");
    return space == "Linear" || space == "linear" || space == "lin_rec709" || space == "lin_rec709_scene" ||
           std::string_view(value.codec->format_name()) == "openexr";
}
float source_gamma(const reader& value)
{
    if (source_linear(value))
        return 1.0F;
    const auto space = value.spec.get_string_attribute("oiio:ColorSpace");
    if (space == "g22_rec709_scene" || space == "Gamma2.2" || space == "GammaCorrected2.2")
        return 2.2F;
    if (space == "g24_rec709_scene" || space == "Gamma2.4" || space == "GammaCorrected2.4")
        return 2.4F;
    if (space == "g18_rec709_scene" || space == "Gamma1.8" || space == "GammaCorrected1.8")
        return 1.8F;
    const auto gamma = value.spec.get_float_attribute("oiio:Gamma", 0.0F);
    if (std::isfinite(gamma) && gamma > 0 && gamma <= 10)
        return gamma;
    if (space.empty() || space == "sRGB" || space == "srgb_rec709_scene" || space == "srgb_texture")
        return -1.0F;
    return 0.0F;
}
std::string source_color_space(const reader& value)
{
    const float gamma = source_gamma(value);
    if (gamma == 1.0F)
        return "linear";
    if (gamma == -1.0F)
        return "sRGB";
    if (gamma > 0.0F)
        return "gamma" + std::to_string(gamma);
    return std::string(value.spec.get_string_attribute("oiio:ColorSpace"));
}
std::string metadata(const reader& value, uint32_t subimages, uint32_t mips)
{
    const auto& s = value.spec;
    bool loss = value.options.format == ARC_FORMAT_RGBA8 || s.nchannels > 4;
    for (int channel = 0; channel < s.nchannels; ++channel) {
        const auto type = s.channelformat(channel);
        loss = loss || type == OIIO::TypeDesc::DOUBLE || type == OIIO::TypeDesc::UINT || type == OIIO::TypeDesc::INT;
    }
    std::string json =
        "{\"version\":1,\"width\":" + std::to_string(s.width) + ",\"height\":" + std::to_string(s.height) +
        ",\"subimages\":" + std::to_string(subimages) + ",\"mips\":" + std::to_string(mips) +
        ",\"subimage\":" + std::to_string(value.options.subimage) + ",\"mip\":" + std::to_string(value.options.mip) +
        ",\"format\":" + std::to_string(value.options.format) + ",\"codec\":" + quote(value.codec->format_name()) +
        ",\"sourceColorSpace\":" + quote(source_color_space(value)) +
        ",\"conversionLoss\":" + (loss ? "true" : "false") + ",\"channels\":[";
    for (int i = 0; i < s.nchannels; ++i) {
        if (i)
            json += ',';
        const auto type = s.channelformat(i);
        json += "{\"name\":" + quote(s.channelnames[static_cast<size_t>(i)]) + ",\"type\":" + quote(type.c_str()) +
                ",\"bits\":" +
                std::to_string(s.get_int_attribute("oiio:BitsPerSample", static_cast<int>(type.size() * 8))) + '}';
    }
    return json + "]}";
}
const char* identify(const unsigned char* data, size_t count)
{
    constexpr unsigned char png[] = {137, 80, 78, 71, 13, 10, 26, 10};
    if (count >= 8 && std::memcmp(data, png, 8) == 0)
        return "png";
    if (count >= 4 && ((data[0] == 'I' && data[1] == 'I' && (data[2] == 42 || data[2] == 43) && data[3] == 0) ||
                       (data[0] == 'M' && data[1] == 'M' && data[2] == 0 && (data[3] == 42 || data[3] == 43))))
        return "tiff";
    if (count >= 4 && data[0] == 0x76 && data[1] == 0x2f && data[2] == 0x31 && data[3] == 0x01)
        return "openexr";
    return nullptr;
}
float linearize(float v)
{
    return v <= 0.04045F ? v / 12.92F : std::pow((v + 0.055F) / 1.055F, 2.4F);
}
} // namespace

arc_status_t ARC_ABI_CALL arc_image_open(const arc_io_v1* io, const arc_image_options_v1* options, arc_handle_t* image,
                                         arc_mut_buffer_t* output, const arc_cancel_token_t* cancel)
{
    if (image)
        *image = 0;
    if (output)
        output->required = 0;
    const auto result_status = guarded([&]() -> arc_status_t {
        if (!image || !output)
            return fail(ARC_INVALID_ARGUMENT, "Image outputs required");
        auto status = arc::abi::validate_record(io, sizeof(arc_io_v1));
        if (status != ARC_OK)
            return status;
        status = arc::abi::validate_record(options, sizeof(arc_image_options_v1));
        if (status != ARC_OK)
            return status;
        status = validate_limits(options->limits);
        if (status != ARC_OK)
            return status;
        status = arc::abi::check_cancelled(cancel);
        if (status != ARC_OK)
            return status;
        if (!io->read_at || !io->length || io->length > io->max_length || io->length > INT64_MAX || options->reserved ||
            options->subimage >= options->limits.max_items || options->mip >= options->limits.max_items)
            return fail(ARC_INVALID_ARGUMENT, "Invalid image input or options");
        if (io->length > options->limits.max_input_bytes)
            return fail(ARC_RESOURCE_LIMIT, "Image input exceeds admission budget");
        if (options->format != ARC_FORMAT_RGBA8 && options->format != ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED)
            return fail(ARC_UNSUPPORTED, "Unknown image output format");
        auto value = std::make_shared<reader>();
        value->options = *options;
        value->input = std::make_unique<source>(*io);
        operation active(*value->input, cancel, options->limits.timeout_ms);
        unsigned char magic[8]{};
        const auto count = value->input->pread(magic, sizeof(magic), 0);
        if (value->input->check() != ARC_OK)
            return fail(value->input->status, "Image input failed");
        const char* format = identify(magic, count);
        if (!format)
            return fail(ARC_UNSUPPORTED, "Only PNG TIFF EXR admitted");
        // Select exactly the admitted built-in plugin; never probe unrelated codecs or a caller path.
        value->codec = create_codec(format);
        if (!value->codec || !value->codec->set_ioproxy(value->input.get()))
            return fail(ARC_UNSUPPORTED, "Admitted image codec unavailable");
        OIIO::ImageSpec config;
        config.attribute("oiio:UnassociatedAlpha", 1);
        config.attribute("oiio:Limits", 1);
        if (!value->codec->open(std::string("brokered.") + (std::string_view(format) == "openexr" ? "exr" : format),
                                value->spec, config))
            return fail(value->input->check() == ARC_OK ? ARC_CORRUPT : value->input->status,
                        "Image header decode failed");
        uint32_t subimages = 0;
        uint32_t selected_mips = 0;
        uint32_t total_items = 0;
        for (uint32_t sub = 0; sub <= options->limits.max_items; ++sub) {
            if (!value->codec->seek_subimage(static_cast<int>(sub), 0))
                break;
            ++subimages;
            for (uint32_t mip = 0; mip <= options->limits.max_items; ++mip) {
                if (!value->codec->seek_subimage(static_cast<int>(sub), static_cast<int>(mip)))
                    break;
                if (++total_items > options->limits.max_items)
                    return fail(ARC_RESOURCE_LIMIT, "Image item count exceeds limits");
                if (sub == options->subimage)
                    ++selected_mips;
                if (value->input->check() != ARC_OK)
                    return fail(value->input->status, "Image operation expired");
            }
        }
        // Some codec directory iterators leave their upstream reader at EOF after a failed seek.
        // Reopen the immutable brokered input before selecting the actual decode state.
        value->codec->close();
        value->codec = create_codec(format);
        value->input->seek(0);
        if (!value->codec || !value->codec->set_ioproxy(value->input.get()) ||
            !value->codec->open(std::string("brokered.") + (std::string_view(format) == "openexr" ? "exr" : format),
                                value->spec, config))
            return fail(value->input->check() == ARC_OK ? ARC_CORRUPT : value->input->status,
                        "Image header reopen failed");
        if (options->subimage >= subimages || options->mip >= selected_mips ||
            !value->codec->seek_subimage(static_cast<int>(options->subimage), static_cast<int>(options->mip)))
            return fail(ARC_NOT_FOUND, "Image subimage or mip missing");
        value->spec = value->codec->spec();
        status = valid_spec(value->spec, options->limits);
        if (status != ARC_OK)
            return status;
        if (options->format == ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED && source_gamma(*value) == 0.0F)
            return fail(ARC_UNSUPPORTED, "Image color transfer requires an unadmitted transform");
        const auto json = metadata(*value, subimages, selected_mips);
        if (json.size() > 65536 || json.size() > options->limits.max_output_bytes)
            return fail(ARC_RESOURCE_LIMIT, "Image metadata exceeds bounds");
        status = arc::abi::prepare_buffer_output(output, json.size());
        if (status != ARC_OK)
            return status;
        status = value->input->check();
        if (status != ARC_OK) {
            output->required = 0;
            return fail(status, "Image operation expired");
        }
        status = handles().create(image_kind, value, image);
        if (status != ARC_OK) {
            output->required = 0;
            return status;
        }
        std::memcpy(output->data, json.data(), json.size());
        return ARC_OK;
    });
    if (result_status < 0 && output)
        output->required = 0;
    return result_status;
}

arc_status_t ARC_ABI_CALL arc_image_read(arc_handle_t image, const arc_region_v1* region, arc_mut_buffer_t* output,
                                         const arc_cancel_token_t* cancel)
{
    if (output)
        output->required = 0;
    const auto result_status = guarded([&]() -> arc_status_t {
        if (!output)
            return fail(ARC_INVALID_ARGUMENT, "Image pixel output required");
        auto status = arc::abi::validate_record(region, sizeof(arc_region_v1));
        if (status != ARC_OK)
            return status;
        status = arc::abi::check_cancelled(cancel);
        if (status != ARC_OK)
            return status;
        arc::abi::handle_lease lease;
        status = handles().acquire(image, image_kind, &lease);
        if (status != ARC_OK)
            return status;
        auto& value = *lease.as<reader>();
        std::unique_lock lock(value.gate, std::try_to_lock);
        if (!lock.owns_lock())
            return fail(ARC_BUSY, "Image reader already borrowed");
        const auto& s = value.spec;
        if (!region->width || !region->height || region->x >= static_cast<uint32_t>(s.width) ||
            region->y >= static_cast<uint32_t>(s.height) ||
            region->width > static_cast<uint32_t>(s.width) - region->x ||
            region->height > static_cast<uint32_t>(s.height) - region->y || region->first_sample ||
            region->sample_count)
            return fail(ARC_INVALID_ARGUMENT, "Image region out of bounds");
        if (region->width > 2048 || region->height > 2048)
            return fail(ARC_RESOURCE_LIMIT, "Image tile dimensions exceed profile");
        const uint64_t pixel_size = value.options.format == ARC_FORMAT_RGBA8 ? 4 : 16;
        const uint64_t packed = region->width * pixel_size;
        if (region->row_stride < packed || region->row_stride > max_tile ||
            region->height > max_tile / region->row_stride)
            return fail(ARC_RESOURCE_LIMIT, "Image stride exceeds tile limit");
        const uint64_t bytes = region->row_stride * region->height;
        if (bytes > value.options.limits.max_output_bytes)
            return fail(ARC_RESOURCE_LIMIT, "Image tile exceeds output budget");
        status = arc::abi::prepare_buffer_output(output, bytes);
        if (status != ARC_OK)
            return status;
        const uint64_t scratch_pixels =
            s.tile_width > 0 ? static_cast<uint64_t>(s.tile_width) * s.tile_height : static_cast<uint64_t>(s.width);
        if (scratch_pixels >
                value.options.limits.max_memory_bytes / (static_cast<uint64_t>(s.nchannels) * sizeof(float)) ||
            scratch_pixels * s.nchannels * sizeof(float) + bytes > value.options.limits.max_memory_bytes) {
            output->required = 0;
            return fail(ARC_RESOURCE_LIMIT, "Image tile working set exceeds memory budget");
        }
        operation active(*value.input, cancel, value.options.limits.timeout_ms);
        std::vector<float> scratch(static_cast<size_t>(scratch_pixels * s.nchannels));
        std::vector<unsigned char> result(static_cast<size_t>(bytes), 0);
        const float gamma = source_gamma(value);
        int red = 0, green = s.nchannels >= 3 ? 1 : 0, blue = s.nchannels >= 3 ? 2 : 0, alpha = s.alpha_channel;
        for (int c = 0; c < s.nchannels; ++c) {
            if (s.channelnames[static_cast<size_t>(c)] == "R")
                red = c;
            if (s.channelnames[static_cast<size_t>(c)] == "G")
                green = c;
            if (s.channelnames[static_cast<size_t>(c)] == "B")
                blue = c;
        }
        int cached_x = -1, cached_y = -1;
        for (uint32_t y = 0; y < region->height; ++y) {
            for (uint32_t x = 0; x < region->width; ++x) {
                const int px = static_cast<int>(region->x + x), py = static_cast<int>(region->y + y);
                const int tx = s.tile_width > 0 ? px / s.tile_width * s.tile_width : 0;
                const int ty = s.tile_width > 0 ? py / s.tile_height * s.tile_height : py;
                if (tx != cached_x || ty != cached_y) {
                    if (value.input->check() != ARC_OK) {
                        output->required = 0;
                        return fail(value.input->status, "Image operation expired");
                    }
                    bool ok;
                    if (s.tile_width > 0) {
                        const int w = std::min(s.tile_width, s.width - tx), h = std::min(s.tile_height, s.height - ty);
                        ok = value.codec->read_tiles(static_cast<int>(value.options.subimage),
                                                     static_cast<int>(value.options.mip), s.x + tx, s.x + tx + w,
                                                     s.y + ty, s.y + ty + h, s.z, s.z + 1, 0, s.nchannels,
                                                     OIIO::TypeDesc::FLOAT, scratch.data());
                    } else {
                        OIIO::image_span<float> span(scratch.data(), s.nchannels, s.width, 1, 1);
                        ok = value.codec->read_scanlines(static_cast<int>(value.options.subimage),
                                                         static_cast<int>(value.options.mip), s.y + py, s.y + py + 1, 0,
                                                         s.nchannels, span);
                    }
                    if (!ok) {
                        output->required = 0;
                        return fail(value.input->check() == ARC_OK ? ARC_CORRUPT : value.input->status,
                                    "Image pixel decode failed");
                    }
                    cached_x = tx;
                    cached_y = ty;
                }
                const int row_width = s.tile_width > 0 ? std::min(s.tile_width, s.width - tx) : s.width;
                const auto offset =
                    (static_cast<size_t>(py - ty) * row_width + static_cast<size_t>(px - tx)) * s.nchannels;
                const float* sample = scratch.data() + offset;
                float rgba[4] = {sample[red], sample[green], sample[blue], alpha >= 0 ? sample[alpha] : 1.0F};
                for (const float v : rgba)
                    if (!std::isfinite(v)) {
                        output->required = 0;
                        return fail(ARC_CORRUPT, "Nonfinite image sample");
                    }
                unsigned char* target = result.data() + y * region->row_stride + x * pixel_size;
                if (value.options.format == ARC_FORMAT_RGBA8) {
                    for (int c = 0; c < 4; ++c)
                        target[c] = static_cast<unsigned char>(std::lround(std::clamp(rgba[c], 0.0F, 1.0F) * 255.0F));
                } else {
                    rgba[3] = std::clamp(rgba[3], 0.0F, 1.0F);
                    const bool associated = std::string_view(value.codec->format_name()) == "openexr" &&
                                            !s.get_int_attribute("oiio:UnassociatedAlpha", 0);
                    for (int c = 0; c < 3; ++c) {
                        if (gamma == -1.0F)
                            rgba[c] = linearize(rgba[c]);
                        else if (gamma != 1.0F)
                            rgba[c] = std::copysign(std::pow(std::abs(rgba[c]), gamma), rgba[c]);
                        if (!associated)
                            rgba[c] *= rgba[3];
                    }
                    std::memcpy(target, rgba, sizeof(rgba));
                }
            }
        }
        status = value.input->check();
        if (status != ARC_OK) {
            output->required = 0;
            return fail(status, "Image operation expired");
        }
        std::memcpy(output->data, result.data(), result.size());
        return ARC_OK;
    });
    if (result_status < 0 && output)
        output->required = 0;
    return result_status;
}
arc_status_t ARC_ABI_CALL arc_image_close(arc_handle_t image)
{
    return guarded([&]() { return handles().close(image, image_kind); });
}
