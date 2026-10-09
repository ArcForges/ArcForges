// SPDX-License-Identifier: AGPL-3.0-only
#include "image_session.hpp"

#include "arc_native_abi_internal.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <new>
#include <string_view>

namespace arc::image {
namespace {

// Source kinds accepted after content probing (decision D10).
enum class source_kind : uint32_t { none = 0, png = 1, tiff = 2, exr = 3 };

constexpr size_t probe_bytes = 16;
constexpr int64_t origin_limit = INT64_C(1) << 30;
constexpr char hex_digits[] = "0123456789ABCDEF";

arc_status_t fail_image(arc_status_t status, const char* message)
{
    return arc::abi::fail(status, message, image_error_domain);
}

// Identifies the container from its leading bytes only. Anything outside the PNG, TIFF and EXR
// signatures yields none, so the declared file name never selects a codec.
source_kind detect_source(const unsigned char* magic, size_t count) noexcept
{
    static constexpr unsigned char png_signature[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    if (count >= sizeof(png_signature) && std::memcmp(magic, png_signature, sizeof(png_signature)) == 0) {
        return source_kind::png;
    }
    if (count >= 4) {
        const bool little_endian_tiff = magic[0] == 'I' && magic[1] == 'I' &&
                                        ((magic[2] == 0x2A && magic[3] == 0) || (magic[2] == 0x2B && magic[3] == 0));
        const bool big_endian_tiff = magic[0] == 'M' && magic[1] == 'M' &&
                                     ((magic[2] == 0 && magic[3] == 0x2A) || (magic[2] == 0 && magic[3] == 0x2B));
        if (little_endian_tiff || big_endian_tiff) {
            return source_kind::tiff;
        }
        if (magic[0] == 0x76 && magic[1] == 0x2F && magic[2] == 0x31 && magic[3] == 0x01) {
            return source_kind::exr;
        }
    }
    return source_kind::none;
}

// File-name hints only select the OpenImageIO plugin. The bytes are read through the callback.
const char* hint_name(source_kind source)
{
    switch (source) {
    case source_kind::png:
        return "arc-image.png";
    case source_kind::tiff:
        return "arc-image.tif";
    default:
        return "arc-image.exr";
    }
}

const char* expected_format_name(source_kind source)
{
    switch (source) {
    case source_kind::png:
        return "png";
    case source_kind::tiff:
        return "tiff";
    default:
        return "openexr";
    }
}

const char* metadata_format_name(source_kind source)
{
    switch (source) {
    case source_kind::png:
        return "png";
    case source_kind::tiff:
        return "tiff";
    default:
        return "exr";
    }
}

bool supported_base_type(const OIIO::TypeDesc& type)
{
    return type == OIIO::TypeDesc::UINT8 || type == OIIO::TypeDesc::INT8 || type == OIIO::TypeDesc::UINT16 ||
           type == OIIO::TypeDesc::INT16 || type == OIIO::TypeDesc::UINT32 || type == OIIO::TypeDesc::INT32 ||
           type == OIIO::TypeDesc::HALF || type == OIIO::TypeDesc::FLOAT || type == OIIO::TypeDesc::DOUBLE;
}

const char* type_name(const OIIO::TypeDesc& type)
{
    if (type == OIIO::TypeDesc::UINT8) {
        return "uint8";
    }
    if (type == OIIO::TypeDesc::INT8) {
        return "int8";
    }
    if (type == OIIO::TypeDesc::UINT16) {
        return "uint16";
    }
    if (type == OIIO::TypeDesc::INT16) {
        return "int16";
    }
    if (type == OIIO::TypeDesc::UINT32) {
        return "uint32";
    }
    if (type == OIIO::TypeDesc::INT32) {
        return "int32";
    }
    if (type == OIIO::TypeDesc::HALF) {
        return "half";
    }
    if (type == OIIO::TypeDesc::DOUBLE) {
        return "double";
    }
    return "float";
}

uint32_t type_bits(const OIIO::TypeDesc& type)
{
    if (type == OIIO::TypeDesc::UINT8 || type == OIIO::TypeDesc::INT8) {
        return 8;
    }
    if (type == OIIO::TypeDesc::UINT16 || type == OIIO::TypeDesc::INT16 || type == OIIO::TypeDesc::HALF) {
        return 16;
    }
    if (type == OIIO::TypeDesc::DOUBLE) {
        return 64;
    }
    return 32;
}

bool is_floating_type(const OIIO::TypeDesc& type)
{
    return type == OIIO::TypeDesc::HALF || type == OIIO::TypeDesc::FLOAT || type == OIIO::TypeDesc::DOUBLE;
}

// Wide integers and doubles cannot be held exactly in the float working type.
bool loses_precision_as_float(const OIIO::TypeDesc& type)
{
    return type == OIIO::TypeDesc::UINT32 || type == OIIO::TypeDesc::INT32 || type == OIIO::TypeDesc::DOUBLE;
}

bool multiply_u64(uint64_t left, uint64_t right, uint64_t& product) noexcept
{
    if (left != 0 && right > UINT64_MAX / left) {
        return false;
    }
    product = left * right;
    return true;
}

bool printable_ascii_name(const std::string& name)
{
    if (name.empty() || name.size() > max_channel_name_bytes) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](char ch) {
        const auto value = static_cast<unsigned char>(ch);
        return value >= 0x20 && value <= 0x7E;
    });
}

bool equals_ignore_case(std::string_view left, std::string_view right) noexcept
{
    if (left.size() != right.size()) {
        return false;
    }
    for (size_t index = 0; index < left.size(); ++index) {
        if (std::tolower(static_cast<unsigned char>(left[index])) !=
            std::tolower(static_cast<unsigned char>(right[index]))) {
            return false;
        }
    }
    return true;
}

void append_json_string(std::string& out, std::string_view text)
{
    out.push_back('"');
    for (const char raw : text) {
        const auto ch = static_cast<unsigned char>(raw);
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
            out.push_back(static_cast<char>(ch));
        } else if (ch < 0x20 || ch >= 0x7F) {
            out += "\\u00";
            out.push_back(hex_digits[(ch >> 4U) & 0x0FU]);
            out.push_back(hex_digits[ch & 0x0FU]);
        } else {
            out.push_back(static_cast<char>(ch));
        }
    }
    out.push_back('"');
}

void append_string_array(std::string& out, const std::vector<const char*>& values)
{
    out.push_back('[');
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            out.push_back(',');
        }
        append_json_string(out, values[index]);
    }
    out.push_back(']');
}

float srgb_to_linear(float encoded) noexcept
{
    if (encoded <= 0.04045F) {
        return encoded / 12.92F;
    }
    return std::pow((encoded + 0.055F) / 1.055F, 2.4F);
}

} // namespace

// Binds the per-call cancellation token and deadline to the session and to the callback adapter, and
// clears them when the call ends.
struct image_session::call_scope final {
    call_scope(image_session& session, const arc_cancel_token_t* cancel, uint32_t timeout_ms) : session_(session)
    {
        session_.cancel_ = cancel;
        session_.has_deadline_ = timeout_ms != 0;
        session_.deadline_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        if (session_.proxy_) {
            session_.proxy_->begin_call(cancel, session_.deadline_, session_.has_deadline_);
        }
    }

    ~call_scope()
    {
        session_.cancel_ = nullptr;
        session_.has_deadline_ = false;
        if (session_.proxy_) {
            session_.proxy_->begin_call(nullptr, std::chrono::steady_clock::time_point{}, false);
        }
    }

    call_scope(const call_scope&) = delete;
    call_scope& operator=(const call_scope&) = delete;

  private:
    image_session& session_;
};

image_session::image_session() = default;

image_session::~image_session() = default;

arc_status_t image_session::open(const arc_io_v1& io, const arc_image_options_v1& options,
                                 const arc_cancel_token_t* cancel, std::unique_ptr<image_session>& output)
{
    output.reset();

    arc_status_t status = arc::abi::validate_record(&io, sizeof(arc_io_v1));
    if (status != ARC_OK) {
        return status;
    }
    status = arc::abi::validate_record(&options, sizeof(arc_image_options_v1));
    if (status != ARC_OK) {
        return status;
    }
    status = arc::abi::validate_record(&options.limits, sizeof(arc_limits_v1));
    if (status != ARC_OK) {
        return status;
    }

    if (io.read_at == nullptr) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image input read callback is required");
    }
    if (io.length > io.max_length) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image input length exceeds its declared maximum");
    }
    if (options.reserved != 0) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image options reserved field must be zero");
    }
    if (options.format != ARC_FORMAT_RGBA8 && options.format != ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED &&
        options.format != ARC_FORMAT_FLOAT32_INTERLEAVED) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image output format key is not known");
    }

    const arc_limits_v1& limits = options.limits;
    const bool positive = limits.max_input_bytes != 0 && limits.max_memory_bytes != 0 && limits.max_output_bytes != 0 &&
                          limits.max_width != 0 && limits.max_height != 0 && limits.max_items != 0 &&
                          limits.timeout_ms != 0;
    const bool within_profile =
        limits.max_input_bytes <= hard_max_input_bytes && limits.max_memory_bytes <= hard_max_memory_bytes &&
        limits.max_output_bytes <= hard_max_region_bytes && limits.max_width <= hard_max_dimension &&
        limits.max_height <= hard_max_dimension && limits.max_items <= hard_max_items;
    if (!positive || !within_profile) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image limits are missing or exceed the producer profile");
    }
    if (io.length > limits.max_input_bytes) {
        return fail_image(ARC_RESOURCE_LIMIT, "Image input exceeds the input byte limit");
    }

    std::unique_ptr<image_session> session(new image_session());
    session->limits_ = limits;
    session->format_ = options.format;
    session->proxy_ = std::make_unique<callback_io>("arc-image", io);

    {
        call_scope scope(*session, cancel, limits.timeout_ms);

        // Content probing: the bytes choose the codec, never the declared name.
        unsigned char magic[probe_bytes] = {};
        const auto probe_count = static_cast<size_t>(std::min<uint64_t>(probe_bytes, io.length));
        const size_t magic_read = session->proxy_->pread(magic, probe_count, 0);
        if (session->proxy_->latched_status() != ARC_OK) {
            return fail_image(session->proxy_->latched_status(), "Image input could not be read");
        }
        const source_kind source = detect_source(magic, magic_read);
        if (source == source_kind::none) {
            return fail_image(ARC_UNSUPPORTED, "Image content is not a supported PNG, TIFF or EXR file");
        }

        // The callback proxy and the straight-alpha request travel in the open configuration (OpenImageIO's
        // documented route, ImageInput::open with an ioproxy attribute). Without the request the PNG and TIFF
        // readers premultiply straight alpha as they read, which loses 8-bit precision for rgba8 output.
        OIIO::ImageSpec reader_config;
        OIIO::Filesystem::IOProxy* proxy = session->proxy_.get();
        reader_config.attribute("oiio:ioproxy", OIIO::TypeDesc::PTR, &proxy);
        if (source == source_kind::png || source == source_kind::tiff) {
            reader_config.attribute("oiio:UnassociatedAlpha", 1);
        }
        std::unique_ptr<OIIO::ImageInput> input = OIIO::ImageInput::open(hint_name(source), &reader_config);
        if (!input) {
            // The reader's own message is replaced by ours, so drain it rather than let it accumulate.
            (void)OIIO::geterror();
            if (session->proxy_->latched_status() != ARC_OK) {
                return fail_image(session->proxy_->latched_status(), "Image input could not be read");
            }
            return fail_image(ARC_CORRUPT, "Image header could not be parsed");
        }
        if (std::string_view(input->format_name()) != expected_format_name(source)) {
            return fail_image(ARC_CORRUPT, "Image header disagrees with the detected format");
        }
        session->input_ = std::move(input);

        // Subimage and mip counts are bounded by max_items before any level is selected.
        uint32_t subimage_count = 0;
        for (;;) {
            const OIIO::ImageSpec dimensions = session->input_->spec_dimensions(static_cast<int>(subimage_count), 0);
            if (dimensions.format == OIIO::TypeUnknown) {
                break;
            }
            ++subimage_count;
            if (subimage_count > limits.max_items) {
                return fail_image(ARC_RESOURCE_LIMIT, "Image subimage count exceeds the item limit");
            }
        }
        if (subimage_count == 0) {
            return fail_image(ARC_CORRUPT, "Image has no readable subimage");
        }
        if (options.subimage >= subimage_count) {
            return fail_image(ARC_NOT_FOUND, "Image subimage does not exist");
        }

        uint32_t mip_count = 0;
        for (;;) {
            const OIIO::ImageSpec dimensions =
                session->input_->spec_dimensions(static_cast<int>(options.subimage), static_cast<int>(mip_count));
            if (dimensions.format == OIIO::TypeUnknown) {
                break;
            }
            ++mip_count;
            if (mip_count > limits.max_items) {
                return fail_image(ARC_RESOURCE_LIMIT, "Image mip count exceeds the item limit");
            }
        }
        if (options.mip >= mip_count) {
            return fail_image(ARC_NOT_FOUND, "Image mip level does not exist");
        }

        if (!session->input_->seek_subimage(static_cast<int>(options.subimage), static_cast<int>(options.mip))) {
            return fail_image(ARC_CORRUPT, "Image subimage could not be selected");
        }
        const OIIO::ImageSpec spec =
            session->input_->spec(static_cast<int>(options.subimage), static_cast<int>(options.mip));
        if (spec.format == OIIO::TypeUnknown) {
            return fail_image(ARC_CORRUPT, "Image level has no pixel format");
        }
        if (spec.depth != 1) {
            return fail_image(ARC_UNSUPPORTED, "Image volumes and deep images are not supported");
        }
        if (spec.width <= 0 || spec.height <= 0 || spec.nchannels <= 0) {
            return fail_image(ARC_CORRUPT, "Image dimensions or channel count are invalid");
        }
        if (spec.x < -origin_limit || spec.x > origin_limit || spec.y < -origin_limit || spec.y > origin_limit) {
            return fail_image(ARC_UNSUPPORTED, "Image origin is outside the supported range");
        }

        // Dimension and pixel-count arithmetic is checked before any decode allocation.
        const auto width = static_cast<uint32_t>(spec.width);
        const auto height = static_cast<uint32_t>(spec.height);
        const uint32_t max_width = std::min(limits.max_width, hard_max_dimension);
        const uint32_t max_height = std::min(limits.max_height, hard_max_dimension);
        if (width > max_width || height > max_height) {
            return fail_image(ARC_RESOURCE_LIMIT, "Image dimensions exceed the limit");
        }
        uint64_t pixel_count = 0;
        if (!multiply_u64(width, height, pixel_count) || pixel_count > hard_max_pixels) {
            return fail_image(ARC_RESOURCE_LIMIT, "Image pixel count exceeds the limit");
        }

        const auto channels = static_cast<uint32_t>(spec.nchannels);
        if (channels > std::min(limits.max_items, max_channels)) {
            return fail_image(ARC_RESOURCE_LIMIT, "Image channel count exceeds the limit");
        }

        // Channel names and types are bounded and closed before they reach the metadata.
        const bool names_present = spec.channelnames.size() == channels;
        std::vector<std::string> names(channels);
        std::vector<OIIO::TypeDesc> types(channels);
        uint32_t maximum_bits = 0;
        bool range_clamp_possible = false;
        bool precision_loss = false;
        for (uint32_t index = 0; index < channels; ++index) {
            if (names_present) {
                names[index] = spec.channelnames[index];
                if (!printable_ascii_name(names[index])) {
                    return fail_image(ARC_UNSUPPORTED, "Image channel names must be printable ASCII up to 64 bytes");
                }
            } else {
                names[index] = "channel" + std::to_string(index);
            }
            types[index] = spec.channelformats.size() == channels ? spec.channelformats[index] : spec.format;
            if (!supported_base_type(types[index])) {
                return fail_image(ARC_UNSUPPORTED, "Image channel type is not supported");
            }
            maximum_bits = std::max(maximum_bits, type_bits(types[index]));
            range_clamp_possible = range_clamp_possible || is_floating_type(types[index]);
            precision_loss = precision_loss || loses_precision_as_float(types[index]);
        }

        // Tile and scanline memory bounds are checked here, before any decode allocation.
        uint64_t memory_bytes = 0;
        if (spec.tile_width > 0) {
            if (spec.tile_height <= 0 || spec.tile_depth > 1) {
                return fail_image(ARC_UNSUPPORTED, "Image tile geometry is not supported");
            }
            uint64_t tile_samples = 0;
            if (!multiply_u64(static_cast<uint64_t>(spec.tile_width), static_cast<uint64_t>(spec.tile_height),
                              tile_samples) ||
                !multiply_u64(tile_samples, channels, tile_samples) ||
                !multiply_u64(tile_samples, sizeof(float), memory_bytes) || memory_bytes > limits.max_memory_bytes) {
                return fail_image(ARC_RESOURCE_LIMIT, "Image tile exceeds the memory limit");
            }
            session->tile_width_ = static_cast<uint32_t>(spec.tile_width);
            session->tile_height_ = static_cast<uint32_t>(spec.tile_height);
        } else {
            uint64_t row_samples = 0;
            if (!multiply_u64(width, channels, row_samples) ||
                !multiply_u64(row_samples, sizeof(float), memory_bytes) || memory_bytes > limits.max_memory_bytes) {
                return fail_image(ARC_RESOURCE_LIMIT, "Image scanline exceeds the memory limit");
            }
        }

        // Transparency and colour metadata. The file's own association is reported and is what the reader returns:
        // PNG alpha is straight by its specification, and TIFF and EXR report oiio:UnassociatedAlpha only when their
        // alpha is unassociated, so an absent attribute means associated. The straight-alpha request keeps the
        // stored association for both readers, so the pixels match the file.
        const bool file_straight =
            source == source_kind::png || spec.get_int_attribute("oiio:UnassociatedAlpha", 0) != 0;
        const bool srgb = equals_ignore_case(spec.get_string_attribute("oiio:ColorSpace"), "sRGB");

        // Channel plan (decision D4). Named channels win; otherwise the mapping is positional.
        const auto find_named = [&names, names_present](const char* wanted) -> int32_t {
            if (!names_present) {
                return -1;
            }
            for (size_t index = 0; index < names.size(); ++index) {
                if (names[index] == wanted) {
                    return static_cast<int32_t>(index);
                }
            }
            return -1;
        };
        int32_t red = -1;
        int32_t green = -1;
        int32_t blue = -1;
        int32_t alpha = -1;
        bool grey = false;
        bool named_mapping = false;
        const int32_t named_red = find_named("R");
        const int32_t named_green = find_named("G");
        const int32_t named_blue = find_named("B");
        const int32_t named_luma = find_named("Y");
        if (named_red >= 0 && named_green >= 0 && named_blue >= 0) {
            red = named_red;
            green = named_green;
            blue = named_blue;
            alpha = find_named("A");
            named_mapping = true;
        } else if (named_luma >= 0) {
            red = named_luma;
            grey = true;
            alpha = find_named("A");
            named_mapping = true;
        } else if (channels == 1) {
            red = 0;
            grey = true;
        } else if (channels == 2) {
            red = 0;
            grey = true;
            alpha = 1;
        } else {
            red = 0;
            green = 1;
            blue = 2;
            alpha = channels >= 4 ? 3 : -1;
        }
        const bool has_alpha = alpha >= 0;

        const bool identity = options.format == ARC_FORMAT_FLOAT32_INTERLEAVED;
        const bool rgba32f = options.format == ARC_FORMAT_RGBA32F_LINEAR_PREMULTIPLIED;
        const bool rgba8 = options.format == ARC_FORMAT_RGBA8;
        session->identity_ = identity;
        session->red_ = identity ? -1 : red;
        session->green_ = identity ? -1 : green;
        session->blue_ = identity ? -1 : blue;
        session->alpha_ = identity ? -1 : alpha;
        session->grey_ = !identity && grey;
        session->output_channels_ = identity ? channels : 4;
        session->bytes_per_pixel_ = identity ? channels * 4U : 4U * (rgba8 ? 1U : 4U);
        session->srgb_to_linear_ = !identity && rgba32f && srgb;
        // Straight sources are read straight (decision D4 and the straight-alpha adjudication), so only an
        // associated source needs unpremultiplying. The sRGB transfer applies to straight colour, and the
        // premultiplied float output multiplies by alpha after the transfer.
        session->source_associated_ = !identity && has_alpha && !file_straight;
        session->premultiply_output_ = rgba32f && has_alpha && (file_straight || session->srgb_to_linear_);

        // Channels that the RGBA output does not read are dropped and reported as a loss.
        std::vector<bool> used(channels, false);
        for (const int32_t index : {red, green, blue, alpha}) {
            if (index >= 0) {
                used[static_cast<size_t>(index)] = true;
            }
        }
        const bool dropped = !identity && static_cast<uint32_t>(std::count(used.begin(), used.end(), true)) < channels;

        // Metadata: a closed JSON document. Every conversion and loss applied to reads is listed.
        const bool lossy_depth = rgba8 && maximum_bits > 8;
        const bool lossy_clamp = rgba8 && range_clamp_possible;
        const bool lossy_precision = !rgba8 && precision_loss;
        std::vector<const char*> conversions;
        if (grey && !identity) {
            conversions.push_back("greyToRgb");
        }
        if (!identity && !has_alpha) {
            conversions.push_back("alphaFilled");
        }
        if (session->source_associated_ && (rgba8 || session->srgb_to_linear_)) {
            conversions.push_back("unpremultiply");
        }
        if (session->srgb_to_linear_) {
            conversions.push_back("srgbToLinear");
        }
        if (session->premultiply_output_) {
            conversions.push_back("premultiplyOnRead");
        }
        std::vector<const char*> losses;
        if (lossy_depth) {
            losses.push_back("bitDepthReduction");
        }
        if (lossy_clamp) {
            losses.push_back("rangeClamp");
        }
        if (lossy_precision) {
            losses.push_back("precisionReduction");
        }
        if (rgba8 && session->source_associated_) {
            losses.push_back("unpremultiplyPrecision");
        }
        if (dropped) {
            losses.push_back("channelsDropped");
        }

        const char* output_name = rgba8 ? "rgba8" : (rgba32f ? "rgba32fLinearPremultiplied" : "float32Interleaved");
        const char* alpha_name = !has_alpha ? "none" : (file_straight ? "straight" : "premultiplied");
        const bool tiled = session->tile_width_ != 0;

        std::string json;
        json.reserve(512);
        json += "{\"schema\":\"arc.image.metadata.v1\",\"format\":";
        append_json_string(json, metadata_format_name(source));
        json += ",\"subimage\":" + std::to_string(options.subimage);
        json += ",\"subimages\":" + std::to_string(subimage_count);
        json += ",\"mip\":" + std::to_string(options.mip);
        json += ",\"mips\":" + std::to_string(mip_count);
        json += ",\"width\":" + std::to_string(width);
        json += ",\"height\":" + std::to_string(height);
        json += ",\"originX\":" + std::to_string(spec.x);
        json += ",\"originY\":" + std::to_string(spec.y);
        json += ",\"tiled\":";
        json += tiled ? "true" : "false";
        json += ",\"tileWidth\":" + std::to_string(session->tile_width_);
        json += ",\"tileHeight\":" + std::to_string(session->tile_height_);
        json += ",\"channels\":[";
        for (uint32_t index = 0; index < channels; ++index) {
            if (index != 0) {
                json.push_back(',');
            }
            json += "{\"name\":";
            append_json_string(json, names[index]);
            json += ",\"type\":";
            append_json_string(json, type_name(types[index]));
            json.push_back('}');
        }
        json += "],\"channelMapping\":";
        append_json_string(json, named_mapping ? "named" : "positional");
        json += ",\"alpha\":";
        append_json_string(json, alpha_name);
        json += ",\"colorSpace\":";
        append_json_string(json, srgb ? "sRGB" : "unknown");
        json += ",\"sourceBitsMax\":" + std::to_string(maximum_bits);
        json += ",\"outputFormat\":";
        append_json_string(json, output_name);
        json += ",\"outputChannels\":" + std::to_string(session->output_channels_);
        json += ",\"bytesPerPixel\":" + std::to_string(session->bytes_per_pixel_);
        json += ",\"conversions\":";
        append_string_array(json, conversions);
        json += ",\"loss\":";
        append_string_array(json, losses);
        json.push_back('}');

        session->width_ = width;
        session->height_ = height;
        session->channels_ = channels;
        session->origin_x_ = spec.x;
        session->origin_y_ = spec.y;
        session->metadata_ = std::move(json);
        session->coverage_ = coverage_tracker(width, height, max_coverage_intervals);
    }

    output = std::move(session);
    return ARC_OK;
}

arc_status_t image_session::poll() const
{
    const arc_status_t cancelled = arc::abi::check_cancelled(cancel_);
    if (cancelled == ARC_CANCELLED) {
        return fail_image(ARC_CANCELLED, "Image operation was cancelled");
    }
    if (cancelled != ARC_OK) {
        return cancelled;
    }
    if (has_deadline_ && std::chrono::steady_clock::now() > deadline_) {
        return fail_image(ARC_RESOURCE_LIMIT, "Image operation exceeded its time limit");
    }
    return ARC_OK;
}

arc_status_t image_session::decode_failure(const char* message) const
{
    const arc_status_t latched = proxy_->latched_status();
    if (latched == ARC_CANCELLED) {
        return fail_image(ARC_CANCELLED, "Image operation was cancelled");
    }
    if (latched == ARC_RESOURCE_LIMIT) {
        return fail_image(ARC_RESOURCE_LIMIT, "Image operation exceeded its time limit");
    }
    if (latched != ARC_OK) {
        return fail_image(latched, "Image input callback failed");
    }
    return fail_image(ARC_CORRUPT, message);
}

arc_status_t image_session::read(const arc_region_v1& region, arc_mut_buffer_t* pixels,
                                 const arc_cancel_token_t* cancel)
{
    std::lock_guard lock(mutex_);

    arc_status_t status = arc::abi::validate_record(&region, sizeof(arc_region_v1));
    if (status != ARC_OK) {
        return status;
    }
    if (region.first_sample != 0 || region.sample_count != 0) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image regions must leave the sample fields zero");
    }
    if (region.width == 0 || region.height == 0) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image region size must be positive");
    }
    if (static_cast<uint64_t>(region.x) + region.width > width_ ||
        static_cast<uint64_t>(region.y) + region.height > height_) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image region is outside the image");
    }

    const uint64_t row_bytes = static_cast<uint64_t>(region.width) * bytes_per_pixel_;
    if (region.row_stride != 0 && region.row_stride != row_bytes) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image region output must be packed");
    }
    uint64_t output_bytes = 0;
    if (!multiply_u64(row_bytes, region.height, output_bytes)) {
        return fail_image(ARC_RESOURCE_LIMIT, "Image region size overflows");
    }
    if (output_bytes > hard_max_region_bytes || output_bytes > limits_.max_output_bytes) {
        return fail_image(ARC_RESOURCE_LIMIT, "Image region exceeds the output limit");
    }

    // Coverage (decision D3) is checked before the buffer. A refused region leaves no state behind.
    status = coverage_.check(region.x, region.y, region.width, region.height);
    if (status == ARC_INVALID_ARGUMENT) {
        return fail_image(ARC_INVALID_ARGUMENT, "Image region overlaps covered pixels or is out of raster order");
    }
    if (status != ARC_OK) {
        return fail_image(status, "Image region coverage limit is reached");
    }

    status = arc::abi::prepare_buffer_output(pixels, output_bytes);
    if (status != ARC_OK) {
        return status;
    }

    call_scope scope(*this, cancel, limits_.timeout_ms);
    std::vector<uint8_t> staging;
    try {
        staging.resize(static_cast<size_t>(output_bytes));
    } catch (const std::bad_alloc&) {
        return fail_image(ARC_OUT_OF_MEMORY, "Image region staging allocation failed");
    }

    status = tile_width_ != 0 ? decode_tiles(region.x, region.y, region.width, region.height, staging.data())
                              : decode_scanlines(region.x, region.y, region.width, region.height, staging.data());
    if (status != ARC_OK) {
        return status;
    }

    coverage_.commit(region.x, region.y, region.width, region.height);
    std::memcpy(pixels->data, staging.data(), static_cast<size_t>(output_bytes));
    pixels->required = output_bytes;
    return ARC_OK;
}

// Decodes the tiles that intersect the region, one tile at a time. Tile reads are bounded by the
// tile size checked at open, and cancellation and the deadline are polled before every tile.
arc_status_t image_session::decode_tiles(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t* out)
{
    const uint64_t tile_w = tile_width_;
    const uint64_t tile_h = tile_height_;
    const uint64_t region_right = static_cast<uint64_t>(x) + w;
    const uint64_t region_bottom = static_cast<uint64_t>(y) + h;
    const uint64_t first_tile_x = x / tile_w;
    const uint64_t last_tile_x = (region_right - 1) / tile_w;
    const uint64_t first_tile_y = y / tile_h;
    const uint64_t last_tile_y = (region_bottom - 1) / tile_h;

    try {
        tile_buffer_.resize(static_cast<size_t>(tile_w * tile_h * channels_));
    } catch (const std::bad_alloc&) {
        return fail_image(ARC_OUT_OF_MEMORY, "Image tile allocation failed");
    }

    for (uint64_t tile_y = first_tile_y; tile_y <= last_tile_y; ++tile_y) {
        for (uint64_t tile_x = first_tile_x; tile_x <= last_tile_x; ++tile_x) {
            const arc_status_t polled = poll();
            if (polled != ARC_OK) {
                return polled;
            }
            const uint64_t tile_left = tile_x * tile_w;
            const uint64_t tile_top = tile_y * tile_h;
            const int64_t absolute_x = static_cast<int64_t>(origin_x_) + static_cast<int64_t>(tile_left);
            const int64_t absolute_y = static_cast<int64_t>(origin_y_) + static_cast<int64_t>(tile_top);
            if (!input_->read_tile(static_cast<int>(absolute_x), static_cast<int>(absolute_y), 0, OIIO::TypeFloat,
                                   tile_buffer_.data())) {
                return decode_failure("Image tile could not be decoded");
            }

            const uint64_t left = std::max<uint64_t>(x, tile_left);
            const uint64_t right = std::min<uint64_t>(region_right, tile_left + tile_w);
            const uint64_t top = std::max<uint64_t>(y, tile_top);
            const uint64_t bottom = std::min<uint64_t>(region_bottom, tile_top + tile_h);
            for (uint64_t row = top; row < bottom; ++row) {
                const float* source =
                    tile_buffer_.data() + ((row - tile_top) * tile_w + (left - tile_left)) * channels_;
                uint8_t* destination = out + ((row - y) * w + (left - x)) * bytes_per_pixel_;
                convert_segment(source, static_cast<uint32_t>(right - left), destination);
            }
        }
    }
    return ARC_OK;
}

arc_status_t image_session::decode_scanlines(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t* out)
{
    const arc_status_t rows = ensure_rows(y, y + h);
    if (rows != ARC_OK) {
        return rows;
    }
    const uint64_t row_floats = static_cast<uint64_t>(width_) * channels_;
    for (uint32_t row = y; row < y + h; ++row) {
        const float* source =
            band_.data() + static_cast<uint64_t>(row - band_begin_) * row_floats + static_cast<uint64_t>(x) * channels_;
        uint8_t* destination = out + static_cast<uint64_t>(row - y) * w * bytes_per_pixel_;
        convert_segment(source, w, destination);
    }
    return ARC_OK;
}

// Keeps decoded full-width rows for [first_row, end_row). Scanline decoders only move forward, and
// decision D3 keeps the region rows non-decreasing, so rows decoded for one band serve every tile
// of that band without a second decode pass.
arc_status_t image_session::ensure_rows(uint32_t first_row, uint32_t end_row)
{
    const uint64_t row_floats = static_cast<uint64_t>(width_) * channels_;
    if (band_end_ <= first_row || band_begin_ > first_row) {
        band_.clear();
        band_begin_ = first_row;
        band_end_ = first_row;
    } else if (band_begin_ < first_row) {
        const uint64_t drop = static_cast<uint64_t>(first_row - band_begin_) * row_floats;
        band_.erase(band_.begin(), band_.begin() + static_cast<std::ptrdiff_t>(drop));
        band_begin_ = first_row;
    }
    if (band_end_ >= end_row) {
        return ARC_OK;
    }

    uint64_t needed_bytes = 0;
    if (!multiply_u64(static_cast<uint64_t>(end_row - first_row), row_floats * sizeof(float), needed_bytes) ||
        needed_bytes > limits_.max_memory_bytes) {
        return fail_image(ARC_RESOURCE_LIMIT, "Image rows exceed the memory limit");
    }
    for (uint32_t row = band_end_; row < end_row; ++row) {
        const arc_status_t polled = poll();
        if (polled != ARC_OK) {
            return polled;
        }
        const size_t previous = band_.size();
        try {
            band_.resize(previous + static_cast<size_t>(row_floats));
        } catch (const std::bad_alloc&) {
            return fail_image(ARC_OUT_OF_MEMORY, "Image row allocation failed");
        }
        const int scanline = static_cast<int>(static_cast<int64_t>(origin_y_) + row);
        if (!input_->read_scanline(scanline, 0, OIIO::TypeFloat, band_.data() + previous)) {
            band_.resize(previous);
            return decode_failure("Image scanline could not be decoded");
        }
        band_end_ = row + 1;
    }
    return ARC_OK;
}

void image_session::convert_segment(const float* source, uint32_t count, uint8_t* out)
{
    const size_t output_floats = static_cast<size_t>(count) * output_channels_;
    scratch_.resize(output_floats);
    for (uint32_t pixel = 0; pixel < count; ++pixel) {
        convert_pixel(source + static_cast<size_t>(pixel) * channels_,
                      scratch_.data() + static_cast<size_t>(pixel) * output_channels_);
    }
    if (format_ == ARC_FORMAT_RGBA8) {
        // Decision D4: float-to-unorm8 with clamping to [0, 1] and round-to-nearest. Written here rather
        // than through OpenImageIO's convert_type, which reports failure for this pair.
        for (size_t index = 0; index < output_floats; ++index) {
            float value = scratch_[index];
            if (!(value > 0.0F)) { // also maps NaN to zero
                value = 0.0F;
            } else if (value > 1.0F) {
                value = 1.0F;
            }
            out[index] = static_cast<uint8_t>(value * 255.0F + 0.5F);
        }
    } else {
        std::memcpy(out, scratch_.data(), output_floats * sizeof(float));
    }
}

void image_session::convert_pixel(const float* source, float* destination) const
{
    if (identity_) {
        for (uint32_t channel = 0; channel < channels_; ++channel) {
            destination[channel] = source[channel];
        }
        return;
    }

    float red = source[red_];
    float green = grey_ ? red : source[green_];
    float blue = grey_ ? red : source[blue_];
    const float alpha = alpha_ >= 0 ? source[alpha_] : 1.0F;

    // Straight colour is needed for rgba8 output and for the transfer curve. An associated source yields it by
    // division; zero alpha has no recoverable colour and yields black.
    if (source_associated_ && (format_ == ARC_FORMAT_RGBA8 || srgb_to_linear_)) {
        if (alpha > 0.0F) {
            red /= alpha;
            green /= alpha;
            blue /= alpha;
        } else {
            red = 0.0F;
            green = 0.0F;
            blue = 0.0F;
        }
    }
    if (srgb_to_linear_) {
        red = srgb_to_linear(red);
        green = srgb_to_linear(green);
        blue = srgb_to_linear(blue);
    }
    if (premultiply_output_) {
        red *= alpha;
        green *= alpha;
        blue *= alpha;
    }
    destination[0] = red;
    destination[1] = green;
    destination[2] = blue;
    destination[3] = alpha;
}

} // namespace arc::image
