// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_image_abi.h>

#include "arc_build_identity.hpp"
#include "arc_native_abi_internal.hpp"
#include "image_session.hpp"

#include <OpenImageIO/imageio.h>

#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <string_view>

#ifndef ARCFORGES_SHIM_STATIC_GRAPH
#error ArcImageNative must be built from the shim-static dependency graph.
#endif

namespace {

using arc::image::image_error_domain;
using arc::image::image_handle_kind;
using arc::image::image_session;

// Image handles live in one table per library context, limited to Annex 06 section 2 defaults.
arc::abi::handle_table& image_handles()
{
    static arc::abi::handle_table table(arc::image::max_open_images);
    return table;
}

arc_status_t write_text(std::string_view text, arc_mut_buffer_t* output)
{
    const arc_status_t prepared = arc::abi::prepare_buffer_output(output, static_cast<uint64_t>(text.size()));
    if (prepared != ARC_OK) {
        return prepared;
    }
    if (!text.empty()) {
        std::memcpy(output->data, text.data(), text.size());
    }
    return ARC_OK;
}

// Build information is a closed JSON object. The identity suffix is embedded as a field, without its
// leading separator, so the document stays valid JSON.
std::string build_info_json()
{
    const std::string_view identity(arc_build_identity);
    const std::string_view identity_fields =
        identity.empty() || identity.front() != ';' ? identity : identity.substr(1);
    std::string json;
    json.reserve(512);
    json += "{\"library\":\"ArcImageNative\",\"abi\":{\"major\":1,\"minor\":1},";
    json += "\"openimageio\":\"3.1.14.0\",";
    json += "\"capabilities\":[\"image.open\",\"image.read\",\"image.close\"],";
    json += "\"formats\":[\"png\",\"tiff\",\"exr\"],";
    json += "\"identity\":\"";
    for (const char ch : identity_fields) {
        if (ch == '"' || ch == '\\') {
            json.push_back('\\');
        }
        json.push_back(ch);
    }
    json += "\"}";
    return json;
}

} // namespace

arc_status_t ARC_ABI_CALL arc_image_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    if (out_major == nullptr || out_minor == nullptr) {
        return arc::abi::fail(ARC_INVALID_ARGUMENT, "ABI version outputs are required", image_error_domain);
    }
    *out_major = ARC_NATIVE_ABI_MAJOR;
    *out_minor = ARC_NATIVE_FUNCTIONAL_ABI_MINOR;
    return ARC_OK;
}

arc_status_t ARC_ABI_CALL arc_image_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        if (OIIO::get_string_attribute("format_list").empty()) {
            return arc::abi::fail(ARC_INTERNAL, "OpenImageIO format probe failed", image_error_domain);
        }
        const std::string json = build_info_json();
        return write_text(json, out_utf8);
    } catch (const std::bad_alloc&) {
        return arc::abi::fail(ARC_OUT_OF_MEMORY, "Build information allocation failed", image_error_domain);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "OpenImageIO build probe failed", image_error_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_image_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}

arc_status_t ARC_ABI_CALL arc_image_open(const arc_io_v1* io, const arc_image_options_v1* options, arc_handle_t* image,
                                         arc_mut_buffer_t* metadata, const arc_cancel_token_t* cancel)
{
    try {
        const arc_status_t prepared = arc::abi::prepare_handle_output(image);
        if (prepared != ARC_OK) {
            return prepared;
        }
        if (io == nullptr || options == nullptr || metadata == nullptr) {
            return arc::abi::fail(ARC_INVALID_ARGUMENT, "Image open arguments are required", image_error_domain);
        }

        std::unique_ptr<image_session> session;
        const arc_status_t opened = image_session::open(*io, *options, cancel, session);
        if (opened != ARC_OK) {
            return opened;
        }
        // Annex 06 section 1: a failed call writes no output. The handle is registered first, into a local
        // token, so a refused create (RESOURCE_LIMIT) leaves the metadata buffer untouched. Only then is the
        // metadata copied. A short metadata buffer closes the new handle again, so the failed call leaves no
        // open handle behind.
        std::shared_ptr<image_session> shared(std::move(session));
        arc_handle_t created = 0;
        const arc_status_t registered = image_handles().create(image_handle_kind, shared, &created);
        if (registered != ARC_OK) {
            return registered;
        }
        const arc_status_t written = write_text(shared->metadata(), metadata);
        if (written != ARC_OK) {
            (void)image_handles().close(created, image_handle_kind);
            return written;
        }
        *image = created;
        return ARC_OK;
    } catch (const std::bad_alloc&) {
        return arc::abi::fail(ARC_OUT_OF_MEMORY, "Image open allocation failed", image_error_domain);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "Image open failed", image_error_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_image_read(arc_handle_t image, const arc_region_v1* region, arc_mut_buffer_t* pixels,
                                         const arc_cancel_token_t* cancel)
{
    try {
        if (region == nullptr || pixels == nullptr) {
            return arc::abi::fail(ARC_INVALID_ARGUMENT, "Image read arguments are required", image_error_domain);
        }
        arc::abi::handle_lease lease;
        const arc_status_t acquired = image_handles().acquire(image, image_handle_kind, &lease);
        if (acquired != ARC_OK) {
            return acquired;
        }
        return lease.as<image_session>()->read(*region, pixels, cancel);
    } catch (const std::bad_alloc&) {
        return arc::abi::fail(ARC_OUT_OF_MEMORY, "Image read allocation failed", image_error_domain);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "Image read failed", image_error_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_image_close(arc_handle_t image)
{
    try {
        return image_handles().close(image, image_handle_kind);
    } catch (const std::bad_alloc&) {
        return arc::abi::fail(ARC_OUT_OF_MEMORY, "Image close allocation failed", image_error_domain);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "Image close failed", image_error_domain);
    }
}
