// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_media_abi.h>

#include "arc_native_abi_internal.hpp"

#include <string>

extern "C" {
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <libavcodec/avcodec.h>
#include <libavfilter/avfilter.h>
#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
#include <libswresample/swresample.h>
#include <libswscale/swscale.h>
#include <libusb.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif
}
#include <miniaudio.h>

#ifndef ARCFORGES_RUNTIME_SHARED_GRAPH
#error ArcMediaNative must be built from the runtime-shared dependency graph.
#endif

namespace {
constexpr uint32_t media_domain = 0x4D454449U;
}

arc_status_t ARC_ABI_CALL arc_media_get_abi_version(uint32_t* out_major, uint32_t* out_minor)
{
    return arc::abi::get_abi_version(out_major, out_minor);
}

arc_status_t ARC_ABI_CALL arc_media_get_build_info(arc_mut_buffer_t* out_utf8)
{
    try {
        const libusb_version* usb = libusb_get_version();
        const bool versions_match =
            avutil_version() == LIBAVUTIL_VERSION_INT && avcodec_version() == LIBAVCODEC_VERSION_INT &&
            avformat_version() == LIBAVFORMAT_VERSION_INT && avfilter_version() == LIBAVFILTER_VERSION_INT &&
            swscale_version() == LIBSWSCALE_VERSION_INT && swresample_version() == LIBSWRESAMPLE_VERSION_INT &&
            usb != nullptr && usb->major == 1 && MA_VERSION_MAJOR == 0 && MA_VERSION_MINOR == 11 &&
            MA_VERSION_REVISION == 25;
        if (!versions_match) {
            return arc::abi::fail(ARC_VERSION_MISMATCH, "ArcMedia dependency version mismatch", media_domain);
        }

        const std::string value =
            std::string(
                "ArcMediaNative;abi=1.0;avutil=" AV_STRINGIFY(LIBAVUTIL_VERSION) ";avcodec=" AV_STRINGIFY(LIBAVCODEC_VERSION) ";avformat=" AV_STRINGIFY(LIBAVFORMAT_VERSION) ";avfilter=" AV_STRINGIFY(
                    LIBAVFILTER_VERSION) ";swscale=" AV_STRINGIFY(LIBSWSCALE_VERSION) ";swresample=" AV_STRINGIFY(LIBSWRESAMPLE_VERSION) ";libusb=") +
            std::to_string(usb->major) + "." + std::to_string(usb->minor) + ";miniaudio=0.11.25";
        return arc::abi::write_build_info(value, out_utf8);
    } catch (...) {
        return arc::abi::fail(ARC_INTERNAL, "ArcMedia build probe failed", media_domain);
    }
}

arc_status_t ARC_ABI_CALL arc_media_get_last_error(arc_error_info_t* out_error)
{
    return arc::abi::get_last_error(out_error);
}
