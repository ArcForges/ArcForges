// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ARC_NATIVE_ABI_INTERNAL_HPP
#define ARC_NATIVE_ABI_INTERNAL_HPP

#include <arc/arc_native_abi.h>

#include <string_view>

namespace arc::abi {

arc_status_t get_abi_version(uint32_t* out_major, uint32_t* out_minor) noexcept;
arc_status_t write_build_info(std::string_view value, arc_mut_buffer_t* out_utf8) noexcept;
arc_status_t get_last_error(arc_error_info_t* out_error) noexcept;
arc_status_t fail(arc_status_t status, std::string_view message, uint32_t domain) noexcept;

} // namespace arc::abi

#endif
