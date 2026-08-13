// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_otio_abi.h>

#include <vector>

namespace {
constexpr int null_output_failure = 4;
constexpr int error_snapshot_failure = 5;
} // namespace

int main()
{
    uint32_t major = 0;
    uint32_t minor = 0;
    if (arc_otio_get_abi_version(&major, &minor) != ARC_OK || major != 1 || minor != 0) {
        return 1;
    }
    arc_mut_buffer_t query{};
    if (arc_otio_get_build_info(&query) != ARC_BUFFER_TOO_SMALL || query.required == 0) {
        return 2;
    }
    std::vector<char> value(static_cast<size_t>(query.required));
    arc_mut_buffer_t output{.data = value.data(), .capacity = value.size(), .required = 0};
    if (arc_otio_get_build_info(&output) != ARC_OK || output.required != value.size()) {
        return 3;
    }
    if (arc_otio_get_abi_version(nullptr, &minor) != ARC_INVALID_ARGUMENT) {
        return null_output_failure;
    }
    arc_error_info_t error{.struct_size = sizeof(arc_error_info_t), .struct_version = 1};
    if (arc_otio_get_last_error(&error) != ARC_BUFFER_TOO_SMALL || error.status != ARC_INVALID_ARGUMENT) {
        return error_snapshot_failure;
    }
    return 0;
}
