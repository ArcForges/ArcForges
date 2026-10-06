# SPDX-License-Identifier: AGPL-3.0-only
# Bind the exact pinned upstream target semantics; cross builds must provide a
# reviewed real sysroot/toolchain rather than relabelling host x64 output.
include("${VCPKG_ROOT_DIR}/triplets/arm64-linux.cmake")
list(APPEND VCPKG_HASH_ADDITIONAL_FILES "${VCPKG_ROOT_DIR}/triplets/arm64-linux.cmake")
