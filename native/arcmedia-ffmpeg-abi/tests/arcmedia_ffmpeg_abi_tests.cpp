// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_media_abi.h>

int main()
{
    return (arc_media_abi_version() == ARC_NATIVE_ABI_VERSION && arc_media_hello() == ARC_STATUS_OK) ? 0 : 1;
}
