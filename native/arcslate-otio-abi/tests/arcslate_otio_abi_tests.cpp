// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_slate_otio_abi.h>

int main()
{
    return (arc_slate_otio_abi_version() == ARC_NATIVE_ABI_VERSION && arc_slate_otio_hello() == ARC_STATUS_OK) ? 0 : 1;
}
