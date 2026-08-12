// SPDX-License-Identifier: AGPL-3.0-only
#include <arc/arc_scope_mdf_abi.h>

int main()
{
    return (arc_scope_mdf_abi_version() == ARC_NATIVE_ABI_VERSION && arc_scope_mdf_hello() == ARC_STATUS_OK) ? 0 : 1;
}
