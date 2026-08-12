// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ArcScope.Native;

internal static partial class MdfNative
{
    [LibraryImport("ArcScopeMdfNative", EntryPoint = "arc_scope_mdf_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint GetAbiVersion();

    [LibraryImport("ArcScopeMdfNative", EntryPoint = "arc_scope_mdf_hello")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Hello();
}
