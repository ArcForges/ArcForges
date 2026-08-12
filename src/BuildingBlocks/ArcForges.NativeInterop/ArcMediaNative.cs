// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ArcForges.NativeInterop;

internal static partial class ArcMediaNative
{
    [LibraryImport("ArcMediaNative", EntryPoint = "arc_media_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint GetAbiVersion();

    [LibraryImport("ArcMediaNative", EntryPoint = "arc_media_hello")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Hello();
}
