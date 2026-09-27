// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ArcForges.NativeInterop;

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct ArcMutableBuffer
{
    internal nint Data;
    internal ulong Capacity;
    internal ulong Required;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct ArcErrorInfo
{
    internal uint StructSize;
    internal uint StructVersion;
    internal int Status;
    internal uint Domain;
    internal ulong CorrelationId;
    internal ArcMutableBuffer MessageUtf8;
}

internal static partial class ArcImageNative
{
    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int GetAbiVersion(uint* major, uint* minor);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetBuildInfo(ref ArcMutableBuffer output);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetLastError(ref ArcErrorInfo output);
}
