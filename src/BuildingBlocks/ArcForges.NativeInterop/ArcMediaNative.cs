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

internal static partial class ArcMediaNative
{
    [LibraryImport("ArcMediaNative", EntryPoint = "arc_media_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int GetAbiVersion(uint* major, uint* minor);

    [LibraryImport("ArcMediaNative", EntryPoint = "arc_media_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetBuildInfo(ref ArcMutableBuffer output);

    [LibraryImport("ArcMediaNative", EntryPoint = "arc_media_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetLastError(ref ArcErrorInfo output);
}

internal static partial class ArcScopeMdfNative
{
    [LibraryImport("ArcScopeMdfNative", EntryPoint = "arc_mdf_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int GetAbiVersion(uint* major, uint* minor);

    [LibraryImport("ArcScopeMdfNative", EntryPoint = "arc_mdf_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetBuildInfo(ref ArcMutableBuffer output);

    [LibraryImport("ArcScopeMdfNative", EntryPoint = "arc_mdf_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetLastError(ref ArcErrorInfo output);
}

internal static partial class ArcSlateNative
{
    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_otio_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int GetOtioAbiVersion(uint* major, uint* minor);

    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_otio_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetOtioBuildInfo(ref ArcMutableBuffer output);

    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_otio_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetOtioLastError(ref ArcErrorInfo output);

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_color_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int GetColorAbiVersion(uint* major, uint* minor);

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_color_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetColorBuildInfo(ref ArcMutableBuffer output);

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_color_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetColorLastError(ref ArcErrorInfo output);

    [LibraryImport("ArcSlateImageNative", EntryPoint = "arc_image_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int GetImageAbiVersion(uint* major, uint* minor);

    [LibraryImport("ArcSlateImageNative", EntryPoint = "arc_image_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetImageBuildInfo(ref ArcMutableBuffer output);

    [LibraryImport("ArcSlateImageNative", EntryPoint = "arc_image_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int GetImageLastError(ref ArcErrorInfo output);
}
