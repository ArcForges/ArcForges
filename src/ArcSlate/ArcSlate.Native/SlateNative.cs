// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ArcSlate.Native;

internal static partial class SlateNative
{
    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_slate_otio_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint GetOtioAbiVersion();

    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_slate_otio_hello")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int HelloOtio();

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_slate_color_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint GetColorAbiVersion();

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_slate_color_hello")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int HelloColor();

    [LibraryImport("ArcSlateImageNative", EntryPoint = "arc_slate_image_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint GetImageAbiVersion();

    [LibraryImport("ArcSlateImageNative", EntryPoint = "arc_slate_image_hello")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int HelloImage();
}
