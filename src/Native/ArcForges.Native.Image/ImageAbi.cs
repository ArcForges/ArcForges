// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

[assembly: DisableRuntimeMarshalling]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace ArcForges.Native.Image;

public static unsafe partial class ImageAbi
{
    static ImageAbi() => NativeLoader.Register(typeof(ImageAbi).Assembly, "ArcImageNative");

    public static NativeAbiVersion GetAbiVersion() => NativeAbi.GetVersion(GetVersionCore);

    public static string GetBuildInfo() => NativeAbi.GetBuildInfo(GetBuildInfoCore, GetErrorCore);

    public static NativeError GetLastError() => NativeAbi.GetError(GetErrorCore);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetVersionCore(uint* major, uint* minor);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetBuildInfoCore(ref NativeBuffer output);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetErrorCore(ref NativeErrorBuffer output);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_open")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Open(NativeIoV1* io, NativeImageOptionsV1* options, ulong* image, NativeBuffer* metadata, NativeCancelToken* cancel);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_read")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Read(ulong image, NativeRegionV1* region, NativeBuffer* pixels, NativeCancelToken* cancel);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_close")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Close(ulong image);
}
