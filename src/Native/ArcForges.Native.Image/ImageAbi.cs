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
}
