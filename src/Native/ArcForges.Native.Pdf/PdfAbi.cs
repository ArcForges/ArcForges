// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

[assembly: DisableRuntimeMarshalling]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace ArcForges.Native.Pdf;

/// <summary>The raw arc_pdf_* exports of ArcPdfNative and the library preamble. Use <see cref="PdfDocument"/> for the bounded API.</summary>
internal static unsafe partial class PdfAbi
{
    static PdfAbi() => NativeLoader.Register(typeof(PdfAbi).Assembly, "ArcPdfNative");

    /// <summary>The ABI version the loaded library reports (a functional PDF library reports 1.1).</summary>
    public static NativeAbiVersion GetAbiVersion() => NativeAbi.GetVersion(GetVersionCore);

    /// <summary>The build information; it names whether a PDF backend is linked (<c>backend=linked</c>) or not (<c>backend=none</c>).</summary>
    public static string GetBuildInfo() => NativeAbi.GetBuildInfo(GetBuildInfoCore, GetErrorCore);

    /// <summary>The calling thread's last native error.</summary>
    public static NativeError GetLastError() => NativeAbi.GetError(GetErrorCore);

    /// <summary>True when the loaded library has a PDF parser linked. A library without one refuses every open.</summary>
    public static bool HasLinkedBackend() => GetBuildInfo().Contains("backend=linked", StringComparison.Ordinal);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetVersionCore(uint* major, uint* minor);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetBuildInfoCore(ref NativeBuffer output);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetErrorCore(ref NativeErrorBuffer output);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_open")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Open(NativeIoV1* io, NativeStringView password, NativeLimitsV1* limits, ulong* document, uint* pages, NativeCancelToken* cancel);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_page_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int PageInfo(ulong document, uint index, NativePdfPageV1* page);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_render")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Render(ulong document, NativePdfPageV1* page, NativeRegionV1* region, uint fullWidth, uint fullHeight, NativeBuffer* rgba8, NativeCancelToken* cancel);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_text")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Text(ulong document, uint page, uint start, uint count, NativeBuffer* textGeometry, NativeCancelToken* cancel);

    [LibraryImport("ArcPdfNative", EntryPoint = "arc_pdf_close")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Close(ulong document);

    internal static NativeError LastError() => GetLastError();
}
