// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Image;

// Functional image exports (Annex 06 sections 2 and 3). The declarations stay internal: product code
// reaches them only through ImageReader, which owns the generation token and the callback context.
public static unsafe partial class ImageAbi
{
    private static readonly Lazy<string> FunctionalBuildInfo = new(VerifyFunctionalAbi, LazyThreadSafetyMode.ExecutionAndPublication);

    // Confirms ABI minor 1 and the closed capability manifest once per process. A library without the
    // functional exports fails here, before any native image call is made.
    internal static string RequireFunctionalAbi() => FunctionalBuildInfo.Value;

    internal static NativeStatus OpenNative(NativeIoV1* io, NativeImageOptionsV1* options, ulong* image,
        NativeBuffer* metadata, NativeCancelToken* cancel) =>
        (NativeStatus)OpenCore(io, options, image, metadata, cancel);

    internal static NativeStatus ReadNative(ulong image, NativeRegionV1* region, NativeBuffer* pixels,
        NativeCancelToken* cancel) =>
        (NativeStatus)ReadCore(image, region, pixels, cancel);

    internal static NativeStatus CloseNative(ulong image) => (NativeStatus)CloseCore(image);

    // Must run on the thread that made the failing call, immediately after it returns, because the
    // diagnostic slot is thread local.
    internal static string LastErrorMessage(NativeStatus status)
    {
        try
        {
            string message = GetLastError().Message;
            return string.IsNullOrEmpty(message) ? status.ToString() : message;
        }
        catch (InvalidOperationException)
        {
            return status.ToString();
        }
    }

    private static string VerifyFunctionalAbi()
    {
        NativeAbiVersion version = GetAbiVersion();
        if (version.Minor < NativeAbiConstants.FunctionalMinor)
        {
            throw new ImageNativeException(NativeStatus.VersionMismatch,
                $"ArcImageNative ABI {version.Major}.{version.Minor} does not provide the functional image exports.");
        }

        string info = GetBuildInfo();
        if (!AdvertisesFunctionalImage(info))
        {
            throw new ImageNativeException(NativeStatus.VersionMismatch,
                "ArcImageNative build information does not advertise the functional image capabilities.");
        }

        return info;
    }

    private static bool AdvertisesFunctionalImage(string info)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(info);
            JsonElement root = document.RootElement;
            return root.GetProperty("library").GetString() == "ArcImageNative"
                && root.GetProperty("abi").GetProperty("minor").GetUInt32() == NativeAbiConstants.FunctionalMinor
                && ContainsAll(root.GetProperty("capabilities"), "image.open", "image.read", "image.close")
                && ContainsAll(root.GetProperty("formats"), "png", "tiff", "exr");
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return false;
        }
    }

    private static bool ContainsAll(JsonElement array, params string[] required)
    {
        var present = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement item in array.EnumerateArray())
        {
            if (item.GetString() is { } value)
            {
                present.Add(value);
            }
        }

        return required.All(present.Contains);
    }

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_open")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int OpenCore(NativeIoV1* io, NativeImageOptionsV1* options, ulong* image,
        NativeBuffer* metadata, NativeCancelToken* cancel);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_read")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int ReadCore(ulong image, NativeRegionV1* region, NativeBuffer* pixels,
        NativeCancelToken* cancel);

    [LibraryImport("ArcImageNative", EntryPoint = "arc_image_close")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int CloseCore(ulong image);
}
