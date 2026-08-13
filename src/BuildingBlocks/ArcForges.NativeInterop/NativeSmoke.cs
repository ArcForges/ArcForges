// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.InteropServices;
using System.Text;

namespace ArcForges.NativeInterop;

public readonly record struct NativeProbeResult(
    string LibraryName,
    uint AbiMajor,
    uint AbiMinor,
    int Status,
    string BuildInfo);

public static unsafe class NativeSmoke
{
    private const int BufferTooSmall = 1;
    private const int InvalidArgument = -1;

    public static NativeProbeResult VerifyMedia() => Verify(
        "ArcMediaNative", ArcMediaNative.GetAbiVersion, ArcMediaNative.GetBuildInfo, ArcMediaNative.GetLastError);

    public static NativeProbeResult VerifyMdf() => Verify(
        "ArcScopeMdfNative", ArcScopeMdfNative.GetAbiVersion, ArcScopeMdfNative.GetBuildInfo, ArcScopeMdfNative.GetLastError);

    public static NativeProbeResult VerifyOtio() => Verify(
        "ArcSlateOtioNative", ArcSlateNative.GetOtioAbiVersion, ArcSlateNative.GetOtioBuildInfo, ArcSlateNative.GetOtioLastError);

    public static NativeProbeResult VerifyColor() => Verify(
        "ArcSlateColorNative", ArcSlateNative.GetColorAbiVersion, ArcSlateNative.GetColorBuildInfo, ArcSlateNative.GetColorLastError);

    public static NativeProbeResult VerifyImage() => Verify(
        "ArcSlateImageNative", ArcSlateNative.GetImageAbiVersion, ArcSlateNative.GetImageBuildInfo, ArcSlateNative.GetImageLastError);

    public static IReadOnlyList<NativeProbeResult> VerifyAll() =>
        [VerifyMedia(), VerifyMdf(), VerifyOtio(), VerifyColor(), VerifyImage()];

    private static unsafe NativeProbeResult Verify(
        string libraryName,
        VersionProbe versionProbe,
        BufferProbe buildProbe,
        ErrorProbe errorProbe)
    {
        if (Marshal.SizeOf<ArcMutableBuffer>() != 24 || Marshal.SizeOf<ArcErrorInfo>() != 48)
        {
            throw new InvalidOperationException("Managed ABI POD layout differs from the native x64 contract.");
        }

        uint major;
        uint minor;
        int status = versionProbe(&major, &minor);
        if (status != 0 || major != 1 || minor != 0)
        {
            throw new InvalidOperationException($"{libraryName} rejected ABI negotiation ({status}, {major}.{minor}).");
        }

        ArcMutableBuffer query = default;
        status = buildProbe(ref query);
        if (status != BufferTooSmall || query.Required == 0 || query.Required > 4096)
        {
            throw new InvalidOperationException($"{libraryName} violated two-stage build-info sizing.");
        }

        byte[] bytes = GC.AllocateUninitializedArray<byte>(checked((int)query.Required));
        unsafe
        {
            fixed (byte* data = bytes)
            {
                ArcMutableBuffer output = new() { Data = (nint)data, Capacity = (ulong)bytes.Length };
                status = buildProbe(ref output);
                if (status != 0 || output.Required != (ulong)bytes.Length)
                {
                    throw new InvalidOperationException($"{libraryName} failed its exact two-stage build-info write.");
                }
            }
        }

        string buildInfo = Encoding.UTF8.GetString(bytes);
        if (!buildInfo.StartsWith(libraryName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{libraryName} returned unexpected build information.");
        }

        status = versionProbe(&major, &minor);
        if (status != 0)
        {
            throw new InvalidOperationException($"{libraryName} failed after its successful build probe.");
        }

        status = versionProbe(null, &minor);
        if (status != InvalidArgument)
        {
            throw new InvalidOperationException($"{libraryName} did not reject a null ABI output.");
        }

        ArcErrorInfo error = new()
        {
            StructSize = checked((uint)Marshal.SizeOf<ArcErrorInfo>()),
            StructVersion = 1,
        };
        int errorStatus = errorProbe(ref error);
        if (errorStatus != BufferTooSmall || error.Status != InvalidArgument || error.MessageUtf8.Required == 0)
        {
            throw new InvalidOperationException($"{libraryName} did not preserve its thread-local error snapshot.");
        }

        return new NativeProbeResult(libraryName, major, minor, 0, buildInfo);
    }

    private unsafe delegate int VersionProbe(uint* major, uint* minor);
    private delegate int BufferProbe(ref ArcMutableBuffer output);
    private delegate int ErrorProbe(ref ArcErrorInfo output);
}
