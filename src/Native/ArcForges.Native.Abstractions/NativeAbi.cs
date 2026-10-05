// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

[assembly: InternalsVisibleTo("ArcForges.Native.Image")]
[assembly: InternalsVisibleTo("ArcForges.Native.Pdf")]

namespace ArcForges.Native.Abstractions;

public enum NativeStatus : int
{
    Ok = 0,
    BufferTooSmall = 1,
    EndOfStream = 2,
    WouldBlock = 3,
    InvalidArgument = -1,
    NotFound = -2,
    Unsupported = -3,
    Io = -4,
    Cancelled = -5,
    VersionMismatch = -6,
    Corrupt = -7,
    OutOfMemory = -8,
    ResourceLimit = -9,
    Closed = -10,
    Busy = -11,
    PermissionDenied = -12,
    Internal = -13,
}

public readonly record struct NativeAbiVersion(uint Major, uint Minor);

public readonly record struct NativeError(NativeStatus Status, uint Domain, ulong CorrelationId, string Message);

public static class NativeAbiConstants
{
    public const uint Major = 1;
    public const uint ProbeMinor = 0;
    public const uint FunctionalMinor = 1;
    public const uint RecordVersion1 = 1;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeBoolean
{
    internal byte Value;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeStringView
{
    internal nint Data;
    internal ulong Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeByteView
{
    internal nint Data;
    internal ulong Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeBuffer
{
    internal nint Data;
    internal ulong Capacity;
    internal ulong Required;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeRational
{
    internal long Numerator;
    internal long Denominator;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeTimeRange
{
    internal NativeRational Start;
    internal NativeRational Duration;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeErrorBuffer
{
    internal uint StructSize;
    internal uint StructVersion;
    internal int Status;
    internal uint Domain;
    internal ulong CorrelationId;
    internal NativeBuffer Message;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal unsafe struct NativeCancelToken
{
    internal uint StructSize;
    internal uint StructVersion;
    internal delegate* unmanaged[Cdecl]<nint, byte> IsCancelled;
    internal nint UserData;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal unsafe struct NativeIoV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal nint Context;
    internal ulong Length;
    internal ulong MaxLength;
    internal delegate* unmanaged[Cdecl]<nint, ulong, nint, ulong, ulong*, int> ReadAt;
    internal delegate* unmanaged[Cdecl]<nint, ulong, nint, ulong, ulong*, int> WriteAt;
    internal delegate* unmanaged[Cdecl]<nint, int> Flush;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeLimitsV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal ulong MaxInputBytes;
    internal ulong MaxMemoryBytes;
    internal ulong MaxOutputBytes;
    internal uint MaxWidth;
    internal uint MaxHeight;
    internal uint MaxItems;
    internal uint TimeoutMs;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeFrameV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal ulong Buffer;
    internal ulong Sequence;
    internal long Pts;
    internal long Duration;
    internal NativeRational TimeBase;
    internal uint Kind;
    internal uint Format;
    internal uint Width;
    internal uint Height;
    internal uint SampleRate;
    internal uint Channels;
    internal ulong SampleCount;
    internal ulong ByteLength;
    internal uint Flags;
    internal uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeRegionV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal uint X;
    internal uint Y;
    internal uint Width;
    internal uint Height;
    internal ulong FirstSample;
    internal ulong SampleCount;
    internal ulong RowStride;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeInstrumentOptionsV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal NativeStringView DeviceId;
    internal uint Transport;
    internal uint InterfaceNumber;
    internal uint Baud;
    internal uint DataBits;
    internal uint Parity;
    internal uint StopBits;
    internal uint FlowControl;
    internal uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeTransferV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal uint Kind;
    internal uint Endpoint;
    internal uint TimeoutMs;
    internal uint RequestType;
    internal uint Request;
    internal uint Value;
    internal uint Index;
    internal uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeImageOptionsV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal uint Subimage;
    internal uint Mip;
    internal uint Format;
    internal uint Reserved;
    internal NativeLimitsV1 Limits;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativePdfPageV1
{
    internal uint StructSize;
    internal uint StructVersion;
    internal uint PageIndex;
    internal uint Rotation;
    internal double WidthPoints;
    internal double HeightPoints;
}

/// <summary>
/// Owns one opaque, process-local native handle token. Implementations must release the token
/// through their matching native close function; tokens are never domain identifiers or wire data.
/// </summary>
public abstract class NativeSafeHandle : SafeHandle
{
    protected NativeSafeHandle(ulong token) : base(IntPtr.Zero, ownsHandle: true)
    {
        if (IntPtr.Size != sizeof(ulong))
        {
            throw new PlatformNotSupportedException("The native ABI requires a 64-bit process.");
        }

        if (token == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(token), "Native handle tokens are nonzero.");
        }

        SetHandle(new IntPtr(unchecked((long)token)));
    }

    public sealed override bool IsInvalid => handle == IntPtr.Zero;

    protected abstract NativeStatus ReleaseNativeToken(ulong token);

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "SafeHandle cleanup must translate every close failure to false rather than propagate through deterministic or finalizer release.")]
    protected sealed override bool ReleaseHandle()
    {
        try
        {
            NativeStatus status = ReleaseNativeToken(unchecked((ulong)handle.ToInt64()));
            return status is NativeStatus.Ok or NativeStatus.Closed;
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>Closed numeric keys shared by the retained image, instrument and PDF ABI families.</summary>
public static class NativeAbiKeys
{
    public const uint IoRead = 1;
    public const uint IoWrite = 2;

    public const uint FrameVideo = 1;
    public const uint FrameAudio = 2;
    public const uint FrameSubtitle = 3;
    public const uint FrameData = 4;

    public const uint FormatRgba8 = 1;
    public const uint FormatRgba32fLinearPremultiplied = 2;
    public const uint FormatFloat32Interleaved = 3;

    public const uint InstrumentSerial = 1;
    public const uint InstrumentUsb = 2;
    public const uint ParityNone = 0;
    public const uint ParityOdd = 1;
    public const uint ParityEven = 2;
    public const uint StopBitsOne = 1;
    public const uint StopBitsTwo = 2;
    public const uint FlowControlNone = 0;
    public const uint FlowControlRtsCts = 1;
    public const uint FlowControlXonXoff = 2;

    public const uint TransferUsbControl = 1;
    public const uint TransferUsbBulk = 2;
    public const uint TransferUsbInterrupt = 3;
    public const uint TransferSerialRead = 4;
    public const uint TransferSerialWrite = 5;
}

internal static unsafe class NativeAbi
{
    internal delegate int VersionCall(uint* major, uint* minor);
    internal delegate int BufferCall(ref NativeBuffer output);
    internal delegate int ErrorCall(ref NativeErrorBuffer output);

    internal static NativeAbiVersion GetVersion(VersionCall call)
    {
        uint major;
        uint minor;
        int status = call(&major, &minor);
        if (status != 0 || major != 1)
        {
            throw new InvalidOperationException($"Unsupported native ABI ({status}, {major}.{minor}).");
        }

        return new NativeAbiVersion(major, minor);
    }

    internal static string GetBuildInfo(BufferCall call, ErrorCall errorCall)
    {
        NativeBuffer query = default;
        int status = call(ref query);
        if (status != (int)NativeStatus.BufferTooSmall || query.Required is 0 or > 4096)
        {
            throw new InvalidOperationException($"Native build-info query failed ({status}): {GetError(errorCall).Message}");
        }

        byte[] bytes = GC.AllocateUninitializedArray<byte>(checked((int)query.Required));
        fixed (byte* data = bytes)
        {
            NativeBuffer output = new() { Data = (nint)data, Capacity = (ulong)bytes.Length };
            status = call(ref output);
            if (status != 0 || output.Required != (ulong)bytes.Length)
            {
                throw new InvalidOperationException($"Native build-info write failed ({status}).");
            }
        }

        return new UTF8Encoding(false, true).GetString(bytes);
    }

    internal static NativeError GetError(ErrorCall call)
    {
        NativeErrorBuffer output = new()
        {
            StructSize = checked((uint)sizeof(NativeErrorBuffer)),
            StructVersion = 1,
        };
        int status = call(ref output);
        if (status == 0 && output.Message.Required == 0)
        {
            return new NativeError((NativeStatus)output.Status, output.Domain, output.CorrelationId, string.Empty);
        }

        if (status != (int)NativeStatus.BufferTooSmall || output.Message.Required is 0 or > 512)
        {
            throw new InvalidOperationException($"Native error query failed ({status}).");
        }

        byte[] bytes = GC.AllocateUninitializedArray<byte>(checked((int)output.Message.Required));
        fixed (byte* data = bytes)
        {
            output.Message = new NativeBuffer { Data = (nint)data, Capacity = (ulong)bytes.Length };
            status = call(ref output);
            if (status != 0 || output.Message.Required != (ulong)bytes.Length)
            {
                throw new InvalidOperationException($"Native error write failed ({status}).");
            }
        }

        return new NativeError((NativeStatus)output.Status, output.Domain, output.CorrelationId,
            new UTF8Encoding(false, true).GetString(bytes));
    }
}

internal static class NativeLoader
{
    internal static void Register(Assembly assembly, string libraryName)
    {
        var handle = new Lazy<nint>(() => Load(assembly, libraryName));
        NativeLibrary.SetDllImportResolver(assembly, (name, _, _) =>
            name == libraryName ? handle.Value : throw new DllNotFoundException(name));
    }

    private static nint Load(Assembly assembly, string libraryName)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException("This release requires an explicit win-x64 runtime package.");
        }

        string directory = AppContext.BaseDirectory;
        string manifestPath = Path.Combine(directory, libraryName + ".manifest.json");
        if (new FileInfo(manifestPath).Length > 1024 * 1024)
        {
            throw new InvalidDataException("Native runtime manifest exceeds its bound.");
        }

        using JsonDocument manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
        JsonElement root = manifest.RootElement;
        if (root.GetProperty("schemaVersion").GetInt32() != 1
            || root.GetProperty("rid").GetString() != "win-x64"
            || root.GetProperty("library").GetString() != libraryName)
        {
            throw new InvalidDataException("Native runtime manifest identity mismatch.");
        }

        bool foundLibrary = false;
        foreach (JsonElement file in root.GetProperty("files").EnumerateArray())
        {
            string name = file.GetProperty("name").GetString()!;
            if (name != Path.GetFileName(name) || name.Contains('\\', StringComparison.Ordinal)
                || name.Contains('/', StringComparison.Ordinal) || name.Contains(':', StringComparison.Ordinal))
            {
                throw new InvalidDataException("Native runtime manifest contains an invalid filename.");
            }

            using FileStream stream = File.OpenRead(Path.Combine(directory, name));
            string hash = Convert.ToHexStringLower(SHA256.HashData(stream));
            if (hash != file.GetProperty("sha256").GetString())
            {
                throw new InvalidDataException($"Native runtime hash mismatch: {name}");
            }

            foundLibrary |= name == libraryName + ".dll";
        }

        if (!foundLibrary)
        {
            throw new InvalidDataException("Native runtime manifest omits the owned library.");
        }

        return NativeLibrary.Load(Path.Combine(directory, libraryName + ".dll"), assembly,
            DllImportSearchPath.UseDllDirectoryForDependencies | DllImportSearchPath.System32);
    }
}
