// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

[assembly: InternalsVisibleTo("ArcForges.Native.Image")]
[assembly: InternalsVisibleTo("ArcForges.Native.Pdf")]
[assembly: InternalsVisibleTo("ArcForges.ContentSandbox")]
[assembly: InternalsVisibleTo("ArcForges.ContentSandbox.Broker")]
[assembly: InternalsVisibleTo("ArcForges.Tests.NativeAbiTests")]

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
    private static readonly object Gate = new();
    private static readonly Dictionary<string, NativeVerifiedRuntime> Production = new(StringComparer.Ordinal);
    private static readonly HashSet<string> Activated = new(StringComparer.Ordinal);
    private static bool _localFixture;

    internal static void ConfigureProduction(IReadOnlyDictionary<string, NativeVerifiedRuntime> runtimes)
    {
        lock (Gate)
        {
            if (_localFixture || Production.Count != 0 || Activated.Count != 0
                || runtimes.Count != 2 || !runtimes.ContainsKey("ArcImageNative") || !runtimes.ContainsKey("ArcPdfNative"))
            {
                throw new InvalidOperationException("The exact native production cohort must be installed once before any parser library activates.");
            }

            foreach (var pair in runtimes) { Production.Add(pair.Key, pair.Value); }
        }
    }

    internal static void ConfigureLocalFixture()
    {
        lock (Gate)
        {
            if (Production.Count != 0 || Activated.Count != 0) { throw new InvalidOperationException("A local fixture cannot replace an active production native cohort."); }
            _localFixture = true;
        }
    }

    internal static void RequireProduction(string library)
    {
        lock (Gate)
        {
            if (!Production.ContainsKey(library) && !_localFixture)
            {
                throw new InvalidOperationException("The helper has no authenticated production native cohort.");
            }
        }
    }

    internal static void Register(Assembly assembly, string libraryName)
    {
        var handle = new Lazy<nint>(() => Load(assembly, libraryName));
        NativeLibrary.SetDllImportResolver(assembly, (name, _, _) =>
            name == libraryName ? handle.Value : throw new DllNotFoundException(name));
    }

    private static nint Load(Assembly assembly, string libraryName)
    {
        lock (Gate)
        {
            Activated.Add(libraryName);
            if (Production.TryGetValue(libraryName, out var runtime)) { return runtime.Handle; }
        }

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


/// <summary>Exact installed production identity. Caller-provided hashes alone never establish publisher trust.</summary>
internal sealed record NativeRuntimeIdentity(string Rid, string Library, string PackageVersion,
    string SourceCommit, string ProfileSha256, string ManifestSha256)
{
    internal void Validate()
    {
        if (Rid is not ("win-x64" or "win-arm64" or "linux-x64" or "linux-arm64" or "osx-x64" or "osx-arm64")
            || Library is not ("ArcImageNative" or "ArcPdfNative")
            || !Version(PackageVersion)
            || !Digest(SourceCommit, 40) || !Digest(ProfileSha256, 64) || !Digest(ManifestSha256, 64))
        {
            throw new InvalidDataException("The production native runtime identity is invalid.");
        }
    }

    private static bool Digest(string value, int length) => value is not null && value.Length == length
        && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool Version(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-')))
        {
            return false;
        }

        var separator = value.IndexOf('-', StringComparison.Ordinal);
        var numbers = (separator < 0 ? value : value[..separator]).Split('.');
        if (numbers.Length != 3 || numbers.Any(part => part.Length == 0 || part.Any(c => !char.IsAsciiDigit(c)) || part.Length > 1 && part[0] == '0'))
        {
            return false;
        }

        return separator < 0 || value[(separator + 1)..].Split('.').All(part => part.Length != 0
            && !(part.Length > 1 && part[0] == '0' && part.All(char.IsAsciiDigit)));
    }
}

/// <summary>Approved immutable publisher keys; material is copied and validated rather than borrowed from an envelope.</summary>
internal sealed class NativePublisherTrust
{
    private readonly Dictionary<string, byte[]> _keys = new(StringComparer.Ordinal);

    internal NativePublisherTrust(IEnumerable<KeyValuePair<string, byte[]>> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        foreach (var pair in keys)
        {
            if (_keys.Count >= 8 || string.IsNullOrEmpty(pair.Key) || pair.Key.Length > 128
                || pair.Key.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-'))
                || pair.Value is null || pair.Value.Length is 0 or > 512 || _keys.ContainsKey(pair.Key))
            {
                throw new InvalidDataException("The native publisher key inventory is invalid.");
            }

            var bytes = pair.Value.ToArray();
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(bytes, out var read);
            if (read != bytes.Length || key.KeySize != 256
                || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            {
                throw new InvalidDataException("Native publisher keys require the exact ES256 curve and complete SPKI.");
            }

            _keys.Add(pair.Key, bytes);
        }

        if (_keys.Count == 0)
        {
            throw new InvalidDataException("An approved native publisher key is required.");
        }
    }

    internal void Verify(ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> manifest,
        NativeRuntimeIdentity expected, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        expected.Validate();
        if (envelope.Length is 0 or > 8192 || manifest.Length is 0 or > 1024 * 1024)
        {
            throw new InvalidDataException("The signed native manifest exceeds its production bound.");
        }

        using var outer = JsonDocument.Parse(envelope.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
        var root = outer.RootElement;
        Closed(root, ["algorithm", "payload", "schemaVersion", "signature"]);
        if (RequiredInteger(root, "schemaVersion") != 1 || RequiredString(root, "algorithm") != "ES256")
        {
            throw new InvalidDataException("The native signature envelope version or algorithm is unsupported.");
        }

        var payload = Decode(RequiredString(root, "payload"), 4096);
        var signature = Decode(RequiredString(root, "signature"), 64);
        if (signature.Length != 64)
        {
            throw new InvalidDataException("ES256 requires a complete fixed-field signature.");
        }

        using var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 4 });
        var value = document.RootElement;
        Closed(value, ["keyId", "library", "manifestSha256", "packageVersion", "profileSha256", "publisher", "rid", "schemaVersion", "sourceCommit"]);
        var keyId = RequiredString(value, "keyId");
        if (RequiredInteger(value, "schemaVersion") != 1 || RequiredString(value, "publisher") != "ArcForges"
            || !_keys.TryGetValue(keyId, out var spki)
            || !payload.AsSpan().SequenceEqual(EncodePayload(expected, keyId)))
        {
            throw new InvalidDataException("The native signature is not bound to the exact approved publisher, source, RID and profile.");
        }

        var actualHash = Convert.ToHexStringLower(SHA256.HashData(manifest));
        if (actualHash != expected.ManifestSha256)
        {
            throw new InvalidDataException("The authenticated native manifest bytes changed.");
        }

        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        if (!key.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new CryptographicException("The native publisher signature is invalid.");
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    internal static byte[] EncodePayload(NativeRuntimeIdentity identity, string keyId)
    {
        identity.Validate();
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("keyId", keyId);
            writer.WriteString("library", identity.Library);
            writer.WriteString("manifestSha256", identity.ManifestSha256);
            writer.WriteString("packageVersion", identity.PackageVersion);
            writer.WriteString("profileSha256", identity.ProfileSha256);
            writer.WriteString("publisher", "ArcForges");
            writer.WriteString("rid", identity.Rid);
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("sourceCommit", identity.SourceCommit);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static byte[] Decode(string text, int maximum)
    {
        if (text.Length > ((maximum + 2) / 3) * 4)
        {
            throw new InvalidDataException("The native signature field exceeds its bound.");
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(text);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The native signature field is not Base64.", exception);
        }

        if (bytes.Length > maximum || Convert.ToBase64String(bytes) != text)
        {
            throw new InvalidDataException("The native signature field is not canonical bounded Base64.");
        }

        return bytes;
    }

    private static string RequiredString(JsonElement value, string name)
    {
        var property = value.GetProperty(name);
        if (property.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("The native signature contract requires a string: " + name);
        }

        return property.GetString()!;
    }

    private static int RequiredInteger(JsonElement value, string name)
    {
        var property = value.GetProperty(name);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt32(out var result))
        {
            throw new InvalidDataException("The native signature contract requires an integer: " + name);
        }

        return result;
    }

    private static void Closed(JsonElement value, string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The signed native contract must be an object.");
        }

        var actual = value.EnumerateObject().Select(p => p.Name).ToArray();
        if (actual.Length != fields.Length || actual.Distinct(StringComparer.Ordinal).Count() != actual.Length
            || !actual.Order(StringComparer.Ordinal).SequenceEqual(fields.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new InvalidDataException("The signed native contract contains missing, duplicate or unknown fields.");
        }
    }
}


/// <summary>Real release envelope signing over an externally provisioned ES256 private key (including certificate/HSM providers).</summary>
internal sealed class NativePublisherSigner(ECDsa key, string keyId)
{
    private readonly object _gate = new();

    internal byte[] Sign(NativeRuntimeIdentity identity, ReadOnlySpan<byte> manifest, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        cancellationToken.ThrowIfCancellationRequested();
        identity.Validate();
        // Reuse the closed public-key admission contract; the private provider need not support private-key export.
        _ = new NativePublisherTrust([new(keyId, key.ExportSubjectPublicKeyInfo())]);
        if (manifest.Length is 0 or > 1024 * 1024
            || Convert.ToHexStringLower(SHA256.HashData(manifest)) != identity.ManifestSha256)
        {
            throw new InvalidDataException("Signing requires the exact bounded production manifest bytes.");
        }

        var payload = NativePublisherTrust.EncodePayload(identity, keyId);
        byte[] signature;
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            signature = key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("algorithm", "ES256");
            writer.WriteString("payload", Convert.ToBase64String(payload));
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("signature", Convert.ToBase64String(signature));
            writer.WriteEndObject();
        }

        var envelope = stream.ToArray();
        // Refuse a broken signing provider before a purported release receipt can be emitted.
        new NativePublisherTrust([new(keyId, key.ExportSubjectPublicKeyInfo())]).Verify(envelope, manifest, identity, cancellationToken);
        return envelope;
    }
}

/// <summary>A platform lease pins verified bytes and their loader location until every native handle is released.</summary>
internal interface INativeRuntimeFileLease : IDisposable
{
    Stream Bytes { get; }
    string LoaderPath { get; }
}

/// <summary>Closed platform adapter. Production implementations must pin bytes, not merely reopen a verified pathname.</summary>
internal interface INativeRuntimeLoadPlatform
{
    string Rid { get; }
    INativeRuntimeFileLease Open(string directory, string name, CancellationToken cancellationToken);
    nint Load(string loaderPath);
    bool HasExport(nint handle, string name);
    void Free(nint handle);
}

/// <summary>Actual Windows loading with mandatory read-only sharing, preventing writes and pathname replacement while retained.</summary>
internal sealed class WindowsNativeRuntimeLoadPlatform : INativeRuntimeLoadPlatform
{
    public string Rid => OperatingSystem.IsWindows() ? RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => "win-x64",
        Architecture.Arm64 => "win-arm64",
        _ => throw new PlatformNotSupportedException("Only the admitted Windows architectures are supported."),
    } : throw new PlatformNotSupportedException("Windows runtime loading requires Windows.");

    public INativeRuntimeFileLease Open(string directory, string name, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows runtime loading requires Windows.");
        }

        return new WindowsFile(Path.Combine(directory, name));
    }

    public nint Load(string loaderPath) => NativeLibrary.Load(loaderPath, typeof(WindowsNativeRuntimeLoadPlatform).Assembly,
        DllImportSearchPath.UseDllDirectoryForDependencies | DllImportSearchPath.System32);
    public bool HasExport(nint handle, string name) => NativeLibrary.TryGetExport(handle, name, out _);
    public void Free(nint handle) => NativeLibrary.Free(handle);

    private sealed class WindowsFile(string path) : INativeRuntimeFileLease
    {
        private readonly FileStream _stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        public Stream Bytes => _stream;
        public string LoaderPath => path;
        public void Dispose() => _stream.Dispose();
    }
}

/// <summary>Authenticated complete native closure. Nothing is executed until every bounded file and dependency has passed admission.</summary>
internal sealed class NativeVerifiedRuntime : IDisposable
{
    private readonly object _gate = new();
    private readonly INativeRuntimeLoadPlatform _platform;
    private readonly List<INativeRuntimeFileLease> _files = [];
    private readonly List<nint> _handles = [];
    private nint _owned;
    private bool _disposed;

    private NativeVerifiedRuntime(INativeRuntimeLoadPlatform platform) => _platform = platform;

    internal nint Handle
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _owned;
            }
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "The returned runtime owns all pinned files/modules; the catch disposes that complete owner and preserves admission plus cleanup failures. Component tests cover every failure phase and concurrent disposal.")]
    internal static NativeVerifiedRuntime Open(string directory, ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> envelope,
        NativeRuntimeIdentity identity, NativePublisherTrust trust, IReadOnlySet<string> allowedSystemImports,
        INativeRuntimeLoadPlatform platform, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(allowedSystemImports);
        ArgumentNullException.ThrowIfNull(platform);
        if (!Path.IsPathFullyQualified(directory) || Path.GetFullPath(directory) != directory)
        {
            throw new InvalidDataException("The production native directory must be an explicit canonical absolute locator.");
        }

        trust.Verify(envelope, manifest, identity, cancellationToken);
        if (platform.Rid != identity.Rid)
        {
            throw new PlatformNotSupportedException("The installed native closure does not match the actual loader platform.");
        }

        using var document = JsonDocument.Parse(manifest.ToArray(), new JsonDocumentOptions { MaxDepth = 16 });
        var root = document.RootElement;
        RequireClosed(root, root.TryGetProperty("vcpkgCommit", out var vcpkg)
            ? ["schemaVersion", "sourceCommit", "rid", "library", "abi", "files", "vcpkgCommit"]
            : ["schemaVersion", "sourceCommit", "rid", "library", "abi", "files"]);
        if (vcpkg.ValueKind != JsonValueKind.Undefined && (identity.Library != "ArcImageNative"
            || vcpkg.ValueKind != JsonValueKind.String || vcpkg.GetString() is not { Length: 40 } commit
            || commit.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))))
        {
            throw new InvalidDataException("The signed Image producer source identity is invalid.");
        }
        if (root.GetProperty("schemaVersion").GetInt32() != 1 || root.GetProperty("sourceCommit").GetString() != identity.SourceCommit
            || root.GetProperty("rid").GetString() != identity.Rid || root.GetProperty("library").GetString() != identity.Library)
        {
            throw new InvalidDataException("The authenticated native closure identity is inconsistent.");
        }

        var abi = root.GetProperty("abi");
        RequireClosed(abi, ["major", "minor"]);
        if (abi.GetProperty("major").GetInt32() != 1 || abi.GetProperty("minor").GetInt32() != 1)
        {
            throw new InvalidDataException("The production parser requires exact functional ABI 1.1.");
        }

        var files = root.GetProperty("files");
        if (files.ValueKind != JsonValueKind.Array || files.GetArrayLength() is 0 or > 64)
        {
            throw new InvalidDataException("The native file closure exceeds its bound.");
        }

        var comparer = identity.Rid.StartsWith("win-", StringComparison.Ordinal) ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var rows = new Dictionary<string, JsonElement>(comparer);
        foreach (var file in files.EnumerateArray())
        {
            RequireUnique(file);
            string[] allowedMetadata = ["name", "sha256", "machine", "imports", "exports", "format", "identity", "runpaths", "forwardedExports", "dataExports", "unnamedExports", "absoluteExports", "versionRequirements", "minimumOs", "sourceSpdxPath"];
            if (file.EnumerateObject().Any(property => !allowedMetadata.Contains(property.Name, StringComparer.Ordinal)))
            {
                throw new InvalidDataException("The native file metadata contains an unknown field.");
            }

            var name = file.GetProperty("name").GetString()!;
            if (string.IsNullOrEmpty(name) || name.Length > 128 || name[0] == '.' || name[^1] == '.'
                || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_')) || !rows.TryAdd(name, file))
            {
                throw new InvalidDataException("The native closure filename is invalid or duplicated.");
            }

            var digest = file.GetProperty("sha256").GetString();
            if (digest is null || digest.Length != 64 || digest.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            {
                throw new InvalidDataException("The native closure digest is invalid.");
            }

            var machine = file.GetProperty("machine").GetString();
            var arm = identity.Rid.EndsWith("arm64", StringComparison.Ordinal);
            var expectedMachine = file.TryGetProperty("format", out var format) ? (arm ? "aarch64" : "x86_64") : (arm ? "arm64" : "x64");
            var expectedFormat = identity.Rid.StartsWith("win-", StringComparison.Ordinal) ? "PE32+"
                : identity.Rid.StartsWith("linux-", StringComparison.Ordinal) ? "ELF64" : "Mach-O64";
            if (machine != expectedMachine || (format.ValueKind != JsonValueKind.Undefined && format.GetString() != expectedFormat))
            {
                throw new InvalidDataException("The native closure contains a foreign architecture.");
            }
        }

        var suffix = identity.Rid.StartsWith("win-", StringComparison.Ordinal) ? ".dll"
            : identity.Rid.StartsWith("linux-", StringComparison.Ordinal) ? ".so" : ".dylib";
        var ownedName = (identity.Rid.StartsWith("win-", StringComparison.Ordinal) ? "" : "lib") + identity.Library + suffix;
        if (!rows.TryGetValue(ownedName, out var ownedRow))
        {
            throw new InvalidDataException("The complete native closure omits the owned parser library.");
        }

        var family = identity.Library == "ArcPdfNative" ? "pdf" : "image";
        var expectedExports = family == "pdf" ? new[] { "arc_pdf_close", "arc_pdf_get_abi_version", "arc_pdf_get_build_info", "arc_pdf_get_last_error", "arc_pdf_open", "arc_pdf_page_info", "arc_pdf_render", "arc_pdf_text" }
            : ["arc_image_close", "arc_image_get_abi_version", "arc_image_get_build_info", "arc_image_get_last_error", "arc_image_open", "arc_image_read"];
        if (!Strings(ownedRow.GetProperty("exports"), 16).SequenceEqual(expectedExports, StringComparer.Ordinal))
        {
            throw new InvalidDataException("The native parser does not declare its exact functional export contract.");
        }

        foreach (var invalid in new[] { "forwardedExports", "dataExports", "unnamedExports" })
        {
            if (ownedRow.TryGetProperty(invalid, out var extras)
                && (extras.ValueKind == JsonValueKind.Array ? extras.GetArrayLength() != 0 : extras.GetInt32() != 0))
            {
                throw new InvalidDataException("Owned parser exports must be callable and directly owned.");
            }
        }

        if (ownedRow.TryGetProperty("absoluteExports", out var absolute)
            && Strings(absolute, 16).Any(name => !identity.Rid.StartsWith("linux-", StringComparison.Ordinal) || name != "ARCFORGES_1.0"))
        {
            throw new InvalidDataException("The parser contains an unadmitted absolute export; only ELF version metadata is permitted.");
        }

        var order = new List<string>();
        var visiting = new HashSet<string>(comparer);
        var visited = new HashSet<string>(comparer);
        void Visit(string name)
        {
            if (visited.Contains(name)) { return; }
            if (!visiting.Add(name)) { throw new InvalidDataException("The native dependency closure contains a cycle."); }
            foreach (var import in Strings(rows[name].GetProperty("imports"), 4096))
            {
                var bundled = import.StartsWith("@loader_path/", StringComparison.Ordinal) ? import[13..]
                    : import.StartsWith("@rpath/", StringComparison.Ordinal) ? import[7..] : import;
                if (rows.ContainsKey(bundled)) { Visit(bundled); }
                else if (!allowedSystemImports.Contains(import)) { throw new InvalidDataException("The native dependency is outside the approved closure: " + import); }
            }

            visiting.Remove(name);
            visited.Add(name);
            order.Add(name);
        }

        foreach (var name in rows.Keys) { Visit(name); }
        var runtime = new NativeVerifiedRuntime(platform);
        try
        {
            var leases = new Dictionary<string, INativeRuntimeFileLease>(comparer);
            // Pin and hash the entire closure first. A later bad file must never follow an earlier native execution.
            foreach (var row in rows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var lease = platform.Open(directory, row.Key, cancellationToken);
                runtime._files.Add(lease);
                leases.Add(row.Key, lease);
                var stream = lease.Bytes;
                if (!stream.CanRead || !stream.CanSeek || stream.Length is 0 or > 256L * 1024 * 1024)
                {
                    throw new InvalidDataException("The native file exceeds its production bound.");
                }

                stream.Position = 0;
                using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[64 * 1024];
                int count;
                long total = 0;
                while ((count = stream.Read(buffer)) != 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    total = checked(total + count);
                    if (total > 256L * 1024 * 1024) { throw new InvalidDataException("The native file grew beyond its production bound."); }
                    digest.AppendData(buffer.AsSpan(0, count));
                }

                if (total != stream.Length || Convert.ToHexStringLower(digest.GetHashAndReset()) != row.Value.GetProperty("sha256").GetString())
                {
                    throw new InvalidDataException("The pinned native file digest differs from its authenticated manifest.");
                }
            }

            foreach (var name in order)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var handle = platform.Load(leases[name].LoaderPath);
                if (handle == 0) { throw new DllNotFoundException("The native platform returned no loaded module."); }
                runtime._handles.Add(handle);
                if (comparer.Equals(name, ownedName)) { runtime._owned = handle; }
            }

            foreach (var export in expectedExports)
            {
                if (!platform.HasExport(runtime._owned, export)) { throw new EntryPointNotFoundException(export); }
            }

            cancellationToken.ThrowIfCancellationRequested();
            return runtime; // Complete lifetime ownership transfers only after all admission and loading checks.
        }
        catch (Exception primary)
        {
            try { runtime.Dispose(); }
            catch (AggregateException cleanup) { throw new AggregateException("Native runtime admission and cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    private static string[] Strings(JsonElement array, int maximum)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > maximum)
        {
            throw new InvalidDataException("The native metadata inventory exceeds its bound.");
        }

        var result = array.EnumerateArray().Select(value => value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new InvalidDataException("Native metadata must be strings.")).ToArray();
        if (result.Any(value => string.IsNullOrEmpty(value) || value.Length > 512) || result.Distinct(StringComparer.Ordinal).Count() != result.Length)
        {
            throw new InvalidDataException("Native metadata strings are invalid or duplicated.");
        }

        return result;
    }

    private static void RequireUnique(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != value.EnumerateObject().Count())
        {
            throw new InvalidDataException("Native metadata contains duplicate fields or is not an object.");
        }
    }

    private static void RequireClosed(JsonElement value, string[] fields)
    {
        RequireUnique(value);
        if (!value.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).SequenceEqual(fields.Order(StringComparer.Ordinal)))
        {
            throw new InvalidDataException("The native closure contains unknown or missing fields.");
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031", Justification = "Attempt every native-handle and pinned-file release even if one platform cleanup fails.")]
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) { return; }
            _disposed = true;
            var errors = new List<Exception>();
            for (var index = _handles.Count - 1; index >= 0; index--)
            {
                try { _platform.Free(_handles[index]); } catch (Exception error) { errors.Add(error); }
            }

            for (var index = _files.Count - 1; index >= 0; index--)
            {
                try { _files[index].Dispose(); } catch (Exception error) { errors.Add(error); }
            }

            if (errors.Count != 0) { throw new AggregateException("Native runtime cleanup failed.", errors); }
        }
    }
}
