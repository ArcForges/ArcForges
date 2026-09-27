// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

[assembly: InternalsVisibleTo("ArcForges.Native.Image")]

namespace ArcForges.Native.Abstractions;

public enum NativeStatus
{
    Ok = 0,
    BufferTooSmall = 1,
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

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NativeBuffer
{
    internal nint Data;
    internal ulong Capacity;
    internal ulong Required;
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
