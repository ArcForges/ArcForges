// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.RunSupervisor.Protocol;

public enum RunControlCommand
{
    Hello,
    Activate,
    Stop,
    Observe,
    TerminalBegin,
    TerminalPoll,
}

public sealed record RunControlFrame(
    long Sequence, RunControlCommand Command, RunRelease? Release = null, int GraceMilliseconds = 0,
    RunOwnerIdentity? Identity = null, RunOwnerObservation? Observation = null, string? Error = null, string? LaunchBinding = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] RunTerminalRequest? TerminalRequest = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] RunTerminalPoll? TerminalPoll = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] RunTerminalReply? TerminalReply = null);

public sealed record RunTerminalPoll(RunTerminalCaller Caller, string CommandId);

internal sealed record RunObservationReceipt(
    string RunId, string Epoch, string LaunchSha256, RunOwnerObservation Observation);

[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(RunLaunchSpec))]
[JsonSerializable(typeof(RunLaunchInputs))]
[JsonSerializable(typeof(RunControlFrame))]
[JsonSerializable(typeof(RunObservationReceipt))]
internal sealed partial class RunJson : JsonSerializerContext;

/// <summary>Bounded files and authenticated frames for the private supervisor channel.</summary>
public static partial class RunWire
{
    public const int KeyLength = 32;
    public const int ChallengeLength = 32;
    public const int LaunchInputsLimit = 2 * 1024 * 1024;
    private const int LaunchLimit = 2 * 1024 * 1024;
    private const int FrameLimit = 64 * 1024;
    private const int ObservationLimit = 64 * 1024;
    // JSON base64 expands the 64 KiB terminal input. Only Begin may carry that payload.
    private const int TerminalRequestLimit = 96 * 1024;
    private const int TerminalReplyLimit = 8 * 1024;

    public static string LaunchPath(RunLaunchSpec spec) => Path.Combine(spec.ControlDirectory, "launch.json");

    private static string ObservationPath(RunLaunchSpec spec) => Path.Combine(spec.ControlDirectory, "observed.bin");

    public static string WriteLaunch(RunLaunchSpec spec, Action<SafeFileHandle>? captureCreatedFile = null)
    {
        if (!CanEncodeLaunchInputs(spec))
        {
            throw new InvalidDataException("run_launch_inputs_invalid");
        }

        var manifest = spec with { InputBinding = Convert.ToHexStringLower(BindInputs(spec, new(spec.Argv, spec.Environment))) };
        ValidateLaunch(manifest);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, RunJson.Default.RunLaunchSpec);
        if (bytes.Length > LaunchLimit)
        {
            throw new InvalidDataException("run_launch_too_large");
        }

        WritePrivateNew(LaunchPath(manifest), bytes, captureCreatedFile);
        return LaunchBinding(manifest, bytes);
    }

    public static RunLaunchSpec ReadLaunch(string path, out string launchBinding)
    {
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException("run_launch_path_invalid");
        }

        var bytes = ReadPrivate(path, LaunchLimit);
        var spec = JsonSerializer.Deserialize(bytes, RunJson.Default.RunLaunchSpec)
            ?? throw new InvalidDataException("run_launch_invalid");
        ValidateLaunch(spec);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(LaunchPath(spec)), comparison))
        {
            throw new InvalidDataException("run_launch_path_mismatch");
        }

        launchBinding = LaunchBinding(spec, bytes);
        return spec;
    }

    private static string LaunchBinding(RunLaunchSpec spec, byte[] bytes) =>
        Convert.ToHexStringLower(Authenticate(spec.ControlKey, 4, [], bytes));

    public static bool CanEncodeLaunchInputs(RunLaunchSpec spec)
    {
        var inputs = new RunLaunchInputs(spec.Argv, spec.Environment);
        if (!ValidLaunchInputs(spec, inputs))
        {
            return false;
        }

        // Reserve the exact header overhead of the largest sequence and a Windows Job capability.
        var frame = new RunControlFrame(long.MaxValue, RunControlCommand.Activate, new RunRelease(long.MaxValue, inputs));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(frame, RunJson.Default.RunControlFrame);
        try
        {
            return bytes.Length <= LaunchInputsLimit;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool ValidLaunchInputs(RunLaunchSpec spec, RunLaunchInputs? inputs)
    {
        if (inputs is not { Argv.Length: > 0 and <= 256, Environment: not null }
            || !StringComparer.Ordinal.Equals(inputs.Argv[0], spec.ExecutablePath)
            || inputs.Argv.Any(argument => argument is null || argument.Contains('\0')))
        {
            return false;
        }

        var names = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var entry in inputs.Environment)
        {
            if (entry is not { Name.Length: >= 1 and <= 256, Value: not null }
                || entry.Name.AsSpan().IndexOfAny('=', '\0') >= 0 || entry.Value.Contains('\0')
                || System.Text.Encoding.UTF8.GetByteCount(entry.Value) > 32_768 || !names.Add(entry.Name)
                || entry.Name.StartsWith("ARCFORGES_", StringComparison.OrdinalIgnoreCase)
                || entry.Name.StartsWith("MXC_", StringComparison.OrdinalIgnoreCase)
                || entry.Name.StartsWith("BWRAP_", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] BindInputs(RunLaunchSpec spec, RunLaunchInputs inputs)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(inputs, RunJson.Default.RunLaunchInputs);
        try
        {
            return Authenticate(spec.ControlKey, 5, [], bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static void WriteObservation(RunLaunchSpec spec, RunOwnerObservation observation)
    {
        var path = ObservationPath(spec);
        var temp = Path.Combine(spec.ControlDirectory, $".observed-{Guid.NewGuid():N}.tmp");
        var receipt = new RunObservationReceipt(spec.RunId, spec.Epoch, spec.LaunchSha256, observation);
        var message = JsonSerializer.SerializeToUtf8Bytes(receipt, RunJson.Default.RunObservationReceipt);
        if (message.Length > ObservationLimit)
        {
            throw new InvalidDataException("run_observation_too_large");
        }

        var bytes = new byte[message.Length + KeyLength];
        message.CopyTo(bytes, 0);
        Authenticate(spec.ControlKey, 3, [], message).CopyTo(bytes, message.Length);
        try
        {
            WritePrivateNew(temp, bytes);
            CommitPrivateReplace(temp, path, spec.ControlDirectory, "run_receipt");
        }
        finally
        {
            File.Delete(temp);
        }
    }

    public static RunOwnerObservation? TryReadObservation(RunLaunchSpec spec)
    {
        try
        {
            var bytes = ReadPrivate(ObservationPath(spec), ObservationLimit + KeyLength);
            if (bytes.Length <= KeyLength)
            {
                return null;
            }

            var message = bytes.AsSpan(0, bytes.Length - KeyLength);
            if (!CryptographicOperations.FixedTimeEquals(bytes.AsSpan(bytes.Length - KeyLength), Authenticate(spec.ControlKey, 3, [], message)))
            {
                return null;
            }

            var receipt = JsonSerializer.Deserialize(message, RunJson.Default.RunObservationReceipt);
            return receipt is not null && receipt.RunId == spec.RunId && receipt.Epoch == spec.Epoch && receipt.LaunchSha256 == spec.LaunchSha256
                ? receipt.Observation
                : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or CryptographicException or InvalidDataException)
        {
            return null;
        }
    }

    public static async ValueTask WriteFrameAsync(Stream stream, RunLaunchSpec spec, byte[] challenge, bool response, RunControlFrame frame,
        CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(frame, RunJson.Default.RunControlFrame);
        byte[]? data = null;
        try
        {
            if (body.Length < 1 || body.Length > ControlFrameLimit(frame.Command, response))
            {
                throw new InvalidDataException("run_control_frame_too_large");
            }

            data = new byte[sizeof(int) + body.Length + KeyLength];
            BinaryPrimitives.WriteInt32BigEndian(data, body.Length);
            body.CopyTo(data, sizeof(int));
            Authenticate(spec.ControlKey, response ? (byte)2 : (byte)1, challenge, body).CopyTo(data, sizeof(int) + body.Length);
            await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (frame.TerminalRequest?.Input is not null || frame.Release?.Inputs is not null)
            {
                CryptographicOperations.ZeroMemory(body);
                if (data is not null)
                {
                    CryptographicOperations.ZeroMemory(data);
                }
            }
        }
    }

    public static async ValueTask<RunControlFrame> ReadFrameAsync(Stream stream, RunLaunchSpec spec, byte[] challenge, bool response,
        CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length < 1 || length > (response ? FrameLimit : LaunchInputsLimit))
        {
            throw new InvalidDataException("run_control_frame_length_invalid");
        }

        var bytes = new byte[length + KeyLength];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            var body = bytes.AsSpan(0, length);
            if (!CryptographicOperations.FixedTimeEquals(bytes.AsSpan(length), Authenticate(spec.ControlKey, response ? (byte)2 : (byte)1, challenge, body)))
            {
                throw new InvalidDataException("run_control_authentication_failed");
            }

            var frame = JsonSerializer.Deserialize(body, RunJson.Default.RunControlFrame)
                ?? throw new InvalidDataException("run_control_frame_invalid");
            if (length > ControlFrameLimit(frame.Command, response))
            {
                throw new InvalidDataException("run_control_frame_too_large");
            }

            if (response || frame.Command != RunControlCommand.Activate)
            {
                if (frame.Release is not null)
                {
                    frame.Release.Inputs?.Clear();
                    throw new InvalidDataException("run_release_unexpected");
                }
            }
            else if (frame.Release?.Inputs is not { } inputs || !ValidLaunchInputs(spec, inputs)
                || spec.InputBinding is null || !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(spec.InputBinding), BindInputs(spec, inputs)))
            {
                frame.Release?.Inputs?.Clear();
                throw new InvalidDataException("run_launch_inputs_mismatch");
            }

            return frame;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static int ControlFrameLimit(RunControlCommand command, bool response) => command switch
    {
        RunControlCommand.TerminalBegin when !response => TerminalRequestLimit,
        RunControlCommand.Activate when !response => LaunchInputsLimit,
        RunControlCommand.TerminalBegin or RunControlCommand.TerminalPoll => TerminalReplyLimit,
        _ => FrameLimit,
    };

    private static byte[] Authenticate(byte[] key, byte direction, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> bytes)
    {
        using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        mac.AppendData("arcforges-run-control-v1"u8);
        mac.AppendData([direction]);
        mac.AppendData(challenge);
        mac.AppendData(bytes);
        return mac.GetHashAndReset();
    }

    private static void ValidateLaunch(RunLaunchSpec spec)
    {
        if (spec.ControlKey?.Length != KeyLength || spec.InputBinding is not { Length: 64 }
            || !spec.InputBinding.All(char.IsAsciiHexDigitLower) || !Path.IsPathFullyQualified(spec.ExecutablePath)
            || string.IsNullOrWhiteSpace(spec.RunId) || string.IsNullOrWhiteSpace(spec.SandboxId) || string.IsNullOrWhiteSpace(spec.OwnerId)
            || string.IsNullOrWhiteSpace(spec.Epoch) || spec.LaunchSha256?.Length != 64 || string.IsNullOrWhiteSpace(spec.ControlEndpoint)
            || string.IsNullOrWhiteSpace(spec.ProfileId) || string.IsNullOrWhiteSpace(spec.ProfileVersion)
            || !Path.IsPathFullyQualified(spec.ControlDirectory) || !Path.IsPathFullyQualified(spec.SupervisorPath)
            || spec.SupervisorSha256 is not { Length: 64 } || !spec.SupervisorSha256.All(char.IsAsciiHexDigitLower)
            || !Path.IsPathFullyQualified(spec.InstallationRoot) || !Path.IsPathFullyQualified(spec.PrivateRoot))
        {
            throw new InvalidDataException("run_launch_invalid");
        }
    }

    private static byte[] ReadPrivate(string path, int limit)
    {
        var file = new FileInfo(path);
        if ((file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 || file.Length is < 1 || file.Length > limit)
        {
            throw new InvalidDataException("run_private_file_invalid");
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        var length = stream.Length;
        if (length is < 1 || length > limit)
        {
            throw new InvalidDataException("run_private_file_size_invalid");
        }

        var bytes = new byte[(int)length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
        {
            throw new InvalidDataException("run_private_file_changed");
        }

        return bytes;
    }

    internal static void WritePrivateNew(string path, ReadOnlySpan<byte> bytes, Action<SafeFileHandle>? captureCreatedFile = null)
    {
        var options = new FileStreamOptions
        {
            Access = captureCreatedFile is null ? FileAccess.Write : FileAccess.ReadWrite,
            Mode = FileMode.CreateNew,
            Share = FileShare.None,
            Options = FileOptions.WriteThrough,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using var stream = new FileStream(path, options);
        captureCreatedFile?.Invoke(stream.SafeFileHandle);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }
    internal static void CommitPrivateReplace(string temp, string path, string directory, string errorSubject = "run_private")
    {
        if (OperatingSystem.IsWindows())
        {
            if (!MoveFileEx(temp, path, 1 | 8)) // replace existing, write through
            {
                throw new IOException(errorSubject + "_commit_failed:" + Marshal.GetLastPInvokeError());
            }

            return;
        }

        File.Move(temp, path, overwrite: true);
        if (OperatingSystem.IsLinux())
        {
            int fileDescriptor = OpenDirectory(directory, 0x10000 | 0x20000 | 0x80000); // directory, nofollow, cloexec
            if (fileDescriptor < 0)
            {
                throw new IOException(errorSubject + "_directory_open_failed:" + Marshal.GetLastPInvokeError());
            }

            using var descriptor = new SafeFileHandle(new IntPtr(fileDescriptor), ownsHandle: true);
            if (Sync(descriptor) != 0)
            {
                throw new IOException(errorSubject + "_directory_sync_failed:" + Marshal.GetLastPInvokeError());
            }
        }
    }

    [LibraryImport("kernel32", EntryPoint = "MoveFileExW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool MoveFileEx(string from, string to, uint flags);

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenDirectory(string path, int flags);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int Sync(SafeFileHandle descriptor);

}
