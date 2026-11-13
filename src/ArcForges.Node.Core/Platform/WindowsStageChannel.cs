// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

[SupportedOSPlatform("windows")]
internal static partial class WindowsStageChannel
{
    internal static async Task SendAsync(Stream stream, byte kind, ReadOnlyMemory<byte> payload, CancellationToken token)
    {
        if (payload.Length > 65_536) throw new InvalidDataException("The stage message is oversized.");
        var header = new byte[5];
        header[0] = kind;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(1), payload.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(payload, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }

    internal static async Task<(byte Kind, byte[] Payload)> ReadAsync(Stream stream, CancellationToken token)
    {
        var header = new byte[5];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(1));
        if (length is < 0 or > 65_536) throw new InvalidDataException("The stage message is oversized.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, token).ConfigureAwait(false);
        return (header[0], payload);
    }

    internal static byte[] Encode(Action<BinaryWriter> write)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        write(writer);
        writer.Flush();
        return stream.ToArray();
    }

    internal static BinaryReader Reader(byte[] payload) => new(new MemoryStream(payload, writable: false), Encoding.UTF8);
    internal static void RequireEnd(BinaryReader reader)
    {
        if (reader.BaseStream.Position != reader.BaseStream.Length) throw new InvalidDataException("The stage message has trailing bytes.");
    }

    internal static CancellationTokenSource Budget(long deadline, long expiryMicroseconds, CancellationToken token)
    {
        var monotonic = (double)(deadline - Stopwatch.GetTimestamp()) / Stopwatch.Frequency * 1000;
        var real = (expiryMicroseconds - (DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / 10) / 1000d;
        var remaining = Math.Min(monotonic, real);
        if (remaining <= 0 || remaining > 10_000) throw new WorkspacePathException("file_guard_expired");
        var result = CancellationTokenSource.CreateLinkedTokenSource(token);
        result.CancelAfter(TimeSpan.FromMilliseconds(remaining));
        return result;
    }

    internal static SafeFileHandle DuplicateFrom(SafeProcessHandle source, long raw)
    {
        if (raw <= 0 || !DuplicateHandle(source, checked((nint)raw), GetCurrentProcess(), out var copy, 0, false, 2))
            throw Failure();
        return new SafeFileHandle(copy, ownsHandle: true);
    }

    internal static SafeProcessHandle OpenTransferParent(int expectedPid)
    {
        if (NtQueryInformationProcess(GetCurrentProcess(), 0, out var information,
                checked((uint)Marshal.SizeOf<ProcessBasicInformation>()), out _) < 0 ||
            information.ParentId != expectedPid)
            throw Failure();
        var parent = OpenProcess(0x00101040u, false, checked((uint)expectedPid));
        if (parent.IsInvalid) { parent.Dispose(); throw Failure(); }
        try
        {
            RequireSameExecutable(parent);
            return parent;
        }
        catch { parent.Dispose(); throw; }
    }

    internal static unsafe void RequireSameExecutable(SafeProcessHandle process)
    {
        var expected = Environment.ProcessPath ?? throw new IOException("The Host image is unavailable.");
        var buffer = new char[32768];
        var size = checked((uint)buffer.Length);
        fixed (char* native = buffer)
        {
            if (!QueryFullProcessImageName(process, 0, native, ref size) ||
                !string.Equals(new string(buffer, 0, checked((int)size)), expected, StringComparison.OrdinalIgnoreCase))
                throw Failure();
        }
    }

    internal static void RequireClient(NamedPipeServerStream pipe, WindowsOwnedStageProcess process)
    {
        process.RequireLive();
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid) || pid != process.ProcessId) throw Failure();
        RequireSameExecutable(process.Handle);
    }

    internal static void RequireServer(NamedPipeClientStream pipe, SafeProcessHandle parent, int expectedPid, long creation)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid) || pid != expectedPid ||
            WindowsOwnedStageProcess.CreationTimeOf(parent) != creation ||
            WindowsOwnedStageProcess.ObserveHandle(parent) != WindowsStageProcessObservation.Running)
            throw Failure();
        RequireSameExecutable(parent);
    }

    private static IOException Failure() => new("The owned Windows stage channel is unavailable.", new Win32Exception(Marshal.GetLastPInvokeError()));

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        internal nint Reserved1;
        internal nint Peb;
        internal nint Reserved2;
        internal nint Reserved3;
        internal nint ProcessId;
        internal nint ParentId;
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();
    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(nint process, uint informationClass,
        out ProcessBasicInformation information, uint size, out uint returnedSize);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DuplicateHandle(SafeProcessHandle source, nint handle, nint target, out nint copy,
        uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(SafeProcessHandle process, uint flags,
        char* path, ref uint size);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsStageJob : IDisposable
{
    private readonly SafeFileHandle _handle;

    internal WindowsStageJob()
    {
        _handle = CreateJobObject(0, 0);
        if (_handle.IsInvalid) { _handle.Dispose(); throw new IOException("The stage job is unavailable."); }
        var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE, no breakaway.
        if (!SetInformationJobObject(_handle, 9, ref limits, checked((uint)Marshal.SizeOf<ExtendedLimits>())))
        {
            _handle.Dispose();
            throw new IOException("The stage job lifetime could not be installed.");
        }
    }

    internal void Assign(WindowsOwnedStageProcess process)
    {
        process.RequireLive();
        if (!AssignProcessToJobObject(_handle, process.Handle) ||
            !IsProcessInJob(process.Handle, _handle, out var member) || !member)
            throw new IOException("The owned stage process did not enter its lifetime job.");
    }

    public void Dispose() => _handle.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        internal long ProcessTime;
        internal long JobTime;
        internal uint Flags;
        internal nuint MinimumWorkingSet;
        internal nuint MaximumWorkingSet;
        internal uint ActiveProcesses;
        internal nuint Affinity;
        internal uint Priority;
        internal uint Scheduling;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        internal ulong ReadOperations;
        internal ulong WriteOperations;
        internal ulong OtherOperations;
        internal ulong ReadBytes;
        internal ulong WriteBytes;
        internal ulong OtherBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        internal BasicLimits Basic;
        internal IoCounters Io;
        internal nuint ProcessMemory;
        internal nuint JobMemory;
        internal nuint PeakProcessMemory;
        internal nuint PeakJobMemory;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true)]
    private static partial SafeFileHandle CreateJobObject(nint attributes, nint name);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformationJobObject(SafeFileHandle job, int informationClass, ref ExtendedLimits information, uint size);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(SafeFileHandle job, SafeProcessHandle process);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsProcessInJob(SafeProcessHandle process, SafeFileHandle job, [MarshalAs(UnmanagedType.Bool)] out bool member);
}
