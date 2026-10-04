// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.MemoryMappedFiles;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.ContentSandbox.Broker.Native;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.LocalRpc;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ContentSandbox.Broker.Linux;

/// <summary>
/// The Linux launch profile, parent side. The parent creates every resource before the child exists, as close-on-exec descriptors, and
/// hands the child exactly the closed inventory at fixed numbers through a spawn plan (standard input carries the launch frame, standard output and
/// error a diagnostic stream, 3 and 4 the two private streams, 5 the read-only input, 6 to 8 the slots); every other descriptor of the parent is
/// closed by the exec. The helper then applies Landlock, seccomp, no_new_privs and its limits to itself and checks them before it serves a call
/// (the profile is the helper's, because only the helper can restrict its own threads). This launcher has not been run on Linux by the task that
/// wrote it: it is compiled in hosted CI and its pure parts are tested offline.
/// </summary>
[SupportedOSPlatform("linux")]
[SuppressMessage("Reliability", "CA2000", Justification = "Every descriptor, stream and mapping is owned by the provisioned helper or closed on the failure paths.")]
internal sealed class LinuxHelperLauncher : IContentSandboxProcessLauncher
{
    private const int DiagnosticBytes = 4096;
    private const int FirstSafeDescriptor = 64;

    public ContentSandboxProfileKind Profile => ContentSandboxProfileKind.LinuxLandlockSeccomp;

    public async ValueTask<IProvisionedHelper> StartAsync(HelperStartRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!OperatingSystem.IsLinux())
        {
            throw new ContentSandboxLaunchException("security.isolation_unavailable", "This launch profile runs only on Linux.");
        }

        using var pinned = OpenAndVerifyHelper(request);
        var helper = new LinuxProvisionedHelper();
        try
        {
            await helper.StartAsync(request, cancellationToken).ConfigureAwait(false);
            return helper;
        }
        catch
        {
            await helper.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static FileStream OpenAndVerifyHelper(HelperStartRequest request)
    {
        FileStream file;
        try
        {
            file = new FileStream(request.HelperPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new ContentSandboxLaunchException("resource.unavailable", "The helper executable cannot be opened.", exception);
        }

        var digest = SHA256.HashData(file);
        if (!CryptographicOperations.FixedTimeEquals(digest, request.HelperSha256.Span))
        {
            file.Dispose();
            throw new ContentSandboxLaunchException("resource.integrity_failed", "The helper executable is not the pinned build.");
        }

        return file;
    }

    private sealed class LinuxProvisionedHelper : IProvisionedHelper
    {
        private readonly TaskCompletionSource<int> _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly List<MappedSlot> _slots = [];
        private readonly byte[] _tail = new byte[DiagnosticBytes];
        private readonly object _tailGate = new();
        private readonly object _spawnGate = new();
        private int _tailLength;
        private int _processId;
        private NetworkStream? _control;
        private NetworkStream? _service;
        private NetworkStream? _diagnostics;
        private Task _diagnosticReader = Task.CompletedTask;
        private int _disposed;

        public LocalRpcProcessIdentity Identity { get; private set; }

        public Stream ControlStream => _control ?? throw new InvalidOperationException("The helper is not started.");

        public Stream ServiceStream => _service ?? throw new InvalidOperationException("The helper is not started.");

        public IReadOnlyList<ILocalRpcBufferMapping> SlotMappings => _slots;

        public Task<int> Exited => _exited.Task;

        public string DiagnosticTail
        {
            get
            {
                lock (_tailGate)
                {
                    return Encoding.UTF8.GetString(_tail, 0, _tailLength);
                }
            }
        }

        internal async Task StartAsync(HelperStartRequest request, CancellationToken cancellationToken)
        {
            var owned = new List<int>();
            NetworkStream? frameStream = null;
            try
            {
                var control = Pair(owned);
                var service = Pair(owned);
                var frame = Pair(owned);
                var diagnostics = Pair(owned);
                _control = Stream(control.Parent);
                _service = Stream(service.Parent);
                _diagnostics = Stream(diagnostics.Parent);
                frameStream = Stream(frame.Parent);

                var childFds = new Dictionary<int, int>
                {
                    [0] = Raise(frame.Child, owned),
                    [1] = Raise(diagnostics.Child, owned),
                    [2] = Raise(diagnostics.Child, owned),
                    [3] = Raise(control.Child, owned),
                    [4] = Raise(service.Child, owned),
                };
                var inputFd = CreateMemory(request.Input.Length, owned, out var inputStream);
                using (inputStream)
                {
                    await inputStream.WriteAsync(request.Input, cancellationToken).ConfigureAwait(false);
                    await inputStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                    using var readOnly = File.OpenHandle("/proc/self/fd/" + inputFd.ToString(CultureInfo.InvariantCulture), FileMode.Open, FileAccess.Read);
                    childFds[5] = Raise((int)readOnly.DangerousGetHandle(), owned);
                }

                for (var index = 0; index < request.SlotCapacities.Count; index++)
                {
                    var capacity = request.SlotCapacities[index];
                    var slotFd = CreateMemory(capacity, owned, out var slotStream);
                    var file = MemoryMappedFile.CreateFromFile(slotStream, null, capacity, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, leaveOpen: false);
                    _slots.Add(new MappedSlot(file, capacity));
                    childFds[6 + index] = Raise(slotFd, owned);
                }

                var entries = LinuxLaunchPlan.TargetPlan(request.SlotCapacities.Count).Select(item => new ContentSandboxHandleEntry(item.Role, (ulong)item.Target)).ToList();
                var processId = Spawn(request, childFds);
                _processId = processId;
                foreach (var fd in childFds.Values)
                {
                    _ = LinuxNative.Close(fd);
                    _ = owned.Remove(fd);
                }

                using var process = Process.GetProcessById(processId);
                Identity = LocalRpcProcessIdentity.FromProcess(process);
                request.OnProcessCreated(Identity);
                _ = Task.Factory.StartNew(WaitForExit, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                _diagnosticReader = ReadDiagnosticsAsync();
                var bytes = request.EncodeFrame(entries);
                try
                {
                    await frameStream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                    await frameStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or UnauthorizedAccessException or ArgumentException or SocketException)
            {
                Terminate();
                throw new ContentSandboxLaunchException("resource.unavailable", "The restricted helper could not be started.", exception);
            }
            finally
            {
                if (frameStream is not null)
                {
                    await frameStream.DisposeAsync().ConfigureAwait(false);
                }

                foreach (var fd in owned)
                {
                    _ = LinuxNative.Close(fd);
                }
            }
        }

        public void Terminate()
        {
            var processId = Volatile.Read(ref _processId);
            if (processId > 0)
            {
                _ = LinuxNative.Kill(processId, LinuxNative.SigKill);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Terminate();
            if (Volatile.Read(ref _processId) > 0)
            {
                try
                {
                    _ = await _exited.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    // The tree is gone or unreachable.
                }
            }

            await _diagnosticReader.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            await DisposeStreamAsync(_control).ConfigureAwait(false);
            await DisposeStreamAsync(_service).ConfigureAwait(false);
            await DisposeStreamAsync(_diagnostics).ConfigureAwait(false);
            foreach (var slot in _slots)
            {
                slot.Dispose();
            }
        }

        private static async ValueTask DisposeStreamAsync(Stream? stream)
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }

        private static NetworkStream Stream(int descriptor) =>
            new(new Socket(new SafeSocketHandle((nint)descriptor, ownsHandle: true)), ownsSocket: true);

        private static unsafe (int Parent, int Child) Pair(List<int> owned)
        {
            var descriptors = stackalloc int[2];
            if (LinuxNative.SocketPair(LinuxNative.AfUnix, LinuxNative.SockStream | LinuxNative.SockCloseOnExec, 0, descriptors) != 0)
            {
                throw new IOException("A socket pair could not be created.", Marshal.GetLastPInvokeError());
            }

            // The parent end is owned by its stream from here on; only the child end stays in the owned list until the spawn.
            owned.Add(descriptors[1]);
            return (descriptors[0], descriptors[1]);
        }

        /// <summary>Duplicates a descriptor to a number above the child targets, so a plan that maps it can never map a descriptor onto itself.</summary>
        private static int Raise(int descriptor, List<int> owned)
        {
            var moved = LinuxNative.Fcntl(descriptor, LinuxNative.FDupFdCloseOnExec, FirstSafeDescriptor);
            if (moved < 0)
            {
                throw new IOException("A descriptor could not be duplicated.", Marshal.GetLastPInvokeError());
            }

            owned.Add(moved);
            return moved;
        }

        private static int CreateMemory(long length, List<int> owned, out FileStream stream)
        {
            var descriptor = LinuxNative.MemfdCreate("arcforges-content", LinuxNative.MemfdCloseOnExec);
            if (descriptor < 0)
            {
                throw new IOException("A memory-backed file could not be created.", Marshal.GetLastPInvokeError());
            }

            _ = owned;
            stream = new FileStream(new SafeFileHandle(descriptor, ownsHandle: true), FileAccess.ReadWrite, 1, false);
            stream.SetLength(length);
            return descriptor;
        }

        private unsafe int Spawn(HelperStartRequest request, Dictionary<int, int> plan)
        {
            var actions = (nint)NativeMemory.AllocZeroed(512);
            var strings = new List<nint>();
            try
            {
                if (LinuxNative.SpawnFileActionsInit(actions) != 0)
                {
                    throw new IOException("The spawn plan could not be created.");
                }

                foreach (var (target, source) in plan.OrderBy(pair => pair.Key))
                {
                    if (LinuxNative.SpawnFileActionsAddDup2(actions, source, target) != 0)
                    {
                        throw new IOException("A descriptor could not be placed in the spawn plan.");
                    }
                }

                var path = Utf8(request.HelperPath, strings);
                var arguments = (nint*)NativeMemory.AllocZeroed((nuint)(2 * sizeof(nint)));
                arguments[0] = path;
                var variables = LinuxLaunchPlan.Environment(request.Limits);
                var environment = (nint*)NativeMemory.AllocZeroed((nuint)((variables.Count + 1) * sizeof(nint)));
                for (var index = 0; index < variables.Count; index++)
                {
                    environment[index] = Utf8(variables[index], strings);
                }

                int result;
                int processId;
                lock (_spawnGate)
                {
                    result = LinuxNative.Spawn(out processId, path, actions, 0, (nint)arguments, (nint)environment);
                }

                NativeMemory.Free(arguments);
                NativeMemory.Free(environment);
                if (result != 0)
                {
                    throw new IOException("The helper could not be spawned (error " + result.ToString(CultureInfo.InvariantCulture) + ").");
                }

                return processId;
            }
            finally
            {
                _ = LinuxNative.SpawnFileActionsDestroy(actions);
                NativeMemory.Free((void*)actions);
                foreach (var text in strings)
                {
                    Marshal.FreeCoTaskMem(text);
                }
            }
        }

        private static nint Utf8(string value, List<nint> owned)
        {
            var text = Marshal.StringToCoTaskMemUTF8(value);
            owned.Add(text);
            return text;
        }

        private void WaitForExit()
        {
            var code = -1;
            if (LinuxNative.WaitPid(_processId, out var status, 0) == _processId)
            {
                code = (status & 0x7F) == 0 ? (status >> 8) & 0xFF : 128 + (status & 0x7F);
            }

            _ = _exited.TrySetResult(code);
        }

        private async Task ReadDiagnosticsAsync()
        {
            var stream = _diagnostics ?? throw new InvalidOperationException("The diagnostic stream is not open.");
            var buffer = new byte[1024];
            try
            {
                int read;
                while ((read = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
                {
                    lock (_tailGate)
                    {
                        var keep = Math.Min(_tailLength, DiagnosticBytes - read);
                        Buffer.BlockCopy(_tail, _tailLength - keep, _tail, 0, keep);
                        var copy = Math.Min(read, DiagnosticBytes);
                        Buffer.BlockCopy(buffer, read - copy, _tail, keep, copy);
                        _tailLength = keep + copy;
                    }
                }
            }
            catch (IOException)
            {
                // The other end closed with the process.
            }
        }
    }
}
