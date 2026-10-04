// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.MemoryMappedFiles;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.ContentSandbox.Broker.Native;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.LocalRpc;
using Microsoft.Win32.SafeHandles;
using static ArcForges.ContentSandbox.Broker.Native.WindowsNative;

namespace ArcForges.ContentSandbox.Broker.Windows;

/// <summary>
/// The Windows restricted launch profile of annex 24: the helper is created suspended in an AppContainer that has no capability (no
/// network, no file or registry grant of its own), at a low integrity level, with a handle list that names exactly the OS resources of its
/// closed inventory, a minimal environment and child processes denied by the Job Object process limit. A non-breakaway Job Object with kill-on-close, a process limit
/// of one and a memory limit is attached before the first instruction runs, so the parent's death ends the helper. The token is read back and
/// checked before the thread resumes: a child that is not in the expected AppContainer is never run.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsHelperLauncher : IContentSandboxProcessLauncher
{
    private const int PipeConnectMilliseconds = 10_000;
    private const int DiagnosticBytes = 4096;

    // DEP, heap-termination, bottom-up and high-entropy ASLR, strict handle checks, no extension points,
    // no remote or low-label image loads. Dynamic-code prohibition is left off: the Native AOT runtime and native parser libraries are
    // not proven to run under it, and nothing here claims it.
    private const ulong MitigationPolicy =
        0x0000000000000001UL
        | 0x0000000000001000UL
        | 0x0000000000010000UL
        | 0x0000000000100000UL
        | 0x0000000001000000UL
        | 0x0000000100000000UL
        | 0x0010000000000000UL
        | 0x0100000000000000UL;

    private readonly string _containerPrefix;
    private readonly string _slotDirectory;

    internal WindowsHelperLauncher(string containerPrefix, string? slotDirectory)
    {
        _containerPrefix = containerPrefix;
        _slotDirectory = slotDirectory ?? AppContainerSlots.DefaultLockDirectory();
    }

    public ContentSandboxProfileKind Profile => ContentSandboxProfileKind.WindowsAppContainerJob;

    [SuppressMessage("Reliability", "CA2000", Justification = "The helper owns the container lease and is disposed on every failure path; on success it is returned to the caller.")]
    public async ValueTask<IProvisionedHelper> StartAsync(HelperStartRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!OperatingSystem.IsWindows())
        {
            throw new ContentSandboxLaunchException("security.isolation_unavailable", "This launch profile runs only on Windows.");
        }

        using var pinned = OpenAndVerifyHelper(request);
        var lease = AppContainerSlots.Acquire(_containerPrefix, _slotDirectory);
        var helper = new WindowsProvisionedHelper(lease);
        try
        {
            await helper.StartAsync(request, pinned, cancellationToken).ConfigureAwait(false);
            return helper;
        }
        catch
        {
            await helper.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Opens the helper for reading with writers refused and checks its SHA-256 against the pinned digest of the installed inventory. The
    /// stream stays open across the process creation, so the bytes that were checked are the bytes that run.
    /// </summary>
    private static FileStream OpenAndVerifyHelper(HelperStartRequest request)
    {
        FileStream file;
        try
        {
            // Neither writing nor deleting/renaming is shared while the handle is held, so the file cannot be replaced between the hash and the start.
            file = new FileStream(request.HelperPath, FileMode.Open, FileAccess.Read, FileShare.Read);
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

    [SupportedOSPlatform("windows")]
    private sealed class WindowsProvisionedHelper(AppContainerLease container) : IProvisionedHelper
    {
        private readonly TaskCompletionSource<int> _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly List<MappedSlot> _slots = [];
        private readonly byte[] _tail = new byte[DiagnosticBytes];
        private readonly object _tailGate = new();
        private int _tailLength;
        private AnonymousPipeServerStream? _diagnostics;
        private NamedPipeServerStream? _control;
        private NamedPipeServerStream? _service;
        private long _job;
        private Process? _process;
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

        [SuppressMessage("Reliability", "CA2000", Justification = "Every created stream and handle is owned by this object or disposed in the same method.")]
        [SuppressMessage("Maintainability", "CA1506", Justification = "One method owns the ordered, fail-closed creation of the restricted process.")]
        [SuppressMessage("Design", "CA1031", Justification = "Any failure while creating the process ends the launch with a registered reason code.")]
        internal async Task StartAsync(HelperStartRequest request, FileStream pinnedHelper, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(pinnedHelper);
            using var stdin = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable, 64 * 1024);
            var diagnostics = _diagnostics = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable, 64 * 1024);
            SafeFileHandle? controlClient = null;
            SafeFileHandle? serviceClient = null;
            MemoryMappedFile? input = null;
            nint inputReadOnly = 0;
            ProcessInformation information = default;
            try
            {
                (_control, controlClient) = await CreatePipeAsync(cancellationToken).ConfigureAwait(false);
                (_service, serviceClient) = await CreatePipeAsync(cancellationToken).ConfigureAwait(false);
                foreach (var capacity in request.SlotCapacities)
                {
                    var section = MemoryMappedFile.CreateNew(null, capacity, MemoryMappedFileAccess.ReadWrite, MemoryMappedFileOptions.None, HandleInheritability.Inheritable);
                    _slots.Add(new MappedSlot(section, capacity));
                }

                input = MemoryMappedFile.CreateNew(null, request.Input.Length, MemoryMappedFileAccess.ReadWrite, MemoryMappedFileOptions.None, HandleInheritability.None);
                using (var writer = input.CreateViewStream(0, request.Input.Length, MemoryMappedFileAccess.Write))
                {
                    await writer.WriteAsync(request.Input, cancellationToken).ConfigureAwait(false);
                }

                // A read-only duplicate: the helper can map the input for reading and can never map it writable.
                if (!DuplicateHandle(-1, input.SafeMemoryMappedFileHandle.DangerousGetHandle(), -1, out inputReadOnly, SectionMapRead, true, 0))
                {
                    throw Fail("The read-only input handle could not be made.");
                }

                var inherited = new List<nint>
                {
                    stdin.ClientSafePipeHandle.DangerousGetHandle(),
                    diagnostics.ClientSafePipeHandle.DangerousGetHandle(),
                    controlClient.DangerousGetHandle(),
                    serviceClient.DangerousGetHandle(),
                    inputReadOnly,
                };
                inherited.AddRange(_slots.Select(slot => slot.SectionHandle));
                information = CreateRestrictedProcess(
                    request.HelperPath,
                    container.Sid,
                    [.. inherited],
                    stdin.ClientSafePipeHandle.DangerousGetHandle(),
                    diagnostics.ClientSafePipeHandle.DangerousGetHandle());

                stdin.DisposeLocalCopyOfClientHandle();
                diagnostics.DisposeLocalCopyOfClientHandle();
                var entries = new List<ContentSandboxHandleEntry>
                {
                    new(ContentSandboxHandleRole.Control, (ulong)controlClient.DangerousGetHandle()),
                    new(ContentSandboxHandleRole.Service, (ulong)serviceClient.DangerousGetHandle()),
                    new(ContentSandboxHandleRole.Input, (ulong)inputReadOnly),
                };
                for (var index = 0; index < _slots.Count; index++)
                {
                    entries.Add(new ContentSandboxHandleEntry((ContentSandboxHandleRole)((int)ContentSandboxHandleRole.Slot0 + index), (ulong)_slots[index].SectionHandle));
                }

                VerifyAppContainer(information.Process, container.Sid);
                _job = CreateJob(request.Limits);
                if (!AssignProcessToJobObject((nint)_job, information.Process))
                {
                    throw Fail("The helper could not be placed in its Job Object.");
                }

                if (!IsProcessInJob(information.Process, (nint)_job, out var inJob) || !inJob)
                {
                    throw Fail("The helper is not in its Job Object.");
                }

                _process = Process.GetProcessById((int)information.ProcessId);
                Identity = LocalRpcProcessIdentity.FromProcess(_process);
                _process.EnableRaisingEvents = true;
                _process.Exited += OnExited;
                request.OnProcessCreated(Identity);
                _diagnosticReader = ReadDiagnosticsAsync();
                if (ResumeThread(information.Thread) == uint.MaxValue)
                {
                    throw Fail("The helper could not be resumed.");
                }

                if (_process.HasExited)
                {
                    OnExited(this, EventArgs.Empty);
                }

                var frame = request.EncodeFrame(entries);
                try
                {
                    await stdin.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
                    await stdin.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(frame);
                }
            }
            catch (Exception exception) when (exception is not ContentSandboxLaunchException and not OperationCanceledException)
            {
                var note = await DescribeEndAsync().ConfigureAwait(false);
                KillCreated(information.Process);
                Terminate();
                throw new ContentSandboxLaunchException("resource.unavailable", "The restricted helper could not be started" + note + ".", exception);
            }
            catch
            {
                KillCreated(information.Process);
                Terminate();
                throw;
            }
            finally
            {
                controlClient?.Dispose();
                serviceClient?.Dispose();
                input?.Dispose();
                if (inputReadOnly != 0)
                {
                    _ = CloseHandle(inputReadOnly);
                }

                if (information.Thread != 0)
                {
                    _ = CloseHandle(information.Thread);
                }

                if (information.Process != 0)
                {
                    _ = CloseHandle(information.Process);
                }

            }
        }

        /// <summary>What the helper did before it stopped answering: its exit code and the last bytes it wrote. Parent-side diagnostics only.</summary>
        private async Task<string> DescribeEndAsync()
        {
            if (_process is null)
            {
                return string.Empty;
            }

            _ = await Task.WhenAny(_exited.Task, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            return _exited.Task.IsCompletedSuccessfully ? " (exit " + await _exited.Task.ConfigureAwait(false) + "; output: " + HelperText.Sanitise(DiagnosticTail) + ")" : string.Empty;
        }

        private static async ValueTask DisposeStreamAsync(Stream? stream)
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }

        private static void KillCreated(nint process)
        {
            if (process != 0)
            {
                _ = TerminateProcess(process, 1);
            }
        }

        public void Terminate()
        {
            var job = Interlocked.Read(ref _job);
            if (job != 0)
            {
                _ = TerminateJobObject((nint)job, 1);
            }
            else
            {
                try
                {
                    _process?.Kill(entireProcessTree: true);
                }
                catch (Exception exception) when (exception is InvalidOperationException or Win32Exception or NotSupportedException)
                {
                    // The process already ended.
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Terminate();
            if (_process is not null)
            {
                try
                {
                    await _exited.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    // The tree is gone or unreachable; the identity below is released either way.
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

            if (_job != 0)
            {
                _ = CloseHandle((nint)_job);
                _job = 0;
            }

            _process?.Dispose();
            container.Dispose();
        }

        private void OnExited(object? sender, EventArgs args)
        {
            try
            {
                _ = _exited.TrySetResult(_process?.ExitCode ?? -1);
            }
            catch (InvalidOperationException)
            {
                _ = _exited.TrySetResult(-1);
            }
        }

        private async Task ReadDiagnosticsAsync()
        {
            var stream = _diagnostics ?? throw new InvalidOperationException("The diagnostic pipe is not open.");
            var buffer = new byte[1024];
            try
            {
                int read;
                while ((read = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
                {
                    lock (_tailGate)
                    {
                        var keep = Math.Min(_tailLength, DiagnosticBytes - read);
                        if (keep < 0)
                        {
                            keep = 0;
                        }

                        Buffer.BlockCopy(_tail, _tailLength - keep, _tail, 0, keep);
                        var copy = Math.Min(read, DiagnosticBytes);
                        Buffer.BlockCopy(buffer, read - copy, _tail, keep, copy);
                        _tailLength = keep + copy;
                    }
                }
            }
            catch (IOException)
            {
                // The write end closed with the process.
            }
        }

        /// <summary>
        /// Creates one duplex pipe: the parent's asynchronous server end, and the child's end opened overlapped, inheritable and never bound to a
        /// completion port here. A handle that the parent bound to its own thread pool could not be bound again by the child.
        /// </summary>
        private static async Task<(NamedPipeServerStream Server, SafeFileHandle Client)> CreatePipeAsync(CancellationToken cancellationToken)
        {
            var name = "ArcForges.ContentSandbox." + Guid.NewGuid().ToString("N");
            var server = new NamedPipeServerStream(
                name,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
            try
            {
                var accepted = server.WaitForConnectionAsync(cancellationToken);
                var attributes = new SecurityAttributes { Length = (uint)Marshal.SizeOf<SecurityAttributes>(), InheritHandle = 1 };
                var raw = CreateFileW(@"\\.\pipe\" + name, GenericReadWrite, 0, ref attributes, OpenExisting, FileFlagOverlapped | SecuritySqosPresent, 0);
                if (raw == -1)
                {
                    throw Fail("The child end of a pipe could not be opened.");
                }

                var client = new SafeFileHandle(raw, ownsHandle: true);
                try
                {
                    await accepted.WaitAsync(TimeSpan.FromMilliseconds(PipeConnectMilliseconds), cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    client.Dispose();
                    throw;
                }

                return (server, client);
            }
            catch
            {
                await server.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        private static unsafe ProcessInformation CreateRestrictedProcess(string helperPath, nint appContainerSid, nint[] inheritedHandles, nint standardInput, nint standardOutput)
        {
            nuint size = 0;
            _ = InitializeProcThreadAttributeList(0, 3, 0, ref size);
            var list = (nint)NativeMemory.Alloc(size);
            var initialized = false;
            try
            {
                if (!InitializeProcThreadAttributeList(list, 3, 0, ref size))
                {
                    throw Fail("The attribute list could not be made.");
                }

                initialized = true;
                var capabilities = new SecurityCapabilities { AppContainerSid = appContainerSid };
                if (!UpdateProcThreadAttribute(list, 0, (nuint)AttributeSecurityCapabilities, (nint)(&capabilities), (nuint)sizeof(SecurityCapabilities), 0, 0))
                {
                    throw Fail("The AppContainer attribute could not be set.");
                }

                fixed (nint* handles = inheritedHandles)
                {
                    if (!UpdateProcThreadAttribute(list, 0, (nuint)AttributeHandleList, (nint)handles, (nuint)(inheritedHandles.Length * sizeof(nint)), 0, 0))
                    {
                        throw Fail("The handle list could not be set.");
                    }

                    var mitigation = MitigationPolicy;
                    if (!UpdateProcThreadAttribute(list, 0, (nuint)AttributeMitigationPolicy, (nint)(&mitigation), sizeof(ulong), 0, 0))
                    {
                        throw Fail("The mitigation policy could not be set.");
                    }

                    var startup = new StartupInfoExW { AttributeList = list };
                    startup.StartupInfo.Cb = (uint)sizeof(StartupInfoExW);
                    startup.StartupInfo.Flags = StartfUseStdHandles;
                    startup.StartupInfo.StdInput = standardInput;
                    startup.StartupInfo.StdOutput = standardOutput;
                    startup.StartupInfo.StdError = standardOutput;
                    var commandLine = ("\"" + helperPath + "\"\0").ToCharArray();
                    var environment = MinimalEnvironment();
                    fixed (char* command = commandLine)
                    fixed (char* block = environment)
                    {
                        if (!CreateProcessW(
                                null,
                                command,
                                0,
                                0,
                                true,
                                ExtendedStartupInfoPresent | CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow,
                                (nint)block,
                                Path.GetDirectoryName(helperPath),
                                ref startup,
                                out var information))
                        {
                            throw Fail("The helper process could not be created.");
                        }

                        return information;
                    }
                }
            }
            finally
            {
                if (initialized)
                {
                    DeleteProcThreadAttributeList(list);
                }

                NativeMemory.Free((void*)list);
            }
        }

        /// <summary>The whole environment of the helper: the system root and nothing else. No profile path, no token cache path, no inherited secret.</summary>
        private static char[] MinimalEnvironment()
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            // AppContainer process creation fails (error 203) unless LOCALAPPDATA is present; the system redirects it for the container.
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return ("SystemRoot=" + windows + "\0windir=" + windows + "\0LOCALAPPDATA=" + local + "\0\0").ToCharArray();
        }

        private static nint CreateJob(ContentSandboxLimits limits)
        {
            var job = CreateJobObjectW(0, 0);
            if (job == 0)
            {
                throw Fail("The Job Object could not be created.");
            }

            try
            {
                var extended = default(JobExtendedLimitInformation);
                extended.BasicLimitInformation.LimitFlags =
                    JobLimitKillOnJobClose | JobLimitActiveProcess | JobLimitProcessMemory | JobLimitJobMemory | JobLimitDieOnUnhandledException;
                extended.BasicLimitInformation.ActiveProcessLimit = 1;
                extended.ProcessMemoryLimit = (nuint)limits.MaxMemoryBytes;
                extended.JobMemoryLimit = (nuint)limits.MaxMemoryBytes;
                unsafe
                {
                    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, (nint)(&extended), (uint)sizeof(JobExtendedLimitInformation)))
                    {
                        throw Fail("The Job Object limits could not be set.");
                    }

                    var ui = new JobBasicUiRestrictions { UiRestrictionsClass = JobUiLimitAll };
                    if (!SetInformationJobObject(job, JobObjectBasicUiRestrictions, (nint)(&ui), (uint)sizeof(JobBasicUiRestrictions)))
                    {
                        throw Fail("The Job Object user-interface restrictions could not be set.");
                    }
                }

                return job;
            }
            catch
            {
                _ = CloseHandle(job);
                throw;
            }
        }

        /// <summary>Reads the token of the suspended child and refuses anything but the expected AppContainer with no capability.</summary>
        [SuppressMessage("Maintainability", "CA1508", Justification = "The token query writes the value through its pointer.")]
        private static unsafe void VerifyAppContainer(nint process, nint expectedSid)
        {
            if (!OpenProcessToken(process, TokenQueryAccess, out var token))
            {
                throw Fail("The token of the helper could not be read.");
            }

            try
            {
                uint isContainer = 0;
                if (!GetTokenInformation(token, TokenIsAppContainer, (nint)(&isContainer), sizeof(uint), out _) || isContainer != 1)
                {
                    throw new ContentSandboxLaunchException("security.isolation_unavailable", "The helper is not running in an AppContainer.");
                }

                _ = GetTokenInformation(token, TokenAppContainerSid, 0, 0, out var needed);
                var buffer = (nint)NativeMemory.Alloc(needed);
                try
                {
                    if (!GetTokenInformation(token, TokenAppContainerSid, buffer, needed, out _)
                        || !EqualSid(*(nint*)buffer, expectedSid))
                    {
                        throw new ContentSandboxLaunchException("security.isolation_unavailable", "The helper runs in another AppContainer than the one leased.");
                    }
                }
                finally
                {
                    NativeMemory.Free((void*)buffer);
                }

                _ = GetTokenInformation(token, TokenCapabilities, 0, 0, out var capabilityBytes);
                var capabilities = (nint)NativeMemory.Alloc(capabilityBytes);
                try
                {
                    if (!GetTokenInformation(token, TokenCapabilities, capabilities, capabilityBytes, out _) || *(uint*)capabilities != 0)
                    {
                        throw new ContentSandboxLaunchException("security.isolation_unavailable", "The helper token carries a capability.");
                    }
                }
                finally
                {
                    NativeMemory.Free((void*)capabilities);
                }
            }
            finally
            {
                _ = CloseHandle(token);
            }
        }

        private static ContentSandboxLaunchException Fail(string message) =>
            new("security.isolation_unavailable", message, new Win32Exception(Marshal.GetLastPInvokeError()));
    }
}
