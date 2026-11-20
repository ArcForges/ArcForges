// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using ArcForges.Client;
using ArcForges.Node.Platform.Windows;
using ArcForges.Security.Secrets;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Runs the exact product CLI in a Windows pseudoconsole owned by this test.</summary>
[SupportedOSPlatform("windows")]
internal sealed partial class TerminalCliNativeWindows : IAsyncDisposable
{
    private const int PipeCapacity = 64 * 1024;
    private const uint WaitTimeout = 258;
    private const uint StartfUseStdHandles = 0x100;
    private const uint CreateSuspendedWithUnicodeEnvironmentAndAttributes = 0x4 | 0x400 | 0x80000;
    private const nuint PseudoconsoleAttribute = 0x20016;
    private static readonly TimeSpan CleanupBound = TimeSpan.FromSeconds(10);
    private readonly HostedProcess _process;
    private readonly ModeKeeper? _keeper;
    private readonly Lock _consoleGate = new();
    private nint _console;
    private int _modeSequence;

    private TerminalCliNativeWindows(nint console, HostedProcess process, ModeKeeper? keeper, Stream input, Stream output)
    {
        _console = console;
        _process = process;
        _keeper = keeper;
        Input = input;
        Output = output;
    }

    public Stream Input { get; }
    public Stream Output { get; }
    public int ProcessId => _process.Id;
    public DateTimeOffset ProcessStartTimeUtc => _process.Created;
    public ConsoleModes InitialModes => RequireModeKeeper().Initial;

    public static TerminalCliNativeWindows Start(string executable, IReadOnlyList<string> args, string cwd,
        IReadOnlyDictionary<string, string?> environment, ushort rows, ushort columns) =>
        StartCoreAsync(executable, args, cwd, environment, rows, columns, null, CancellationToken.None).GetAwaiter().GetResult();

    public static Task<TerminalCliNativeWindows> StartWithModeKeeperAsync(string executable, IReadOnlyList<string> args, string cwd,
        IReadOnlyDictionary<string, string?> environment, ushort rows, ushort columns, string keeperExecutable,
        string privateModeDirectory, CancellationToken cancellationToken)
    {
        if (!Path.IsPathFullyQualified(keeperExecutable) || !File.Exists(keeperExecutable) || !Path.IsPathFullyQualified(privateModeDirectory))
        {
            throw new ArgumentException("The native mode keeper and its private fixture directory must be absolute.");
        }

        Directory.CreateDirectory(privateModeDirectory);
        if (Directory.EnumerateFileSystemEntries(privateModeDirectory).Any())
        {
            throw new ArgumentException("The private mode fixture directory must be empty.", nameof(privateModeDirectory));
        }

        return StartCoreAsync(executable, args, cwd, environment, rows, columns,
            new ModeKeeperOptions(keeperExecutable, privateModeDirectory), cancellationToken);
    }

    private static async Task<TerminalCliNativeWindows> StartCoreAsync(string executable, IReadOnlyList<string> args, string cwd,
        IReadOnlyDictionary<string, string?> environment, ushort rows, ushort columns, ModeKeeperOptions? keeperOptions,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(environment);
        if (!Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(cwd))
        {
            throw new ArgumentException("The CLI image and working directory must be absolute.");
        }

        if (executable.Contains('\0') || cwd.Contains('\0') || args.Any(argument => argument.Contains('\0')))
        {
            throw new ArgumentException("The CLI image, working directory and arguments must be NUL-free.");
        }

        if (!args.TakeWhile(argument => argument != "--").Contains(NodeLocations.TestModeOption, StringComparer.Ordinal)
            || !environment.TryGetValue(NodeLocations.ConfigDirectoryVariable, out var config) || !Path.IsPathFullyQualified(config ?? "")
            || !environment.TryGetValue(NodeLocations.EndpointVariable, out var endpoint) || string.IsNullOrWhiteSpace(endpoint))
        {
            throw new ArgumentException("The terminal fixture requires isolated test mode, configuration and endpoint.");
        }

        var size = Dimensions(rows, columns);
        var variables = BuildEnvironment(environment);
        NamedPipeServerStream? input = null;
        NamedPipeServerStream? output = null;
        nint console = 0;
        HostedProcess? process = null;
        HostedProcess? keeperProcess = null;
        try
        {
            using var consoleInput = CreatePipe(PipeDirection.Out, out input);
            using var consoleOutput = CreatePipe(PipeDirection.In, out output);
            Marshal.ThrowExceptionForHR(CreatePseudoConsole(size, consoleInput.SafePipeHandle, consoleOutput.SafePipeHandle, 0, out console));
            if (console == 0)
            {
                throw new InvalidOperationException("ConPTY returned no pseudoconsole handle.");
            }

            ModeKeeper? keeper = null;
            if (keeperOptions is { } mode)
            {
                keeperProcess = StartAttached(mode.Executable, ["terminal", "observe-console-modes", mode.Directory],
                    variables, mode.Directory, console);
                var initial = await ReadSnapshotAsync(keeperProcess, mode.Directory, 0, cancellationToken).ConfigureAwait(false);
                if (initial.Rows != rows || initial.Columns != columns)
                {
                    throw new InvalidOperationException("The passive observer did not see the fixture's initial console geometry.");
                }

                keeper = new ModeKeeper(keeperProcess, mode.Directory, initial);
            }

            cancellationToken.ThrowIfCancellationRequested();
            process = StartAttached(executable, args, variables, cwd, console);
            return new TerminalCliNativeWindows(console, process, keeper, input, output);
        }
        catch (Exception launchFailure)
        {
            try
            {
                await ReleaseAsync(process, keeperProcess, input, output, console).ConfigureAwait(false);
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException("The ConPTY launch and its cleanup both failed.", launchFailure, cleanupFailure);
            }

            throw;
        }
    }

    public void Resize(ushort rows, ushort columns)
    {
        lock (_consoleGate)
        {
            ObjectDisposedException.ThrowIf(_console == 0, this);
            Marshal.ThrowExceptionForHR(ResizePseudoConsole(_console, Dimensions(rows, columns)));
        }
    }

    public Task<int> WaitForExitAsync(CancellationToken cancellationToken) => WaitForProcessAsync(_process.Handle, cancellationToken);

    public async Task<int> RunContenderAsync(string executable, IReadOnlyList<string> args, string cwd,
        IReadOnlyDictionary<string, string?> environment, CancellationToken cancellationToken)
    {
        if (!Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(cwd) || !File.Exists(executable)
            || !args.TakeWhile(argument => argument != "--").Contains(NodeLocations.TestModeOption, StringComparer.Ordinal)
            || !environment.TryGetValue(NodeLocations.ConfigDirectoryVariable, out var config) || !Path.IsPathFullyQualified(config ?? "")
            || !environment.TryGetValue(NodeLocations.EndpointVariable, out var endpoint) || string.IsNullOrWhiteSpace(endpoint))
        {
            throw new ArgumentException("The shared console contender requires the exact installed CLI and isolated configuration.");
        }

        HostedProcess contender;
        lock (_consoleGate)
        {
            ObjectDisposedException.ThrowIf(_console == 0, this);
            cancellationToken.ThrowIfCancellationRequested();
            Assert.True(IsRunning(_process.Handle), "The original CLI must still own this same console.");
            contender = StartAttached(executable, args, BuildEnvironment(environment), cwd, _console);
        }

        try
        {
            return await WaitForProcessAsync(contender.Handle, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await CloseProcessAsync(contender).ConfigureAwait(false);
        }
    }

    public Task<ConsoleModes> ReadModesAsync(CancellationToken cancellationToken)
    {
        var keeper = RequireModeKeeper();
        int sequence;
        lock (_consoleGate)
        {
            ObjectDisposedException.ThrowIf(_console == 0, this);
            cancellationToken.ThrowIfCancellationRequested();
            sequence = checked(_modeSequence + 1);
            string request = Path.Combine(keeper.Directory, "request-" + sequence.ToString(CultureInfo.InvariantCulture));
            using var marker = new FileStream(request, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
            _modeSequence = sequence;
        }

        return ReadSnapshotAsync(keeper.Process, keeper.Directory, sequence, cancellationToken);
    }

    public async Task AssertModeRestoredAsync(CancellationToken cancellationToken)
    {
        var initial = InitialModes;
        Assert.False(IsRunning(_process.Handle), "Read the restored console modes only after the exact CLI exits.");
        var restored = await ReadModesAsync(cancellationToken).ConfigureAwait(false);
        Assert.Equal(initial.Input, restored.Input);
        Assert.Equal(initial.Output, restored.Output);
    }

    private ModeKeeper RequireModeKeeper() => _keeper
        ?? throw new InvalidOperationException("This ConPTY fixture was launched without the passive mode keeper.");

    private static async Task<ConsoleModes> ReadSnapshotAsync(HostedProcess keeper, string directory, int sequence,
        CancellationToken cancellationToken)
    {
        string snapshot = Path.Combine(directory, "snapshot-" + sequence.ToString(CultureInfo.InvariantCulture) + ".txt");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(CleanupBound);
        while (true)
        {
            deadline.Token.ThrowIfCancellationRequested();
            if (!IsRunning(keeper.Handle))
            {
                int exitCode = await WaitForProcessAsync(keeper.Handle, deadline.Token).ConfigureAwait(false);
                throw new InvalidOperationException($"The passive console probe exited before observation {sequence}, status {exitCode}.");
            }

            if (File.Exists(snapshot))
            {
                string report = await File.ReadAllTextAsync(snapshot, deadline.Token).ConfigureAwait(false);
                var fields = report.Trim().Split(' ');
                if (fields is ["v1", var pidText, var inputText, var outputText, var rowsText, var columnsText]
                    && Parse(pidText, out uint pid) && pid == (uint)keeper.Id
                    && Parse(inputText, out uint input) && Parse(outputText, out uint output)
                    && Parse(rowsText, out uint rows) && rows is > 0 and <= (uint)short.MaxValue
                    && Parse(columnsText, out uint columns) && columns is > 0 and <= (uint)short.MaxValue)
                {
                    return new ConsoleModes(input, output, (ushort)rows, (ushort)columns);
                }

                throw new InvalidDataException("The passive console probe returned a malformed or mismatched native observation.");
            }

            await Task.Delay(20, deadline.Token).ConfigureAwait(false);
        }

        static bool Parse(string text, out uint value) => uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    public async ValueTask DisposeAsync()
    {
        nint console;
        lock (_consoleGate)
        {
            console = _console;
            _console = 0;
        }

        if (console == 0)
        {
            return;
        }

        await ReleaseAsync(_process, _keeper?.Process, Input, Output, console).ConfigureAwait(false);
    }

    private static async Task ReleaseAsync(HostedProcess? process, HostedProcess? keeper, Stream? input, Stream? output, nint console)
    {
        try
        {
            try
            {
                await CloseProcessAsync(process).ConfigureAwait(false);
            }
            finally
            {
                await CloseProcessAsync(keeper).ConfigureAwait(false);
            }
        }
        finally
        {
            input?.Dispose();
            output?.Dispose(); // The output handle must be closed before ClosePseudoConsole if no reader is active.
            if (console != 0)
            {
                await CloseConsoleAsync(console).ConfigureAwait(false);
            }
        }
    }

    private static async Task CloseProcessAsync(HostedProcess? process)
    {
        if (process is null)
        {
            return;
        }

        using var handle = process.Handle;
        EndProcess(handle);
        using var deadline = new CancellationTokenSource(CleanupBound);
        _ = await WaitForProcessAsync(handle, deadline.Token).ConfigureAwait(false);
    }

    private static Task CloseConsoleAsync(nint console) =>
        Task.Run(() => ClosePseudoConsole(console)).WaitAsync(CleanupBound);

    private static async Task<int> WaitForProcessAsync(SafeProcessHandle process, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        while (IsRunning(process))
        {
            await Task.Delay(20, cancellationToken).ConfigureAwait(false);
        }

        if (!GetExitCodeProcess(process, out uint code))
        {
            throw LastError("Read the CLI process exit code");
        }

        return unchecked((int)code);
    }

    private static void EndProcess(SafeProcessHandle process)
    {
        if (IsRunning(process) && !TerminateProcess(process, 1))
        {
            var failure = LastError("Terminate the unclosed fixture CLI process");
            if (IsRunning(process))
            {
                throw failure;
            }
        }
    }

    private static bool IsRunning(SafeProcessHandle process) => WaitForSingleObject(process, 0) switch
    {
        0 => false,
        WaitTimeout => true,
        _ => throw LastError("Wait on the exact CLI process handle"),
    };

    private static NamedPipeClientStream CreatePipe(PipeDirection direction, out NamedPipeServerStream server)
    {
        string name = "arcforges-cli-conpty-" + Guid.NewGuid().ToString("N");
        server = new NamedPipeServerStream(name, direction, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, PipeCapacity, PipeCapacity);
        NamedPipeClientStream? peer = null;
        try
        {
            using var deadline = new CancellationTokenSource(CleanupBound);
            peer = new NamedPipeClientStream(".", name, direction == PipeDirection.In ? PipeDirection.Out : PipeDirection.In,
                PipeOptions.None, TokenImpersonationLevel.Anonymous);
            var connected = server.WaitForConnectionAsync(deadline.Token);
            peer.Connect((int)CleanupBound.TotalMilliseconds);
            connected.GetAwaiter().GetResult();
            return peer;
        }
        catch
        {
            peer?.Dispose();
            server.Dispose();
            throw;
        }
    }

    private static char[] BuildEnvironment(IReadOnlyDictionary<string, string?> changes)
    {
        var variables = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry variable in Environment.GetEnvironmentVariables())
        {
            if (variable.Key is string name && variable.Value is string value && !name.StartsWith('='))
            {
                variables[name] = value;
            }
        }

        foreach (var (name, value) in changes)
        {
            if (name.Length == 0 || name.Contains('=') || name.Contains('\0') || value?.Contains('\0') == true)
            {
                throw new ArgumentException("Invalid variable in the terminal fixture environment.", nameof(changes));
            }

            if (value is null)
            {
                variables.Remove(name);
            }
            else
            {
                variables[name] = value;
            }
        }

        variables.Remove(OsSecretStoreGuard.OptInVariable);

        var block = new StringBuilder();
        foreach (var (name, value) in variables)
        {
            block.Append(name).Append('=').Append(value).Append('\0');
        }

        if (block.Length == 0)
        {
            block.Append('\0');
        }

        return block.Append('\0').ToString().ToCharArray();
    }

    private static HostedProcess StartAttached(string executable, IReadOnlyList<string> args, char[] environment,
        string cwd, nint console)
    {
        var command = (WindowsCommandLine.Build([executable, .. args]) + '\0').ToCharArray();
        var created = StartSuspended(executable, command, environment, cwd, console);
        var process = new SafeProcessHandle(created.Process, ownsHandle: true);
        using var thread = new SafeWaitHandle(created.Thread, ownsHandle: true);
        try
        {
            if (!GetProcessTimes(process, out var startedAt, out _, out _, out _))
            {
                throw LastError("Read the hosted process creation identity");
            }

            var hosted = new HostedProcess(process, checked((int)created.ProcessId), DateTimeOffset.FromFileTime(startedAt).ToUniversalTime());
            if (ResumeThread(thread) == uint.MaxValue)
            {
                throw LastError("Resume the exact hosted process in ConPTY");
            }

            return hosted;
        }
        catch (Exception launchFailure)
        {
            using (process)
            {
                try
                {
                    EndProcess(process);
                    if (WaitForSingleObject(process, (uint)CleanupBound.TotalMilliseconds) != 0)
                    {
                        throw new InvalidOperationException("The failed ConPTY launch did not release its exact process.");
                    }
                }
                catch (Exception cleanupFailure)
                {
                    throw new AggregateException("The child launch and its cleanup both failed.", launchFailure, cleanupFailure);
                }
            }

            throw;
        }
    }

    private static unsafe ProcessInformation StartSuspended(string executable, char[] command, char[] environment,
        string cwd, nint console)
    {
        nuint bytes = 0;
        _ = InitializeProcThreadAttributeList(0, 1, 0, ref bytes);
        if (bytes == 0)
        {
            throw LastError("Read ConPTY process attribute capacity");
        }

        nint attributes = Marshal.AllocHGlobal(checked((nint)bytes));
        bool initialized = false;
        try
        {
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes))
            {
                throw LastError("Initialize ConPTY process attributes");
            }

            initialized = true;
            if (!UpdateProcThreadAttribute(attributes, 0, PseudoconsoleAttribute, (void*)console, (nuint)sizeof(nint), 0, 0))
            {
                throw LastError("Bind the actual pseudoconsole to the CLI process");
            }

            // Pass explicit null standard handles so this test runner's redirects are not adopted.
            var startup = new StartupInfoEx { Info = new() { Size = sizeof(StartupInfoEx), Flags = StartfUseStdHandles }, Attributes = attributes };
            fixed (char* commandLine = command)
            fixed (char* environmentBlock = environment)
            {
                if (!CreateProcess(executable, commandLine, 0, 0, false, CreateSuspendedWithUnicodeEnvironmentAndAttributes,
                    environmentBlock, cwd, ref startup, out var result))
                {
                    throw LastError("Create the exact CLI process in ConPTY");
                }

                return result;
            }
        }
        finally
        {
            if (initialized)
            {
                DeleteProcThreadAttributeList(attributes);
            }

            Marshal.FreeHGlobal(attributes);
        }
    }

    private static Coordinate Dimensions(ushort rows, ushort columns)
    {
        ArgumentOutOfRangeException.ThrowIfZero(rows);
        ArgumentOutOfRangeException.ThrowIfZero(columns);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(rows, (ushort)short.MaxValue);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(columns, (ushort)short.MaxValue);
        return new((short)columns, (short)rows);
    }

    private static Win32Exception LastError(string operation) => new(Marshal.GetLastPInvokeError(), operation);

    public readonly record struct ConsoleModes(uint Input, uint Output, ushort Rows, ushort Columns);

    private sealed record HostedProcess(SafeProcessHandle Handle, int Id, DateTimeOffset Created);
    private sealed record ModeKeeperOptions(string Executable, string Directory);
    private sealed record ModeKeeper(HostedProcess Process, string Directory, ConsoleModes Initial);

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct Coordinate(short Columns, short Rows);

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Size;
        public nint Reserved, Desktop, Title;
        public uint X, Y, Width, Height, Columns, Rows, FillAttribute, Flags;
        public ushort ShowWindow, ReservedSize;
        public nint ReservedBytes, StandardInput, StandardOutput, StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo Info;
        public nint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint Process, Thread;
        public uint ProcessId, ThreadId;
    }

    [LibraryImport("kernel32.dll")]
    private static partial int CreatePseudoConsole(Coordinate size, SafePipeHandle input, SafePipeHandle output, uint flags, out nint console);

    [LibraryImport("kernel32.dll")]
    private static partial int ResizePseudoConsole(nint console, Coordinate size);

    [LibraryImport("kernel32.dll")]
    private static partial void ClosePseudoConsole(nint console);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InitializeProcThreadAttributeList(nint list, int count, uint flags, ref nuint bytes);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, void* value, nuint bytes, nint previous, nint returned);

    [LibraryImport("kernel32.dll")]
    private static partial void DeleteProcThreadAttributeList(nint list);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CreateProcess(string application, char* command, nint processAttributes, nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, char* environment, string directory, ref StartupInfoEx startup,
        out ProcessInformation information);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint ResumeThread(SafeWaitHandle thread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(SafeProcessHandle process, out uint code);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(SafeProcessHandle process, uint exitCode);
}
