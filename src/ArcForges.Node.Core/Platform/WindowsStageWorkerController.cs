// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>Owns one actual Windows producer process, its lifetime job and authenticated private pipe.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsStageWorkerController : IDisposable
{
    private readonly WindowsStageJob _job = new();
    private readonly NamedPipeServerStream _pipe;
    private readonly string _pipeName;
    private Process? _process;
    private WindowsOwnedStageProcess? _owned;
    private int _shutdown;
    private int _used;
    private int _possibleEffect;

    private WindowsStageWorkerController()
    {
        _pipeName = "arcforges-stage-" + Guid.NewGuid().ToString("N");
        try
        {
            _pipe = new NamedPipeServerStream(_pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        }
        catch { _job.Dispose(); throw; }
    }

    internal static bool IsHostProcess() =>
        string.Equals(Assembly.GetEntryAssembly()?.GetName().Name, "arcforges", StringComparison.Ordinal);

    internal static async Task<WindowsStageWorkerController> StartAsync(bool testMode, CancellationToken cancellationToken)
    {
        if (!IsHostProcess()) throw new InvalidOperationException("The Host worker entry point is unavailable.");
        var result = new WindowsStageWorkerController();
        try
        {
            await result.StartChildAsync(testMode, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch { result.Shutdown(afterExit: null); throw; }
    }

    internal WindowsOwnedStageProcess SealedWorker => _owned ?? throw new InvalidOperationException("The stage worker is unavailable.");
    internal bool PossibleEffect => Volatile.Read(ref _possibleEffect) != 0;

    internal async Task<WorkspaceEmptyNamedStage> ExecuteNamedAsync(WindowsPrivateStageBinding binding,
        WorkspacePath workspaceRoot, WorkspacePath stageDirectory, ReadOnlyMemory<byte> body,
        Func<SafeFileHandle, Action, Task> commitEmptyIdentity, Func<Task> beforeEachEffect, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(commitEmptyIdentity);
        ArgumentNullException.ThrowIfNull(beforeEachEffect);
        if (Interlocked.Exchange(ref _used, 1) != 0) throw new InvalidOperationException("The private producer is one-use.");
        binding.Validate();
        if (binding.WorkerIdentity != SealedWorker.SealedIdentity() || body.Length != binding.Size ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(body.Span), binding.Sha256))
            throw new InvalidDataException("The private producer differs from its FULL binding.");
        WorkspacePath.RequireWindowsStageDirectory(workspaceRoot.RootHandle, binding.RootIdentity);
        WorkspacePath.RequireWindowsStageDirectory(stageDirectory.RootHandle, binding.ParentIdentity);
        using var budget = WindowsStageChannel.Budget(binding.Deadline, binding.ExpiryMicroseconds, cancellationToken);
        var token = budget.Token;
        using var stop = token.Register(static state => ((WindowsStageWorkerController)state!).Stop(), this);
        WindowsPrivateStageTransaction? transaction = null;
        SafeFileHandle? file = null;
        try
        {
            await beforeEachEffect().ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            WindowsStageChannel.RequireClient(_pipe, SealedWorker);
            var initialize = WindowsStageChannel.Encode(writer =>
            {
                binding.Write(writer);
                writer.Write(workspaceRoot.RootHandle.DangerousGetHandle().ToInt64());
                writer.Write(stageDirectory.RootHandle.DangerousGetHandle().ToInt64());
            });
            Volatile.Write(ref _possibleEffect, 1);
            await WindowsStageChannel.SendAsync(_pipe, (byte)'I', initialize, token).ConfigureAwait(false);
            var empty = await WindowsStageChannel.ReadAsync(_pipe, token).ConfigureAwait(false);
            if (empty.Kind != (byte)'E' || empty.Payload.Length != 69)
                throw new InvalidDataException("The worker did not return an exact empty stage.");
            using (var reader = WindowsStageChannel.Reader(empty.Payload))
            {
                var transactionId = new Guid(reader.ReadBytes(16));
                var timeout = reader.ReadUInt32();
                var transactionRaw = reader.ReadInt64();
                var fileRaw = reader.ReadInt64();
                var reported = reader.ReadBytes(33);
                WindowsStageChannel.RequireEnd(reader);
                WindowsStageChannel.RequireClient(_pipe, SealedWorker);
                var duplicate = WindowsStageChannel.DuplicateFrom(SealedWorker.Handle, transactionRaw);
                transaction = WindowsPrivateStageTransaction.AdoptDuplicate(duplicate, transactionId,
                    binding.Deadline, binding.ExpiryMicroseconds, timeout);
                file = WindowsStageChannel.DuplicateFrom(SealedWorker.Handle, fileRaw);
                CheckEmpty();
                var observed = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file), directory: false);
                if (!CryptographicOperations.FixedTimeEquals(observed.Bytes, reported))
                    throw new WorkspacePathException("file_identity_changed");
            }
            var recorded = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file), directory: false);
            await commitEmptyIdentity(file, CheckEmpty).ConfigureAwait(false);
            CheckEmpty();
            await WindowsStageChannel.SendAsync(_pipe, (byte)'G', ReadOnlyMemory<byte>.Empty, token).ConfigureAwait(false);
            for (var offset = 0; offset < body.Length;)
            {
                await beforeEachEffect().ConfigureAwait(false);
                Check();
                var count = Math.Min(65_536, body.Length - offset);
                await WindowsStageChannel.SendAsync(_pipe, (byte)'B', body.Slice(offset, count), token).ConfigureAwait(false);
                var accepted = await WindowsStageChannel.ReadAsync(_pipe, token).ConfigureAwait(false);
                if (accepted.Kind != (byte)'A' || accepted.Payload.Length != 0)
                    throw new InvalidDataException("The worker did not accept its bounded content chunk.");
                offset += count;
            }
            foreach (var phase in new byte[] { (byte)'F', (byte)'C' })
            {
                var request = await WindowsStageChannel.ReadAsync(_pipe, token).ConfigureAwait(false);
                if (request.Kind != phase || request.Payload.Length != 0)
                    throw new InvalidDataException("The worker requested an invalid stage phase.");
                await beforeEachEffect().ConfigureAwait(false);
                Check();
                await WindowsStageChannel.SendAsync(_pipe, (byte)'G', ReadOnlyMemory<byte>.Empty, token).ConfigureAwait(false);
            }
            var complete = await WindowsStageChannel.ReadAsync(_pipe, token).ConfigureAwait(false);
            if (complete.Kind != (byte)'D' || !CryptographicOperations.FixedTimeEquals(complete.Payload, recorded.Bytes))
                throw new InvalidDataException("The worker did not commit the recorded stage.");
            transaction.ConfirmCommitted();
            file.Dispose();
            file = null;
            await WindowsStageChannel.SendAsync(_pipe, (byte)'S', ReadOnlyMemory<byte>.Empty, token).ConfigureAwait(false);
            var process = _process ?? throw new InvalidOperationException("The stage worker is unavailable.");
            await process.WaitForExitAsync(token).ConfigureAwait(false);
            if (!SealedWorker.WaitForActualExit(WindowsStageChannel.Remaining(binding.Deadline, binding.ExpiryMicroseconds)) || process.ExitCode != 0)
                throw new IOException("The private producer did not finish cleanly.");
            token.ThrowIfCancellationRequested();
            WorkspacePath.RequireWindowsStageDirectory(workspaceRoot.RootHandle, binding.RootIdentity);
            WorkspacePath.RequireWindowsStageDirectory(stageDirectory.RootHandle, binding.ParentIdentity);
            var guard = stageDirectory.ReopenWindowsPrivateNamedStage(recorded, binding.Name, binding.Size, binding.Sha256, token);
            return new WorkspaceEmptyNamedStage(binding.Name, recorded, guard,
                NamedStageDurabilityEvidence.WindowsNtfsWriteThroughAndFileFlush);

            void Check()
            {
                token.ThrowIfCancellationRequested();
                WindowsStageChannel.RequireClient(_pipe, SealedWorker);
                WorkspacePath.RequireWindowsStageDirectory(workspaceRoot.RootHandle, binding.RootIdentity);
                WorkspacePath.CheckWindowsTransactionalStage(file!, stageDirectory.RootHandle, binding, transaction!);
            }

            void CheckEmpty()
            {
                Check();
                if (RandomAccess.GetLength(file!) != 0) throw new WorkspacePathException("file_identity_changed");
            }
        }
        catch { Stop(); throw; }
        finally { file?.Dispose(); transaction?.Dispose(); }
    }

    internal void Stop()
    {
        try { _owned?.TerminateOwnedProcess(); }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or ObjectDisposedException) { }
    }

    internal bool WaitForActualExit(int milliseconds) =>
        _owned is not null && _owned.WaitForActualExit(TimeSpan.FromMilliseconds(milliseconds));

    /// <summary>No cleanup callback runs until the exact child actually exits; uncertain exit retains its resources.</summary>
    internal void Shutdown(Action? afterExit) => BeginShutdown(afterExit, requireFirst: true);

    public void Dispose() => BeginShutdown(afterExit: null, requireFirst: false);

    private void BeginShutdown(Action? afterExit, bool requireFirst)
    {
        if (Interlocked.Exchange(ref _shutdown, 1) != 0)
        {
            if (requireFirst) throw new InvalidOperationException("The private stage controller has already been shut down.");
            return;
        }
        var reaper = new Thread(() =>
        {
            Stop();
            _job.Dispose(); // Kernel termination also covers parent death; it is not itself an exit receipt.
            var ended = _process is null;
            try
            {
                if (_process is not null)
                {
                    _process.StandardInput.Close();
                    _process.WaitForExit();
                    ended = _owned is null || _owned.WaitForActualExit();
                }
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException) { }
            if (!ended) return;
            _pipe.Dispose();
            if (_owned is not null) _owned.Dispose();
            else _process?.Dispose();
            try { afterExit?.Invoke(); }
            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { }
        }) { IsBackground = true, Name = "windows-stage-worker-reaper" };
        reaper.Start();
    }

    private async Task StartChildAsync(bool testMode, CancellationToken cancellationToken)
    {
        using var startup = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        startup.CancelAfter(TimeSpan.FromSeconds(5));
        var token = startup.Token;
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("The Host executable is unavailable.");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var assembly = Path.Combine(AppContext.BaseDirectory, "arcforges.dll");
            if (!File.Exists(assembly)) throw new InvalidOperationException("The Host assembly is unavailable.");
            start.ArgumentList.Add(assembly);
        }
        start.ArgumentList.Add("node");
        start.ArgumentList.Add("private-stage-worker");
        if (testMode) start.ArgumentList.Add("--test-mode");
        _process = Process.Start(start) ?? throw new IOException("The private stage worker could not start.");
        _owned = new WindowsOwnedStageProcess(_process);
        _job.Assign(_owned);
        using var self = Process.GetCurrentProcess();
        var challenge = RandomNumberGenerator.GetBytes(32);
        try
        {
            var hello = WindowsStageChannel.Encode(writer =>
            {
                writer.Write(Environment.ProcessId);
                writer.Write(WindowsOwnedStageProcess.CreationTimeOf(self.SafeHandle));
                var name = Encoding.ASCII.GetBytes(_pipeName);
                writer.Write(checked((byte)name.Length));
                writer.Write(name);
                writer.Write(challenge);
            });
            await WindowsStageChannel.SendAsync(_process.StandardInput.BaseStream, (byte)'H', hello, token).ConfigureAwait(false);
            await _pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
            WindowsStageChannel.RequireClient(_pipe, _owned);
            var response = await WindowsStageChannel.ReadAsync(_pipe, token).ConfigureAwait(false);
            if (response.Kind != (byte)'A' || !CryptographicOperations.FixedTimeEquals(challenge, response.Payload))
                throw new IOException("The actual private worker did not authenticate its channel.");
        }
        finally { CryptographicOperations.ZeroMemory(challenge); }
    }
}
