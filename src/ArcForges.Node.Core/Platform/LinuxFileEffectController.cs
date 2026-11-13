// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Owns exactly one private child. The creator thread stays alive until that child actually exits, so PDEATHSIG
/// cannot be silently lost. The controller never signals an unsealed pidfd or any PID/process group.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed partial class LinuxFileEffectController
{
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _finish = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _gate = new();
    private readonly bool _testMode;
    private Process? _child;
    private Socket? _socket;
    private LinuxOwnedPidfd? _pidfd;
    private LinuxOwnedPeer? _peer;
    private Action? _afterExit;
    private bool _sealed;
    private bool _shutdown;
    private int _possibleEffect;

    private LinuxFileEffectController(bool testMode) => _testMode = testMode;

    /// <summary>The self-hosted worker is available only from the real Host entry assembly.</summary>
    internal static bool IsHostProcess() =>
        string.Equals(Assembly.GetEntryAssembly()?.GetName().Name, "arcforges", StringComparison.Ordinal);

    internal static async Task<LinuxFileEffectController> StartAsync(bool testMode, CancellationToken cancellationToken)
    {
        if (!IsHostProcess()) throw new InvalidOperationException("The Host worker entry point is unavailable.");
        var owner = new LinuxFileEffectController(testMode);
        var creator = new Thread(owner.RunCreator) { IsBackground = true, Name = "file-effect-worker-owner" };
        creator.Start();
        try
        {
            await owner._ready.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return owner;
        }
        catch
        {
            owner.Shutdown(afterExit: null);
            throw;
        }
    }

    /// <summary>May be used only in the FULL writer transaction that binds the original operation and policy.</summary>
    internal LinuxOwnedPidfd SealedWorker => _pidfd ?? throw new InvalidOperationException("The worker is unavailable.");

    internal LinuxFileMutationResult Execute(LinuxFileEffectBinding binding, WorkspacePath root,
        WorkspaceWriteGuard target, WorkspaceAnonymousStage original, WorkspaceAnonymousStage intended,
        Action beforeEffect, Action checkNames, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(intended);
        ArgumentNullException.ThrowIfNull(beforeEffect);
        ArgumentNullException.ThrowIfNull(checkNames);
        var socket = _socket ?? throw new InvalidOperationException("The worker channel is unavailable.");
        var peer = _peer ?? throw new InvalidOperationException("The worker peer is unavailable.");
        using var cancellation = cancellationToken.Register(static state => ((LinuxFileEffectController)state!).RequestStop(), this);
        using var stream = new NetworkStream(socket, ownsSocket: false);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        cancellationToken.ThrowIfCancellationRequested();
        checkNames();
        writer.Write((byte)'W');
        binding.Write(writer);
        WorkspaceWriteGuard.TransferLinuxToOwnedPeer(peer, root.RootHandle, target, original.GuardForLinuxHandoff,
            intended.GuardForLinuxHandoff);
        var adopted = ReadWorkerMessage(reader);
        if (adopted != (byte)'A') throw new IOException("The worker did not adopt its guarded objects.");
        target.CheckIntact();
        original.CheckIntact();
        intended.CheckIntact();
        // Closing only our copies preserves the child's exact shared open descriptions and their leases.
        target.CloseLocalAfterLinuxHandoff();
        original.GuardForLinuxHandoff.CloseLocalAfterLinuxHandoff();
        intended.GuardForLinuxHandoff.CloseLocalAfterLinuxHandoff();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var message = ReadWorkerMessage(reader);
            if (message == (byte)'P')
            {
                beforeEffect();
                checkNames();
                cancellationToken.ThrowIfCancellationRequested();
                // Even a failed or interrupted send may have delivered this permission to the child.
                Volatile.Write(ref _possibleEffect, 1);
                writer.Write((byte)'G');
                writer.Flush();
                continue;
            }
            if (message != (byte)'D') throw new IOException("The worker returned an invalid result.");
            var size = reader.ReadInt64();
            var hash = reader.ReadBytes(32);
            if (size != binding.IntendedSize || hash.Length != 32 ||
                !CryptographicOperations.FixedTimeEquals(hash, binding.IntendedSha256))
                throw new InvalidDataException("The worker result differs from its prepared intent.");
            using var received = peer.ReceiveReturnedDescriptorOnce();
            var identity = WorkspacePath.Identity(received);
            if (!CryptographicOperations.FixedTimeEquals(binding.TargetIdentity,
                ArcForges.Node.Core.Files.RegisteredWorkspaces.RootIdentity.Encode(identity, directory: false).Bytes))
                throw new WorkspacePathException("file_identity_changed");
            var owned = new Microsoft.Win32.SafeHandles.SafeFileHandle(received.DangerousGetHandle(), ownsHandle: true);
            received.SetHandleAsInvalid();
            WorkspaceWriteGuard? returned = null;
            try
            {
                try { returned = WorkspaceWriteGuard.AdoptLinuxReturnedFile(owned, peer, identity, binding.Deadline); }
                catch { owned.Dispose(); throw; }
                using (var actual = returned.ReadForMutation(cancellationToken))
                {
                    if (actual.Bytes.Length != size || !CryptographicOperations.FixedTimeEquals(hash, actual.Sha256.Span))
                        throw new WorkspacePathException("file_identity_changed");
                }
                checkNames();
                cancellationToken.ThrowIfCancellationRequested();
                writer.Write((byte)'S');
                writer.Flush();
                var child = _child ?? throw new InvalidOperationException("The worker is unavailable.");
                if (!child.WaitForExit(5000) || child.ExitCode != 0)
                    throw new IOException("The worker did not finish cleanly.");
                checkNames();
                returned.CheckIntact();
                var result = new LinuxFileMutationResult(new WorkspaceGuardedMutationResult(size, hash), returned);
                returned = null;
                return result;
            }
            finally { returned?.Dispose(); }
        }
    }

    private static byte ReadWorkerMessage(BinaryReader reader)
    {
        var message = reader.ReadByte();
        if (message == (byte)'F')
        {
            throw reader.ReadByte() switch
            {
                1 => new WorkspacePathException("hash_mismatch"),
                2 => new WorkspacePathException("file_identity_changed"),
                _ => new WorkspacePreservationUnavailableException(),
            };
        }
        return message;
    }

    internal bool PossibleEffect => Volatile.Read(ref _possibleEffect) != 0;

    internal void Stop() => RequestStop();

    internal bool WaitForActualExit(int milliseconds)
    {
        var child = _child;
        return child is not null && child.WaitForExit(milliseconds);
    }

    /// <summary>
    /// Stops this owned child and invokes cleanup only after it actually exits. A blocked kernel operation may outlive
    /// the caller's deadline: until exit the caller's held stage quota and durable journal fence stay in force.
    /// </summary>
    internal void Shutdown(Action? afterExit)
    {
        lock (_gate)
        {
            if (_shutdown) throw new InvalidOperationException("The worker has already been shut down.");
            _shutdown = true;
            _afterExit = afterExit;
            _finish.TrySetResult();
        }
    }

    private void RequestStop()
    {
        try
        {
            lock (_gate)
            {
                if (_sealed) _pidfd?.StopSealedChild();
                try { _socket?.Shutdown(SocketShutdown.Both); }
                catch (SocketException) { }
            }
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // No result or early release follows from a failed stop attempt; creator waits for actual child exit.
        }
    }

    private void RunCreator()
    {
        try
        {
            StartOnCreatorThread();
            _ready.TrySetResult();
            _finish.Task.GetAwaiter().GetResult();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            _ready.TrySetException(exception);
        }
        finally
        {
            RequestStop();
            _socket?.Dispose();
            var ended = true;
            if (_child is not null)
            {
                try
                {
                    _child.StandardInput.Close();
                    // Keep this thread, its child identity and caller's stage reservation until the actual wait completes.
                    _child.WaitForExit();
                }
                catch (Exception exception) when (exception is IOException or InvalidOperationException)
                {
                    // If actual exit cannot be observed, do not run afterExit or release the held resources.
                    ended = false;
                }
            }
            if (ended)
            {
                _pidfd?.Dispose();
                _child?.Dispose();
                try { _afterExit?.Invoke(); }
                catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { }
            }
        }
    }

    private void StartOnCreatorThread()
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("The Host executable is unavailable.");
        var name = "arcforges-effect-" + Guid.NewGuid().ToString("N");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint("\0" + name));
        listener.Listen(1);
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        // A framework-dependent Host may be launched through dotnet; the child must enter the same Host assembly.
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.Ordinal))
        {
            var assembly = Path.Combine(AppContext.BaseDirectory, "arcforges.dll");
            if (!File.Exists(assembly)) throw new InvalidOperationException("The Host assembly is unavailable.");
            start.ArgumentList.Add(assembly);
        }
        start.ArgumentList.Add("node");
        start.ArgumentList.Add("file-effect-worker");
        if (_testMode) start.ArgumentList.Add("--test-mode");
        _child = Process.Start(start) ?? throw new InvalidOperationException("The owned worker could not start.");
        var bytes = Encoding.ASCII.GetBytes(name);
        _child.StandardInput.BaseStream.WriteByte(checked((byte)bytes.Length));
        _child.StandardInput.BaseStream.Write(bytes);
        _child.StandardInput.BaseStream.Flush();
        if (!listener.Poll(5_000_000, SelectMode.SelectRead)) throw new TimeoutException("The owned worker did not connect.");
        _socket = listener.Accept();
        if (!LinuxExecutableIdentity.MatchesCurrent(_child.Id))
            throw new InvalidOperationException("The worker executable changed.");
        _pidfd = LinuxOwnedPidfd.OpenPending(_socket, _child);
        using var challenge = new LinuxPeerChallenge();
        _peer = _pidfd.AuthenticateAndSeal(_socket, challenge);
        lock (_gate) _sealed = true;
        _socket.SendTimeout = 5000;
        _socket.ReceiveTimeout = 5000;
    }
}
