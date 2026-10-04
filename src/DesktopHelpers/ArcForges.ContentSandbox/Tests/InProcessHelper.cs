// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.LocalRpc;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>
/// One end of a connected in-memory duplex byte stream: a deterministic substitute for an OS stream. It carries real Kestrel HTTP/2 and
/// Grpc.Net.Client framing and proves nothing about a pipe, a socket or a restricted process.
/// </summary>
internal sealed class DuplexStream : Stream
{
    private readonly PipeReader _input;
    private readonly PipeWriter _output;
    private int _disposed;

    private DuplexStream(PipeReader input, PipeWriter output)
    {
        _input = input;
        _output = output;
    }

    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    internal static (DuplexStream Parent, DuplexStream Child) CreatePair()
    {
        var toChild = new Pipe(new PipeOptions(useSynchronizationContext: false));
        var toParent = new Pipe(new PipeOptions(useSynchronizationContext: false));
        return (new DuplexStream(toParent.Reader, toChild.Writer), new DuplexStream(toChild.Reader, toParent.Writer));
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var result = await _input.ReadAsync(cancellationToken).ConfigureAwait(false);
            var sequence = result.Buffer;
            if (!sequence.IsEmpty)
            {
                var count = (int)Math.Min(sequence.Length, buffer.Length);
                sequence.Slice(0, count).CopyTo(buffer.Span);
                _input.AdvanceTo(sequence.GetPosition(count));
                return count;
            }

            _input.AdvanceTo(sequence.End);
            if (result.IsCompleted || result.IsCanceled)
            {
                return 0;
            }
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var result = await _output.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (result.IsCompleted)
        {
            throw new IOException("The in-memory peer closed the stream.");
        }
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _output.Complete();
            _input.CancelPendingRead();
            try
            {
                _input.Complete();
            }
            catch (InvalidOperationException)
            {
                // A read was still unwinding; the cancelled read ends it.
            }
        }

        base.Dispose(disposing);
    }
}

/// <summary>Shared memory of one slot or the input as two views over one array: the parent's read view and the helper's window.</summary>
internal sealed class SharedMemory
{
    internal SharedMemory(int length) => Bytes = new byte[length];

    internal byte[] Bytes { get; }

    internal ParentView Parent() => new(this);

    internal HelperWindow Helper() => new(this);

    /// <summary>The parent's read access: a raw copy that fires a hook first, so a test can rewrite the memory the way a hostile helper would.</summary>
    internal sealed class ParentView(SharedMemory memory) : ILocalRpcBufferMapping
    {
        private int _disposed;

        public long Length => memory.Bytes.Length;

        internal Action<long>? BeforeRead { get; set; }

        internal bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        public int Read(long offset, Span<byte> destination)
        {
            BeforeRead?.Invoke(offset);
            var count = (int)Math.Min(destination.Length, memory.Bytes.Length - offset);
            memory.Bytes.AsSpan((int)offset, count).CopyTo(destination);
            return count;
        }

        public void Dispose() => Interlocked.Exchange(ref _disposed, 1);
    }

    /// <summary>The helper's writable window and, for the input, its read-only view.</summary>
    internal sealed class HelperWindow(SharedMemory memory) : IHelperSlot, ILocalRpcBufferMapping
    {
        public long Capacity => memory.Bytes.Length;

        public long Length => memory.Bytes.Length;

        public Span<byte> GetSpan(long offset, int length) => memory.Bytes.AsSpan((int)offset, length);

        public int Read(long offset, Span<byte> destination)
        {
            var count = (int)Math.Min(destination.Length, memory.Bytes.Length - offset);
            memory.Bytes.AsSpan((int)offset, count).CopyTo(destination);
            return count;
        }

        public void Dispose()
        {
        }
    }
}

/// <summary>What a helper stand-in receives: the decoded frame and its resources, as a real helper would after its profile is in force.</summary>
internal sealed record HelperRun(ContentSandboxLaunchFrame Frame, LocalRpcChildBootstrap Bootstrap, HelperResources Resources, CancellationToken Stop);

/// <summary>
/// TEST ONLY. A launcher that runs the helper host in this process over in-memory streams and arrays. It is a substitute for the
/// restricted process launch: it exercises the launch frame, registration, session, brokered buffers and contract end to end, and it
/// proves no operating-system containment. The opt-in OS tests are the only evidence of that.
/// </summary>
internal sealed class InProcessHelperLauncher(Func<HelperRun, Task<int>> helper) : IContentSandboxProcessLauncher
{
    internal InProcessHelperLauncher(ParserProfiles parsers, TimeProvider? clock = null)
        : this(run => ContentSandboxHost.RunAsync(run.Frame, run.Bootstrap, run.Resources, parsers, clock ?? TimeProvider.System, run.Stop))
    {
    }

    public ContentSandboxProfileKind Profile => ContentSandboxProfileKind.WindowsAppContainerJob;

    internal List<InProcessHelper> Started { get; } = [];

    public ValueTask<IProvisionedHelper> StartAsync(HelperStartRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var (parentControl, childControl) = DuplexStream.CreatePair();
        var (parentService, childService) = DuplexStream.CreatePair();
        var slots = request.SlotCapacities.Select(capacity => new SharedMemory((int)capacity)).ToArray();
        var input = new SharedMemory(request.Input.Length);
        request.Input.CopyTo(input.Bytes);
        var entries = new List<ContentSandboxHandleEntry>
        {
            new(ContentSandboxHandleRole.Control, 1),
            new(ContentSandboxHandleRole.Service, 2),
            new(ContentSandboxHandleRole.Input, 3),
        };
        for (var index = 0; index < slots.Length; index++)
        {
            entries.Add(new ContentSandboxHandleEntry((ContentSandboxHandleRole)((int)ContentSandboxHandleRole.Slot0 + index), (ulong)(4 + index)));
        }

        var encoded = request.EncodeFrame(entries);
        var frame = ContentSandboxLaunchFrame.Decode(encoded.AsSpan(4));
        var bootstrap = LocalRpcChildBootstrap.FromResource(frame.BootstrapResource);
        // A launch binds a child process that is not the parent: a harmless sleeping process stands in for the helper process.
        var sleeper = OperatingSystem.IsWindows()
            ? Process.Start(new ProcessStartInfo("ping", "-n 600 127.0.0.1") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!
            : Process.Start(new ProcessStartInfo("sleep", "600") { UseShellExecute = false })!;
        request.OnProcessCreated(LocalRpcProcessIdentity.FromProcess(sleeper));
        var resources = new HelperResources(childControl, childService, input.Helper(), slots.Select(slot => (IHelperSlot)slot.Helper()).ToArray());
        var stop = new CancellationTokenSource();
        var parentViews = slots.Select(slot => slot.Parent()).ToArray();
        var run = Task.Run(async () =>
        {
            try
            {
                return await helper(new HelperRun(frame, bootstrap, resources, stop.Token)).ConfigureAwait(false);
            }
            finally
            {
                bootstrap.Dispose();
                frame.Dispose();
            }
        });
        var started = new InProcessHelper(parentControl, parentService, parentViews, slots, run, stop, resources, sleeper);
        Started.Add(started);
        return ValueTask.FromResult<IProvisionedHelper>(started);
    }
}

/// <summary>A helper stand-in. Terminating it stops the host and breaks its streams, as ending a process would.</summary>
internal sealed class InProcessHelper(
    DuplexStream control,
    DuplexStream service,
    SharedMemory.ParentView[] slotViews,
    SharedMemory[] slotMemory,
    Task<int> run,
    CancellationTokenSource stop,
    HelperResources resources,
    Process sleeper) : IProvisionedHelper
{
    public LocalRpcProcessIdentity Identity => LocalRpcProcessIdentity.FromProcess(sleeper);

    public Stream ControlStream => control;

    public Stream ServiceStream => service;

    public IReadOnlyList<ILocalRpcBufferMapping> SlotMappings => slotViews;

    public Task<int> Exited { get; } = run;

    public string DiagnosticTail => string.Empty;

    internal SharedMemory.ParentView[] ParentViews => slotViews;

    internal SharedMemory[] Memory => slotMemory;

    public void Terminate()
    {
        try
        {
            stop.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already disposed.
        }

        resources.Control.Dispose();
        resources.Service.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        Terminate();
        try
        {
            _ = await Exited.WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // A parser that ignores its token holds its thread; the in-process stand-in cannot kill it.
        }

        control.Dispose();
        service.Dispose();
        stop.Dispose();
        try
        {
            sleeper.Kill(true);
        }
        catch (InvalidOperationException)
        {
            // Already gone.
        }

        sleeper.Dispose();
    }
}

/// <summary>Builders for the pieces every test needs.</summary>
internal static class Fixtures
{
    internal static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    internal static string NewRoot() => Path.Combine(Path.GetTempPath(), "arcforges-cs-tests-" + Guid.NewGuid().ToString("N")[..12]);

    internal static ContentSandboxLaunchOptions Options(string? parser = null, ContentSandboxLimits? limits = null, long slotBytes = 1024 * 1024, int slots = 3) =>
        new()
        {
            HelperPath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "helper-under-test.exe")),
            HelperSha256 = SHA256.HashData("helper"u8),
            ParserProfile = parser ?? HostileFixture.HostileProfile.ProfileId,
            RuntimeRoot = NewRoot(),
            Limits = limits ?? new ContentSandboxLimits { TimeoutMs = 5000, MaxWidth = 4096, MaxHeight = 4096 },
            SlotCapacityBytes = slotBytes,
            SlotCount = slots,
            LaunchTimeout = Patience,
        };

    internal static ParserProfiles Hostile() => new([new HostileFixture.HostileProfile()]);

    internal static ReadOnlyMemory<byte> Script(params string[] lines) =>
        System.Text.Encoding.UTF8.GetBytes("HOSTILE1\n" + string.Join('\n', lines) + "\n");

    internal static async Task<(ContentSandboxLauncher Launcher, InProcessHelperLauncher Helper, ContentSandboxInvocation Invocation)> LaunchAsync(
        ReadOnlyMemory<byte> input,
        ContentSandboxLaunchOptions? options = null,
        InProcessHelperLauncher? helper = null)
    {
        var stand = helper ?? new InProcessHelperLauncher(Hostile());
        var launcher = new ContentSandboxLauncher(options ?? Options(), profileOverride: null, launcherOverride: stand);
        var result = await launcher.LaunchAsync(input, TestContextToken()).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            await launcher.DisposeAsync().ConfigureAwait(false);
            throw new InvalidOperationException("The launch failed with " + result.Failure!.Code + ": " + result.Detail);
        }

        return (launcher, stand, result.Value!);
    }

    internal static CancellationToken TestContextToken() => Xunit.TestContext.Current.CancellationToken;
}
