// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoveryRequiresFreshTerminalAuthorityWithoutRepeatingProcessedInput()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        await using var installed = await InstalledTerminal.StartAsync();
        var marker = Path.Combine(installed.Working, "recovery-terminal.log");
        byte[] previous = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)));
        byte[] next = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)));
        int delivered = previous.Length + next.Length;
        // One additional byte would finish the fixture. It must remain live until the recovered Node stops it.
        var run = await installed.RunAsync(TerminalMode.Interactive, "terminal", "quiet", marker,
            (delivered + 1).ToString(CultureInfo.InvariantCulture));
        await WaitMarkerAsync(marker, "ready 24 80");
        var originalAcquire = AcquireRequest(run, LeaseMode.Writer);
        var originalWriter = ValueOfAcquire(await AcquireAsync(installed.Runs, originalAcquire));
        var originalInput = Input(run, originalWriter, 1, previous);
        await AcceptInputAsync(installed.Runs, originalInput, (uint)previous.Length);
        await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {previous.Length}"));
        var firstNode = await HandshakeAsync(installed.Node);
        var binding = ReadRecoveryBinding(installed.Fixture.DataRoot, run);
        var supervisor = CaptureRecoveryTerminalSupervisor(installed, binding);

        var continued = await RebindRecoveryTerminalAsync(installed, run, binding, supervisor, firstNode.NodeEpoch, cancellationToken);
        RequireUncertain((await WriteAsync(installed.Runs, originalInput)).Error);
        RequireUncertain((await AcquireAsync(installed.Runs, originalAcquire)).Error);

        var nextAcquire = AcquireRequest(continued, LeaseMode.Writer);
        var writer = ValueOfAcquire(await AcquireAsync(installed.Runs, nextAcquire));
        Assert.Equal(LeaseMode.Writer, writer.Mode);
        Assert.Equal(run.Epoch, writer.RunEpoch);
        Assert.NotEqual(originalWriter.LeaseId, writer.LeaseId);
        Assert.True(writer.Generation > originalWriter.Generation);
        Assert.Equal(0UL, writer.LastInputSequence);
        var nextInput = Input(continued, writer, 1, next);
        await AcceptInputAsync(installed.Runs, nextInput, (uint)next.Length);
        await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {delivered}"));
        RequireUncertain((await WriteAsync(installed.Runs, originalInput)).Error);
        Assert.True(supervisor.IsRunning());
        Assert.Equal(run.RunId, Assert.Single(await ListAsync(installed.Runs, run.SandboxId)).RunId);

        Id[] terminalCommands = [originalAcquire.Meta.CommandId, originalInput.Meta.CommandId, nextAcquire.Meta.CommandId, nextInput.Meta.CommandId];
        await AssertNoTerminalReceiptsAsync(installed, terminalCommands);
        var start = await OperationAsync(installed.Node, installed.OwnerEpoch, installed.StartCommand(run));
        Assert.Equal(run.RunId, start.AggregateId);
        Assert.Equal(OperationState.Succeeded, start.State);
        Assert.Equal(EffectCertainty.Happened, start.Effect);

        await StopRecoveredTerminalAsync(installed, continued, supervisor, cancellationToken);
        var milestones = ReadLines(marker);
        Assert.Equal("ready 24 80", Assert.Single(milestones, line => line.StartsWith("ready ", StringComparison.Ordinal)));
        Assert.DoesNotContain(milestones, line => line.StartsWith("error ", StringComparison.Ordinal));
        Assert.Equal(FormattableString.Invariant($"consumed {delivered}"),
            milestones.Last(line => line.StartsWith("consumed ", StringComparison.Ordinal)));
        AssertNoDurableInput(installed.Fixture, previous, terminalCommands);
        AssertNoDurableInput(installed.Fixture, next, terminalCommands);
        TestContext.Current.TestOutputHelper?.WriteLine(
            "The original owner consumed fresh input after rebind. The lost lease remained uncertain, no input was replayed, and Stop drained the same scope.");
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoveryResumesTheSamePipeCursorAndReportsEvictedOutput()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        const int retention = 4_096;
        await using var installed = await InstalledTerminal.StartAsync(retention);
        var run = await installed.RunAsync(TerminalMode.Pipes, "echo");
        var writer = await AcquireWriterAsync(installed.Runs, run);
        byte[] prefix = [0, 42, 255, 10, 128];
        var prefixInput = Input(run, writer, 1, prefix);
        await AcceptInputAsync(installed.Runs, prefixInput, (uint)prefix.Length);
        var oldOffset = (ulong)prefix.Length;
        var before = await ReadRecoveryPipeAsync(installed.Runs, run, 0, oldOffset, cancellationToken);
        Assert.Null(before.Gap);
        Assert.Equal(prefix, before.Bytes);

        var burst = new byte[16 * 1024];
        Array.Fill(burst, (byte)'T');
        var savedOffset = oldOffset + (ulong)burst.Length;
        await AcceptInputAsync(installed.Runs, Input(run, writer, 2, burst), (uint)burst.Length);
        // Wait for the actual echo output before reading the final retained interval.
        await ReadRecoveryPipeAsync(installed.Runs, run, oldOffset, savedOffset, cancellationToken);
        var retained = await ReadRecoveryPipeAsync(installed.Runs, run, oldOffset, savedOffset, cancellationToken);
        var gap = Assert.IsType<OutputGap>(retained.Gap);
        Assert.Equal("retention", gap.Reason);
        Assert.Equal(oldOffset, gap.RequestedOffset);
        Assert.Equal(savedOffset - gap.EarliestOffset, (ulong)retained.Bytes.Length);
        Assert.InRange(retained.Bytes.Length, 1, retention);
        Assert.True(retained.Bytes.AsSpan().IndexOfAnyExcept((byte)'T') < 0);
        var firstNode = await HandshakeAsync(installed.Node);
        var binding = ReadRecoveryBinding(installed.Fixture.DataRoot, run);
        var supervisor = CaptureRecoveryTerminalSupervisor(installed, binding);

        var continued = await RebindRecoveryTerminalAsync(installed, run, binding, supervisor, firstNode.NodeEpoch, cancellationToken);
        var preserved = await ReadRecoveryPipeAsync(installed.Runs, continued, oldOffset, savedOffset, cancellationToken);
        Assert.Equal(gap, preserved.Gap);
        Assert.Equal(retained.Bytes, preserved.Bytes);
        RequireUncertain((await WriteAsync(installed.Runs, prefixInput)).Error);
        var fresh = await AcquireWriterAsync(installed.Runs, continued);
        byte[] suffix = [241, 0, 7, 225, 130, 10];
        var nextOffset = savedOffset + (ulong)suffix.Length;
        await AcceptInputAsync(installed.Runs, Input(continued, fresh, 1, suffix), (uint)suffix.Length);
        var resumed = await ReadRecoveryPipeAsync(installed.Runs, continued, savedOffset, nextOffset, cancellationToken);
        Assert.Null(resumed.Gap);
        Assert.Equal(suffix, resumed.Bytes);
        await StopRecoveredTerminalAsync(installed, continued, supervisor, cancellationToken);
        var after = await WatchAsync(installed.Runs, continued, StreamKind.Stdout, savedOffset);
        Assert.Null(after.Gap);
        Assert.Equal(nextOffset, after.Offset);
        Assert.Equal(suffix, after.Bytes);
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Output retention preserved the gap from {oldOffset} to {gap.EarliestOffset} across Node restart. The original cursor {savedOffset} resumed through {after.Offset}."));
    }

    private static ProcessIdentity CaptureRecoveryTerminalSupervisor(InstalledTerminal installed, RecoveryBinding binding)
    {
        var process = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(binding.Pid));
        Assert.NotEqual(installed.Process.Id, process.Pid);
        long creation = OperatingSystem.IsWindows()
            ? new DateTime(process.StartKey, DateTimeKind.Utc).ToFileTimeUtc()
            : process.StartKey;
        Assert.Equal(binding.Creation, creation.ToString(CultureInfo.InvariantCulture));
        Assert.True(process.IsRunning());
        return process;
    }

    private static async Task<Run> RebindRecoveryTerminalAsync(InstalledTerminal installed, Run original, RecoveryBinding binding,
        ProcessIdentity supervisor, string firstNodeEpoch, CancellationToken cancellationToken)
    {
        await installed.CrashAndRestartNodeAsync();
        var hello = await HandshakeAsync(installed.Node);
        Assert.NotEqual(firstNodeEpoch, hello.NodeEpoch);
        Assert.Equal(installed.OwnerEpoch, hello.OwnerEpoch);
        var wait = Stopwatch.StartNew();
        while (true)
        {
            Assert.True(supervisor.IsRunning(), "The original native Run owner did not survive the Node restart.");
            var rebound = ReadRecoveryBinding(installed.Fixture.DataRoot, original);
            Assert.Equal(binding, rebound with { Generation = binding.Generation });
            if (rebound.Generation > binding.Generation)
            {
                break;
            }

            Assert.True(wait.Elapsed < NativeBound, "The installed Node did not authenticate a fresh control generation.");
            await Task.Delay(100, cancellationToken);
        }

        var continued = await WaitForStateAsync(installed.Fixture, installed.Runs, original.RunId, RunState.Running, cancellationToken);
        Assert.Equal(original.Epoch, continued.Epoch);
        Assert.Equal(original.LaunchSha256, continued.LaunchSha256);
        Assert.Equal(original.StartedAt, continued.StartedAt);
        Assert.Equal(original.TerminalMode, continued.TerminalMode);
        return continued;
    }

    private static async Task StopRecoveredTerminalAsync(InstalledTerminal installed, Run run, ProcessIdentity supervisor,
        CancellationToken cancellationToken)
    {
        var active = await InspectAsync(installed.Runs, run.RunId, cancellationToken);
        Assert.Equal(RunState.Running, active.State);
        Assert.True(supervisor.IsRunning());
        var stop = BuildStop(installed.OwnerEpoch, active);
        await StopAsync(installed.Runs, stop, cancellationToken);
        var final = await WaitForStateAsync(installed.Fixture, installed.Runs, run.RunId, RunState.Exited, cancellationToken);
        Assert.True(final.Exit.GroupEmptyVerified);
        Assert.False(supervisor.IsRunning());
        AssertStopReceipt(await OperationAsync(installed.Node, installed.OwnerEpoch, stop.Meta.CommandId), stop,
            final.Revision, EffectCertainty.Happened);
    }

    private static async Task<(byte[] Bytes, OutputGap? Gap)> ReadRecoveryPipeAsync(RunService.RunServiceClient runs, Run run,
        ulong offset, ulong until, CancellationToken cancellationToken)
    {
        using var call = StartWatch(runs, run, StreamKind.Stdout, offset);
        using var bytes = new MemoryStream();
        OutputGap? gap = null;
        while (offset < until)
        {
            Assert.True(await call.ResponseStream.MoveNext(cancellationToken), "The live recovered output stopped before its expected byte offset.");
            var frame = call.ResponseStream.Current;
            Assert.Null(frame.Error);
            if (frame.Gap is { } discarded)
            {
                Assert.Equal(run.Epoch, discarded.Epoch);
                Assert.Equal(offset, discarded.RequestedOffset);
                Assert.InRange(discarded.EarliestOffset, offset + 1, until - 1);
                gap = discarded;
                offset = discarded.EarliestOffset;
                bytes.SetLength(0);
                continue;
            }

            var chunk = Assert.IsType<OutputChunk>(frame.Chunk);
            Assert.Equal(run.Epoch, chunk.Epoch);
            Assert.Equal(StreamKind.Stdout, chunk.Stream);
            Assert.Equal(offset, chunk.Offset);
            Assert.InRange(chunk.Data.Length, 1, 65_536);
            Assert.Equal(offset + (ulong)chunk.Data.Length, chunk.NextOffset);
            Assert.InRange(chunk.NextOffset, offset + 1, until);
            bytes.Write(chunk.Data.Span);
            offset = chunk.NextOffset;
        }

        return (bytes.ToArray(), gap);
    }
}
