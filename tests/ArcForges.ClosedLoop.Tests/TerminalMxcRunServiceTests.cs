// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Linux;
using ArcForges.Tests;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 160_000, DisableParallelization = true)]
    public async Task InstalledTerminalDrawsResizesRestoresAndDeliversNativeForegroundInterrupt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var installed = await InstalledTerminal.StartAsync();
        var marker = Path.Combine(installed.Working, "tui.log");
        var tui = await installed.RunAsync(TerminalMode.Interactive, "terminal", "tui", marker);
        Assert.Equal(TerminalMode.Interactive, tui.TerminalMode);
        await WaitMarkerAsync(marker, "ready 24 80");
        var writer = await AcquireWriterAsync(installed.Runs, tui);
        var resized = await installed.Runs.ResizeTerminalAsync(new RunServiceResizeTerminalRequest
        {
            Meta = Mutation(),
            RunId = tui.RunId,
            Lease = writer,
            ResizeSequence = 1,
            Size = new TerminalSize { Rows = 35, Columns = 107 },
        }, deadline: Deadline, cancellationToken: Ct);
        var actualSize = Value(resized.Value, resized.Error).AppliedSize;
        Assert.Equal(35u, actualSize.Rows);
        Assert.Equal(107u, actualSize.Columns);
        await WaitMarkerAsync(marker, "resize 35 107");
        await AcceptInputAsync(installed.Runs, Input(tui, writer, 1, "星"u8.ToArray()), 3);
        await WaitMarkerAsync(marker, "unicode");
        await AcceptInputAsync(installed.Runs, Input(tui, writer, 2, [3]), 1);
        await WaitMarkerAsync(marker, "raw-etx");
        await AcceptInputAsync(installed.Runs, Input(tui, writer, 3, "q"u8.ToArray()), 1);
        await WaitMarkerAsync(marker, "restored");
        await AssertTerminalExitAsync(installed, tui);
        var output = await WatchAsync(installed.Runs, tui, StreamKind.Terminal);
        Assert.Null(output.Gap);
        var canvas = Encoding.UTF8.GetString(output.Bytes);
        Assert.Contains("\u001b[?1049h", canvas);
        Assert.Contains("\u001b[?1049l", canvas);
        Assert.Contains("CORE03 星", canvas);
        Assert.Contains("CORE03 redraw 星 35x107", canvas);

        var signalMarker = Path.Combine(installed.Working, "interrupt.log");
        string[] signal = ["terminal", "signal", signalMarker];
        // Linux job control establishes the tested controlling foreground group separately from the SDK wrapper.
        string[] foreground = OperatingSystem.IsLinux()
            ? ["/usr/bin/bash", "--noprofile", "--norc", "-i", "-c", "\"$0\" \"$@\"", installed.TestLoad, .. signal]
            : [installed.TestLoad, .. signal];
        var cooked = await installed.StartRunAsync(TerminalMode.Interactive, foreground);
        await WaitMarkerAsync(signalMarker, "ready 24 80");
        var cookedWriter = await AcquireWriterAsync(installed.Runs, cooked);
        await AcceptInputAsync(installed.Runs, Input(cooked, cookedWriter, 1, [3]), 1);
        var interrupted = await AssertTerminalExitAsync(installed, cooked);
        var signalMarkers = ReadLines(signalMarker);
        Assert.DoesNotContain(signalMarkers, line => line.StartsWith("error ", StringComparison.Ordinal));
        if (OperatingSystem.IsWindows() && !signalMarkers.Contains("sigint", StringComparer.Ordinal))
        {
            // The qualified Windows executor can deliver the processed interrupt as STATUS_CONTROL_C_EXIT.
            Assert.True(interrupted.Exit.HasRawCode);
            Assert.Equal(ExitSource.OfficialExecutor, interrupted.Exit.Source);
            Assert.Equal(unchecked((int)0xC000013A), interrupted.Exit.RawCode);
        }
        else
        {
            Assert.Contains("sigint", signalMarkers);
            Assert.Contains("restored", signalMarkers);
        }
    }

    [Fact(Timeout = 140_000, DisableParallelization = true)]
    public async Task InstalledPipesPreserveMaximumBinaryFrameAndOnlyExplicitEofClosesInput()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var installed = await InstalledTerminal.StartAsync();
        bool waitAfterEof = OperatingSystem.IsLinux();
        var eofObserved = Path.Combine(installed.Working, "pipe-eof-observed");
        var release = Path.Combine(installed.Working, "pipe-eof-release");
        const string echoThenHold = """
            "$1" echo || exit $?
            : > "$2" || exit $?
            "$1" hold --hold-ms 20000 --until-file "$3" > /dev/null || exit $?
            test -f "$3"
            """;
        // Keep the Linux owner alive after echo reads native EOF so the client can collect its acknowledgment.
        var run = waitAfterEof
            ? await installed.StartRunAsync(TerminalMode.Pipes,
                ["/usr/bin/dash", "-c", echoThenHold, "arcforges-pipe-fixture", installed.TestLoad, eofObserved, release])
            : await installed.RunAsync(TerminalMode.Pipes, "echo");
        Assert.Equal(TerminalMode.Pipes, run.TerminalMode);
        var writer = await AcquireWriterAsync(installed.Runs, run);
        var bytes = new byte[65_536];
        for (var index = 0; index < bytes.Length; index++) bytes[index] = (byte)index;
        await AcceptInputAsync(installed.Runs, Input(run, writer, 1, bytes), 65_536);
        var refused = await installed.Runs.ResizeTerminalAsync(new RunServiceResizeTerminalRequest
        {
            Meta = Mutation(),
            RunId = run.RunId,
            Lease = writer,
            ResizeSequence = 1,
            Size = new TerminalSize { Rows = 30, Columns = 100 },
        }, deadline: Deadline, cancellationToken: Ct);
        Assert.Equal("terminal_unavailable", refused.Error?.Code);

        await DetachAsync(installed.Runs, run, writer);
        await using (var disconnected = OpenChannel(installed.Fixture))
        {
            var disconnecting = new RunService.RunServiceClient(disconnected.CallInvoker);
            var current = await AcquireWriterAsync(disconnecting, run);
            Assert.True(current.Generation > writer.Generation);
            writer = current;
        }

        await using var next = OpenChannel(installed.Fixture);
        var resumed = new RunService.RunServiceClient(next.CallInvoker);
        var newWriter = await WaitForExclusiveWriterAsync(resumed, run);
        Assert.True(newWriter.Generation > writer.Generation);
        Assert.Equal(RunState.Running, (await InspectAsync(resumed, run.RunId, Ct)).State);

        var eof = Input(run, newWriter, 1, null);
        eof.CloseStdin = true;
        Assert.False(eof.HasInput);
        var mixed = Input(run, newWriter, 1, [0]);
        mixed.CloseStdin = true;
        Assert.Equal("invalid_argument", (await WriteAsync(resumed, mixed)).Error?.Code);
        if (waitAfterEof)
        {
            Assert.False(File.Exists(eofObserved));
        }

        await AcceptInputAsync(resumed, eof, 0);
        if (waitAfterEof)
        {
            await TestNode.WaitAsync(() => File.Exists(eofObserved), NativeBound, "the native pipe EOF marker");
            Assert.Equal(RunState.Running, (await InspectAsync(resumed, run.RunId, Ct)).State);
            await File.WriteAllTextAsync(release, "release", Ct);
        }

        var final = await AssertTerminalExitAsync(installed, run);
        if (waitAfterEof)
        {
            Assert.True(final.Exit.HasRawCode);
            Assert.Equal(0, final.Exit.RawCode);
        }

        var stdout = await WatchAsync(resumed, run, StreamKind.Stdout);
        Assert.Null(stdout.Gap);
        Assert.Equal(65_536UL, stdout.Offset);
        Assert.True(bytes.AsSpan().SequenceEqual(stdout.Bytes), "The native pipe output differed from the 65,536-byte binary input.");
        Assert.Empty((await WatchAsync(resumed, run, StreamKind.Stderr)).Bytes);
    }

    [Fact(Timeout = 140_000, DisableParallelization = true)]
    public async Task InstalledUnwatchedOutputFinishesWithAnExplicitRetainedCursorGap()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        const ulong retained = 4_096;
        const int bytes = 2 * 1024 * 1024;
        await using var installed = await InstalledTerminal.StartAsync(retained);
        var run = await installed.StartRunAsync(TerminalMode.Pipes,
            [installed.TestLoad, "output", "--bytes", bytes.ToString(CultureInfo.InvariantCulture), "--stream", "stdout"], waitForRunning: false);
        // No terminal owner, watcher or output consumer participates before native exit.
        await AssertTerminalExitAsync(installed, run);
        var old = await WatchAsync(installed.Runs, run, StreamKind.Stdout);
        Assert.NotNull(old.Gap);
        Assert.Equal(0UL, old.Gap.RequestedOffset);
        Assert.InRange(old.Gap.EarliestOffset, 1UL, (ulong)(bytes - 1));
        var kept = await WatchAsync(installed.Runs, run, StreamKind.Stdout, old.Gap.EarliestOffset);
        Assert.Null(kept.Gap);
        Assert.Equal((ulong)bytes, kept.Offset);
        Assert.InRange(kept.Bytes.Length, 1, (int)retained);
        Assert.Equal(kept.Offset - old.Gap.EarliestOffset, (ulong)kept.Bytes.Length);
    }

    [Fact(Timeout = 100_000, DisableParallelization = true)]
    public async Task InstalledSlowSubscriberGetsExplicitGapWithoutBlockingNativeExit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        const int prefix = 512 * 1024;
        const int tail = 3 * 1024 * 1024;
        const ulong retained = 1024 * 1024;
        byte[] anchor = "CORE03 slow viewer \n"u8.ToArray();
        var produced = (ulong)(anchor.Length + prefix + tail);
        await using var installed = await InstalledTerminal.StartAsync(retained);
        var marker = Path.Combine(installed.Working, "slow-output.log");
        var prefixGate = Path.Combine(installed.Working, "prefix-release");
        var tailGate = Path.Combine(installed.Working, "tail-release");
        var run = await installed.RunAsync(TerminalMode.Pipes, "terminal", "slow-output", marker, prefixGate, tailGate);
        await WaitMarkerAsync(marker, "started");
        await using var viewingConnection = OpenChannel(installed.Fixture);
        var viewer = new RunService.RunServiceClient(viewingConnection.CallInvoker);
        using var slow = StartWatch(viewer, run, StreamKind.Stdout, 0);
        Assert.True(await slow.ResponseStream.MoveNext(Ct));
        var first = slow.ResponseStream.Current.Chunk;
        Assert.NotNull(first);
        Assert.Equal(StreamKind.Stdout, first.Stream);
        Assert.Equal(run.Epoch, first.Epoch);
        Assert.Equal(0UL, first.Offset);
        Assert.Equal((ulong)anchor.Length, first.NextOffset);
        Assert.True(anchor.AsSpan().SequenceEqual(first.Data.Span));

        // Keep the real HTTP/2 response unread. Fill its transport within retention, then advance retention
        // while the response is backpressured. The independent owner connection observes native exit.
        using var paused = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        paused.CancelAfter(TimeSpan.FromSeconds(8)); // The registered stream resets an unread write after ten seconds.
        await File.WriteAllTextAsync(prefixGate, "prefix", paused.Token);
        await WaitSlowMarkerAsync(marker, "prefix-complete", paused.Token);
        await Task.Delay(350, paused.Token); // The stock broker polls its retained cursor every 125 ms.
        await File.WriteAllTextAsync(tailGate, "tail", paused.Token);
        await WaitSlowMarkerAsync(marker, "finished", paused.Token);
        var final = await WaitForStateAsync(installed.Fixture, installed.Runs, run.RunId, RunState.Exited, paused.Token);
        Assert.True(final.Exit.GroupEmptyVerified);

        var gaps = new List<OutputGap>();
        var resumed = await ReadWatchAsync(slow.ResponseStream, run, StreamKind.Stdout, first.NextOffset, gaps);
        var firstBlocked = gaps.FirstOrDefault(gap => gap.Reason == "slow_consumer");
        Assert.NotNull(firstBlocked);
        Assert.InRange(firstBlocked.RequestedOffset, first.NextOffset, (ulong)(anchor.Length + prefix));
        Assert.Equal(produced, resumed.Offset);

        var fresh = await WatchAsync(installed.Runs, run, StreamKind.Stdout);
        Assert.NotNull(fresh.Gap);
        Assert.Equal("retention", fresh.Gap.Reason);
        Assert.All(gaps, gap =>
        {
            Assert.True(gap.Reason is "slow_consumer" or "retention", $"Unexpected advancing GAP reason {gap.Reason}.");
            Assert.InRange(gap.EarliestOffset, first.NextOffset + 1, fresh.Gap.EarliestOffset);
        });
        Assert.Equal(produced, fresh.Offset);
        Assert.InRange(fresh.Bytes.Length, 1, (int)retained);
        Assert.Equal(produced - fresh.Gap.EarliestOffset, (ulong)fresh.Bytes.Length);
        Assert.True(fresh.Bytes.AsSpan().IndexOfAnyExcept((byte)'T') < 0, "The retained bytes must be the final producer burst.");
        Assert.NotNull(resumed.Gap);
        Assert.Equal(produced - resumed.Gap.EarliestOffset, (ulong)resumed.Bytes.Length);
        Assert.True(resumed.Bytes.Length >= fresh.Bytes.Length, "The original subscriber must recover the entire stable retained suffix.");
        Assert.True(resumed.Bytes.AsSpan(^fresh.Bytes.Length).SequenceEqual(fresh.Bytes),
            "The original subscriber's final suffix must match the fresh reader's stable retained bytes.");
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"Native Run exited while its viewer paused. Slow cursor {firstBlocked.RequestedOffset} advanced to {firstBlocked.EarliestOffset}. "
            + $"The viewer received {gaps.Count} gap frames and the stable suffix of {fresh.Bytes.Length} bytes through final offset {fresh.Offset}.");
    }

    private static async Task WaitSlowMarkerAsync(string path, string milestone, CancellationToken cancellationToken)
    {
        while (!ReadLines(path).Contains(milestone, StringComparer.Ordinal))
        {
            await Task.Delay(20, cancellationToken);
        }
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledQuietTerminalIsExclusiveAndNeverPersistsTransientInput()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var installed = await InstalledTerminal.StartAsync();
        var canary = Encoding.ASCII.GetBytes("core03-terminal-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        const uint writes = 257;
        var count = canary.Length + (int)writes;
        var marker = Path.Combine(installed.Working, "quiet.log");
        // Keep the foreground alive after the final byte so the client can poll its acknowledgment.
        var run = await installed.RunAsync(TerminalMode.Interactive, "terminal", "quiet", marker,
            (count + 2).ToString(CultureInfo.InvariantCulture), "1000");
        await WaitMarkerAsync(marker, "ready 24 80");
        await using var second = OpenChannel(installed.Fixture);
        var other = new RunService.RunServiceClient(second.CallInvoker);
        var left = AcquireRequest(run, LeaseMode.Writer);
        var right = AcquireRequest(run, LeaseMode.Writer);
        var candidates = await Task.WhenAll(AcquireAsync(installed.Runs, left), AcquireAsync(other, right));
        var winner = Assert.Single(candidates, reply => reply.Value is not null);
        Assert.Equal("busy", Assert.Single(candidates, reply => reply.Error is not null).Error.Code);
        var firstWins = ReferenceEquals(winner, candidates[0]);
        var acquiredCommand = firstWins ? left.Meta.CommandId : right.Meta.CommandId;
        var writerSide = firstWins ? installed.Runs : other;
        var otherSide = firstWins ? other : installed.Runs;
        var writer = winner.Value.Lease;
        var observer = ValueOfAcquire(await AcquireAsync(otherSide, AcquireRequest(run, LeaseMode.Observer)));
        var observerWrite = await WriteAsync(otherSide, Input(run, observer, 1, "!"u8.ToArray()));
        Assert.Equal("invalid_argument", observerWrite.Error?.Code);

        var original = Input(run, writer, 1, canary);
        await AcceptInputAsync(writerSide, original, (uint)canary.Length);
        await AcceptInputAsync(writerSide, original, (uint)canary.Length);
        Assert.Equal("invalid_argument", (await WriteAsync(writerSide, Input(run, writer, 3, "!"u8.ToArray()))).Error?.Code);
        var conflicting = original.Clone();
        conflicting.Input = ByteString.CopyFromUtf8("different content");
        Assert.Equal("command_id_reused", (await WriteAsync(writerSide, conflicting)).Error?.Code);
        await WaitMarkerAsync(marker, "consumed " + canary.Length.ToString(CultureInfo.InvariantCulture));

        for (uint index = 1; index <= writes; index++)
        {
            await AcceptInputAsync(writerSide, Input(run, writer, index + 1, "."u8.ToArray()), 1);
        }

        RequireUncertain((await WriteAsync(writerSide, original)).Error);
        await WaitMarkerAsync(marker, "consumed " + count.ToString(CultureInfo.InvariantCulture));
        var resize = new RunServiceResizeTerminalRequest
        {
            Meta = Mutation(),
            RunId = run.RunId,
            Lease = writer,
            ResizeSequence = 1,
            Size = new TerminalSize { Rows = 30, Columns = 100 },
        };
        var resized = await writerSide.ResizeTerminalAsync(resize, deadline: Deadline, cancellationToken: Ct);
        Assert.Equal(resize.Size, Value(resized.Value, resized.Error).AppliedSize);

        var take = AcquireRequest(run, LeaseMode.Writer, takeover: true);
        var takeover = ValueOfAcquire(await AcquireAsync(otherSide, take));
        Assert.True(takeover.Generation > writer.Generation);
        var old = Input(run, writer, writes + 2, "!"u8.ToArray());
        Assert.Equal("lease_stale", (await WriteAsync(writerSide, old)).Error?.Code);
        var aged = Input(run, takeover, 1, "+"u8.ToArray());
        await AcceptInputAsync(otherSide, aged, 1);
        await WaitMarkerAsync(marker, "consumed " + (count + 1).ToString(CultureInfo.InvariantCulture));
        var expiry = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(takeover.ExpiresAt));
        var remaining = expiry - DateTimeOffset.UtcNow;
        Assert.InRange(remaining.TotalSeconds, 1, 31);
        await Task.Delay(remaining + TimeSpan.FromMilliseconds(300), Ct);
        RequireUncertain((await WriteAsync(otherSide, aged)).Error);
        Assert.Equal("lease_stale", (await WriteAsync(otherSide, Input(run, takeover, 2, "!"u8.ToArray()))).Error?.Code);
        var finalWriter = await AcquireWriterAsync(writerSide, run);
        Assert.True(finalWriter.Generation > takeover.Generation);
        var detach = await DetachAsync(writerSide, run, finalWriter);
        var last = await AcquireWriterAsync(otherSide, run);
        await AcceptInputAsync(otherSide, Input(run, last, 1, "z"u8.ToArray()), 1);
        await WaitMarkerAsync(marker, "consumed " + (count + 2).ToString(CultureInfo.InvariantCulture));
        await WaitMarkerAsync(marker, "restored");
        var final = await AssertTerminalExitAsync(installed, run);
        var output = await WatchAsync(installed.Runs, run, StreamKind.Terminal);
        Assert.True(output.Bytes.AsSpan().IndexOf(canary) < 0, "The echo-disabled payload returned transient input as output.");

        var stopRequest = BuildStop(installed.OwnerEpoch, final);
        var stop = await StopAsync(installed.Runs, stopRequest, Ct);
        AssertStopReceipt(stop.Operation, stopRequest, final.Revision, EffectCertainty.DidNotHappen);
        Id[] terminalCommands = [acquiredCommand, original.Meta.CommandId, resize.Meta.CommandId, take.Meta.CommandId,
            detach, old.Meta.CommandId, aged.Meta.CommandId];
        await AssertNoTerminalReceiptsAsync(installed, terminalCommands);
        Assert.Equal(OperationState.Succeeded,
            (await OperationAsync(installed.Node, installed.OwnerEpoch, installed.StartCommand(run))).State);
        Assert.Equal(OperationState.Succeeded,
            (await OperationAsync(installed.Node, installed.OwnerEpoch, stopRequest.Meta.CommandId)).State);
        AssertNoDurableInput(installed.Fixture, canary, terminalCommands);
    }

    [Theory(Timeout = 130_000, DisableParallelization = true)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InstalledTerminalLossMakesOldAcknowledgmentUncertain(bool supervisorLoss)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var installed = await InstalledTerminal.StartAsync();
        try
        {
            await ExerciseTerminalLossAsync(installed, supervisorLoss);
        }
        catch (Exception primary)
        {
            try
            {
                await installed.DisposeAsync();
            }
            catch (Exception cleanup)
            {
                throw new AggregateException("The terminal loss case and native cleanup both failed.", primary, cleanup);
            }

            throw;
        }

        await installed.DisposeAsync();
    }

    private static async Task ExerciseTerminalLossAsync(InstalledTerminal installed, bool supervisorLoss)
    {
        var marker = Path.Combine(installed.Working, "loss.log");
        byte[] one = "x"u8.ToArray();
        var run = await installed.RunAsync(TerminalMode.Interactive, "terminal", "quiet", marker, "1", "8000");
        await WaitMarkerAsync(marker, "ready 24 80");
        var writer = await AcquireWriterAsync(installed.Runs, run);
        var original = Input(run, writer, 1, one);
        await AcceptInputAsync(installed.Runs, original, 1);
        await WaitMarkerAsync(marker, "consumed 1");
        var binding = ReadSupervisor(installed.Fixture.DataRoot, run);
        var owner = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(binding.Pid));
        Assert.NotEqual(installed.Process.Id, owner.Pid);
        var unit = OperatingSystem.IsLinux() ? binding.Boundary.Split('|', 2)[0] : "Windows Job";
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"Run {Hex(run.RunId)} has supervisor PID {owner.Pid} and boundary {unit}. Supervisor loss = {supervisorLoss}.");
        if (supervisorLoss)
        {
            KillExactTerminalSupervisor(owner, binding.Creation);
            await TestNode.WaitAsync(() => !owner.IsRunning(), NativeBound, "the exact supervisor to exit");
        }
        else
        {
            await installed.CrashAndRestartNodeAsync();
            Assert.True(owner.IsRunning(), "The original supervisor should survive this Node loss until the fixture self-settles.");
        }

        RequireUncertain((await WriteAsync(installed.Runs, original)).Error);
        await AssertNoTerminalReceiptsAsync(installed, [original.Meta.CommandId]);
        await TestNode.WaitAsync(() => !owner.IsRunning(), NativeBound, "the bounded original terminal owner to self-settle or exit");
        Assert.Equal("consumed 1", Assert.Single(ReadLines(marker), line => line.StartsWith("consumed ", StringComparison.Ordinal)));
    }

    private static RunServiceAcquireTerminalRequest AcquireRequest(Run run, LeaseMode mode, bool takeover = false) => new()
    {
        Meta = Mutation(),
        RunId = run.RunId,
        Mode = mode,
        Takeover = takeover,
    };

    private static async Task<RunServiceAcquireTerminalResponse> AcquireAsync(RunService.RunServiceClient runs, RunServiceAcquireTerminalRequest request) =>
        await runs.AcquireTerminalAsync(request, deadline: Deadline, cancellationToken: Ct);

    private static TerminalLease ValueOfAcquire(RunServiceAcquireTerminalResponse reply) => Value(reply.Value, reply.Error).Lease;

    private static async Task<TerminalLease> AcquireWriterAsync(RunService.RunServiceClient runs, Run run)
    {
        var lease = ValueOfAcquire(await AcquireAsync(runs, AcquireRequest(run, LeaseMode.Writer)));
        Assert.Equal(run.Epoch, lease.RunEpoch);
        Assert.Equal(LeaseMode.Writer, lease.Mode);
        return lease;
    }

    private static async Task<TerminalLease> WaitForExclusiveWriterAsync(RunService.RunServiceClient runs, Run run)
    {
        var started = Stopwatch.StartNew();
        while (true)
        {
            var reply = await AcquireAsync(runs, AcquireRequest(run, LeaseMode.Writer));
            if (reply.Value is { } accepted) return accepted.Lease;

            Assert.Equal("busy", reply.Error?.Code);
            Assert.True(started.Elapsed < TimeSpan.FromSeconds(8), "Disconnection did not release the active pipe writer.");
            await Task.Delay(50, Ct);
        }
    }

    private static RunServiceWriteTerminalRequest Input(Run run, TerminalLease lease, ulong sequence, byte[]? bytes)
    {
        var request = new RunServiceWriteTerminalRequest { Meta = Mutation(), RunId = run.RunId, Lease = lease, InputSequence = sequence };
        if (bytes is not null) request.Input = ByteString.CopyFrom(bytes);
        return request;
    }

    private static async Task<RunServiceWriteTerminalResponse> WriteAsync(RunService.RunServiceClient runs, RunServiceWriteTerminalRequest request) =>
        await runs.WriteTerminalAsync(request, deadline: Deadline, cancellationToken: Ct);

    private static async Task AcceptInputAsync(RunService.RunServiceClient runs, RunServiceWriteTerminalRequest request, uint accepted)
    {
        var reply = await WriteAsync(runs, request);
        var value = Value(reply.Value, reply.Error);
        Assert.True(value.HasAcceptedBytes);
        Assert.Equal(accepted, value.AcceptedBytes);
    }

    private static async Task<Id> DetachAsync(RunService.RunServiceClient runs, Run run, TerminalLease lease)
    {
        var request = new RunServiceDetachTerminalRequest { Meta = Mutation(), RunId = run.RunId, Lease = lease };
        var reply = await runs.DetachTerminalAsync(request, deadline: Deadline, cancellationToken: Ct);
        Value(reply.Value, reply.Error);
        return request.Meta.CommandId;
    }

    private static void RequireUncertain(ArcError? error)
    {
        Assert.NotNull(error);
        Assert.Equal("terminal_ack_unavailable", error.Code);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.False(error.Retry.HasReconciliationOperation);
    }

    private static async Task<Run> AssertTerminalExitAsync(InstalledTerminal installed, Run run)
    {
        var final = await WaitForStateAsync(installed.Fixture, installed.Runs, run.RunId, RunState.Exited);
        Assert.True(final.Exit.GroupEmptyVerified);
        return final;
    }

    private static Task WaitMarkerAsync(string path, string line) => TestNode.WaitAsync(() =>
    {
        var markers = ReadLines(path);
        Assert.DoesNotContain(markers, marker => marker.StartsWith("error ", StringComparison.Ordinal));
        return markers.Contains(line, StringComparer.Ordinal);
    }, NativeBound, "the native payload milestone " + line);

    private static async Task<(byte[] Bytes, ulong Offset, OutputGap? Gap)> WatchAsync(
        RunService.RunServiceClient runs, Run run, StreamKind kind, ulong offset = 0)
    {
        using var call = StartWatch(runs, run, kind, offset);
        return await ReadWatchAsync(call.ResponseStream, run, kind, offset);
    }

    private static AsyncServerStreamingCall<RunServiceWatchOutputFrame> StartWatch(
        RunService.RunServiceClient runs, Run run, StreamKind kind, ulong offset) =>
        runs.WatchOutput(new RunServiceWatchOutputRequest
        {
            Meta = Query(),
            RunId = run.RunId,
            Epoch = run.Epoch,
            Stream = kind,
            Offset = offset,
        }, deadline: Deadline, cancellationToken: Ct);

    private static async Task<(byte[] Bytes, ulong Offset, OutputGap? Gap)> ReadWatchAsync(
        IAsyncStreamReader<RunServiceWatchOutputFrame> response, Run run, StreamKind kind, ulong offset,
        List<OutputGap>? successiveGaps = null)
    {
        using var bytes = new MemoryStream();
        OutputGap? gap = null;
        var terminal = false;
        while (await response.MoveNext(Ct))
        {
            var frame = response.Current;
            Assert.Null(frame.Error);
            Assert.False(terminal, "The terminal Run frame must be last.");
            if (frame.Gap is { } missing)
            {
                Assert.Equal(run.Epoch, missing.Epoch);
                Assert.Equal(offset, missing.RequestedOffset);
                Assert.True(missing.EarliestOffset > offset);
                if (successiveGaps is null)
                {
                    Assert.Null(gap);
                }
                else
                {
                    successiveGaps.Add(missing);
                    bytes.SetLength(0); // Keep the contiguous output suffix after the latest gap.
                }

                gap = missing;
                offset = missing.EarliestOffset;
            }
            else if (frame.Chunk is { } chunk)
            {
                Assert.Equal(run.Epoch, chunk.Epoch);
                Assert.Equal(kind, chunk.Stream);
                Assert.Equal(offset, chunk.Offset);
                Assert.InRange(chunk.Data.Length, 1, 65_536);
                Assert.Equal(offset + (ulong)chunk.Data.Length, chunk.NextOffset);
                Assert.True(bytes.Length + chunk.Data.Length <= 2 * 1024 * 1024);
                bytes.Write(chunk.Data.Span);
                offset = chunk.NextOffset;
            }
            else
            {
                Assert.NotNull(frame.Run);
                Assert.Equal(run.RunId, frame.Run.RunId);
                Assert.Equal(RunState.Exited, frame.Run.State);
                Assert.True(frame.Run.Exit.GroupEmptyVerified);
                terminal = true;
            }
        }

        Assert.True(terminal, "The installed output RPC must finish with the authoritative Run state.");
        return (bytes.ToArray(), offset, gap);
    }

    private static async Task AssertNoTerminalReceiptsAsync(InstalledTerminal installed, IReadOnlyList<Id> ids)
    {
        using var database = ReadDatabase(installed.Fixture.DataRoot);
        using var query = database.CreateCommand();
        query.CommandText = "SELECT count(*) FROM command_receipt WHERE command_id = $id;";
        var parameter = query.Parameters.AddWithValue("$id", string.Empty);
        foreach (var id in ids)
        {
            var response = await installed.Node.GetOperationAsync(new NodeServiceGetOperationRequest
            {
                Meta = Query(),
                OwnerEpoch = installed.OwnerEpoch,
                CommandId = id,
            }, deadline: Deadline, cancellationToken: Ct);
            Assert.Equal("not_found", response.Error?.Code);
            parameter.Value = Hex(id);
            Assert.Equal(0L, Assert.IsType<long>(query.ExecuteScalar()));
        }
    }

    private static void AssertNoDurableInput(TestNode fixture, byte[] canary, IReadOnlyList<Id> terminalCommands)
    {
        var hash = SHA256.HashData(canary);
        var canaryText = Encoding.ASCII.GetString(canary);
        var patterns = new List<byte[]>
        {
            canary, hash, Encoding.ASCII.GetBytes(Convert.ToHexStringLower(hash)), Encoding.ASCII.GetBytes(Convert.ToHexString(hash)),
            Encoding.ASCII.GetBytes(Convert.ToBase64String(canary)), Encoding.ASCII.GetBytes(Convert.ToBase64String(hash)),
            Encoding.Unicode.GetBytes(canaryText),
        };
        foreach (var id in terminalCommands)
        {
            patterns.Add(id.Value.ToByteArray());
            patterns.Add(Encoding.ASCII.GetBytes(Hex(id)));
            patterns.Add(Encoding.ASCII.GetBytes(IdText.Format(id)));
        }

        foreach (var path in Directory.EnumerateFiles(fixture.DataRoot, "*", new EnumerationOptions
        { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = false }))
        {
            // Socket endpoints and empty coordination files have no durable body to inspect.
            if (path.EndsWith(".sock", StringComparison.Ordinal) || new FileInfo(path).Length == 0) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Assert.InRange(stream.Length, 0, 64 * 1024 * 1024);
            var persisted = new byte[checked((int)stream.Length)];
            stream.ReadExactly(persisted);
            Assert.False(patterns.Any(pattern => persisted.AsSpan().IndexOf(pattern) >= 0),
                "Transient terminal input, its deterministic fingerprint, or its command identity appeared in " + Path.GetFileName(path));
        }
    }

    private static void KillExactTerminalSupervisor(ProcessIdentity expected, string creation)
    {
        if (OperatingSystem.IsLinux())
        {
            using var fd = new SafeFileHandle((nint)Libc.PidfdOpen(expected.Pid), ownsHandle: true);
            Assert.False(fd.IsInvalid);
            Assert.Equal(creation, expected.StartKey.ToString(CultureInfo.InvariantCulture));
            Assert.True(expected.IsRunning());
            Assert.Equal(0, Libc.PidfdSendSignal(fd.DangerousGetHandle().ToInt32(), Libc.SigKill));
            return;
        }

        using var process = System.Diagnostics.Process.GetProcessById(expected.Pid);
        Assert.False(process.SafeHandle.IsInvalid);
        Assert.Equal(expected.StartKey, process.StartTime.ToUniversalTime().Ticks);
        Assert.Equal(creation, process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture));
        process.Kill();
    }

    private sealed class InstalledTerminal : IAsyncDisposable
    {
        private NodeChannel _channel;
        private readonly Sandbox _sandbox;
        private readonly Dictionary<string, (Id Run, Id Command)> _runs = new(StringComparer.Ordinal);

        private InstalledTerminal(TestNode fixture, Process process, NodeChannel channel, Id ownerEpoch, Sandbox sandbox)
        {
            Fixture = fixture;
            Process = process;
            _channel = channel;
            OwnerEpoch = ownerEpoch;
            _sandbox = sandbox;
            Working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
            Directory.CreateDirectory(Working);
            var published = Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH");
            Assert.True(published is not null && Path.IsPathFullyQualified(published) && File.Exists(published),
                "Use the published native TestLoad with the extracted package fixture.");
            TestLoad = Path.Combine(Working, OperatingSystem.IsWindows() ? "arcforges-testload.exe" : "arcforges-testload");
            File.Copy(published!, TestLoad);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(TestLoad, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        public TestNode Fixture { get; }
        public Process Process { get; private set; }
        public Id OwnerEpoch { get; }
        public string Working { get; }
        public string TestLoad { get; }
        public RunService.RunServiceClient Runs => new(_channel.CallInvoker);
        public NodeService.NodeServiceClient Node => new(_channel.CallInvoker);

        public static async Task<InstalledTerminal> StartAsync(ulong? retention = null)
        {
            RequireExtractedPackage();
            var fixture = TestNode.Create();
            Process? process = null;
            NodeChannel? channel = null;
            Id? epoch = null;
            try
            {
                PrepareDataRoot(fixture.DataRoot);
                process = await fixture.StartNodeAsync();
                channel = OpenChannel(fixture);
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                epoch = (await HandshakeAsync(node)).OwnerEpoch;
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var sandbox = await CreateSandboxAsync(sandboxes, epoch, outputRetentionBytes: retention);
                return new InstalledTerminal(fixture, process, channel, epoch, sandbox);
            }
            catch
            {
                try
                {
                    if (channel is not null) await channel.DisposeAsync();
                    if (process is not null) await StopNodeAsync(fixture, process);
                    if (epoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, epoch);
                }
                finally
                {
                    await fixture.DisposeAsync();
                }

                throw;
            }
        }

        public Task<Run> RunAsync(TerminalMode mode, params string[] argv) => StartRunAsync(mode, [TestLoad, .. argv]);

        public async Task<Run> StartRunAsync(TerminalMode mode, string[] argv, bool waitForRunning = true)
        {
            var request = BuildStart(_sandbox, OwnerEpoch, argv);
            request.TerminalMode = mode;
            if (mode == TerminalMode.Pipes) request.TerminalSize = null;
            var reply = await Runs.StartAsync(request, deadline: Deadline, cancellationToken: Ct);
            var run = Value(reply.Value, reply.Error).Run;
            _runs.Add(Hex(run.RunId), (run.RunId, request.Meta.CommandId));
            return waitForRunning ? await WaitForStateAsync(Fixture, Runs, run.RunId, RunState.Running) : run;
        }

        public Id StartCommand(Run run) => _runs[Hex(run.RunId)].Command;

        public async Task CrashAndRestartNodeAsync()
        {
            Process.Kill();
            await Process.WaitForExitAsync(Ct).WaitAsync(NativeBound, Ct);
            await _channel.DisposeAsync();
            Process = await Fixture.StartNodeAsync();
            _channel = OpenChannel(Fixture);
            Assert.Equal(OwnerEpoch, (await HandshakeAsync(Node)).OwnerEpoch);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!Process.HasExited)
                {
                    foreach (var entry in _runs.Values)
                    {
                        var current = await InspectAsync(Runs, entry.Run, CancellationToken.None);
                        var cleanupStart = current.State;
                        var stopState = "already settling";
                        if (current.State is RunState.Running or RunState.Starting)
                        {
                            var stop = await Runs.StopAsync(BuildStop(OwnerEpoch, current), deadline: Deadline, cancellationToken: CancellationToken.None);
                            // Loss cases deliberately keep the old owner unbound. A typed unknown does not authorize native cleanup.
                            if (stop.Error?.Code == "outcome_unknown") continue;
                            current = Value(stop.Value, stop.Error).Run;
                            stopState = current.State.ToString();
                        }

                        var cleanup = Stopwatch.StartNew();
                        while (current.State is RunState.Stopping or RunState.Draining)
                        {
                            if (cleanup.Elapsed >= NativeBound)
                            {
                                var phases = ReadRunDiagnostics(Fixture, entry.Run);
                                Assert.Fail($"Run {Hex(entry.Run)} did not drain after cleanup Stop. "
                                    + $"Inspect initially reported {cleanupStart}. Stop reported {stopState}. "
                                    + $"Last Inspect reported {current.State} at revision {current.Revision.Value}. {phases}");
                            }

                            await Task.Delay(100);
                            current = await InspectAsync(Runs, entry.Run, CancellationToken.None);
                        }
                    }
                }
            }
            finally
            {
                try
                {
                    await _channel.DisposeAsync();
                    await StopNodeAsync(Fixture, Process);
                    RemoveFixtureOwnerKey(Fixture.DataRoot, OwnerEpoch);
                }
                finally
                {
                    await Fixture.DisposeAsync();
                }
            }
        }
    }
}
