// SPDX-License-Identifier: AGPL-3.0-only
// Test code runs on a console without a synchronization context and holds each fixture for the whole check, so these
// library-oriented rules do not apply here; the production-shaped files of this project keep them enabled.
#pragma warning disable CA1849, CA2007, CA2000, CA1508
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.PublicApi.V1;
using Grpc.Core;

namespace RealtimeAotProbe;

/// <summary>Cadence, cursor and recovery behavior of the <c>Poll</c> and <c>ReadOutput</c> fallbacks.</summary>
internal static class SelfTestReaders
{
    private sealed class PollRig
    {
        public PollRig()
        {
            Transport = new ScriptedTransport(Time);
            Poller = new EventPoller(Session, Transport, Observer, Time, () => Random, Policy);
        }

        public ManualTimeProvider Time { get; } = new();

        public ScriptedTransport Transport { get; }

        public RecordingObserver Observer { get; } = new();

        public RealtimePolicy Policy { get; } = new();

        public EventSession Session { get; } = new(Make.Key);

        public EventPoller Poller { get; }

        public double Random { get; set; }

        public CancellationTokenSource Cancel { get; } = new();

        public Task<WatchResult> Run { get; private set; } = Task.FromResult(default(WatchResult));

        public PollRig Start()
        {
            Run = Poller.RunAsync(Cancel.Token);
            return this;
        }

        public async Task<WatchResult> FinishAsync()
        {
            await Check.EventuallyAsync(() => Run.IsCompleted, "the run to end").ConfigureAwait(false);
            return await Run.ConfigureAwait(false);
        }

        public async Task<WatchResult> StopAsync()
        {
            await Cancel.CancelAsync().ConfigureAwait(false);
            return await FinishAsync().ConfigureAwait(false);
        }

        public Task PendingAsync(string what, params double[] seconds) =>
            Check.EventuallyAsync(() => Time.Pending().SequenceEqual(seconds.Select(TimeSpan.FromSeconds)), what + " (pending timers " + string.Join(",", Time.Pending()) + ")");
    }

    private sealed class ReadRig
    {
        public ReadRig()
        {
            Transport = new ScriptedTransport(Time);
            Session = new OutputSession(Make.Owner(), Policy);
            Reader = new OutputReader(Session, Transport, Observer, Time, () => Random, Policy);
        }

        public ManualTimeProvider Time { get; } = new();

        public ScriptedTransport Transport { get; }

        public RecordingObserver Observer { get; } = new();

        public RealtimePolicy Policy { get; } = new();

        public OutputSession Session { get; }

        public OutputReader Reader { get; }

        public double Random { get; set; }

        public CancellationTokenSource Cancel { get; } = new();

        public Task<WatchResult> Run { get; private set; } = Task.FromResult(default(WatchResult));

        public ReadRig Start()
        {
            Run = Reader.RunAsync(Cancel.Token);
            return this;
        }

        public async Task<WatchResult> FinishAsync()
        {
            await Check.EventuallyAsync(() => Run.IsCompleted, "the run to end").ConfigureAwait(false);
            return await Run.ConfigureAwait(false);
        }

        public async Task<WatchResult> StopAsync()
        {
            await Cancel.CancelAsync().ConfigureAwait(false);
            return await FinishAsync().ConfigureAwait(false);
        }
    }

    public static void Register(SelfTestRunner runner)
    {
        ArgumentNullException.ThrowIfNull(runner);
        runner.Add("poll: the first Poll sets scope, the snapshot is read, then Polls run at 10 seconds with 20 percent jitter", PollCadence);
        runner.Add("poll: a first Poll that does not require a reset is a protocol violation", PollFirstMustReset);
        runner.Add("poll: the cursor advances only after the whole page and replayed hints are deduplicated", PollCursorAfterPage);
        runner.Add("poll: malformed pages and typed errors stop or back off", PollMalformedAndErrors);
        runner.Add("poll: a reset page with a live cursor reads a snapshot and replaces the cursor", PollResetWithCursor);
        runner.Add("poll: calls never overlap", PollNoOverlap);
        runner.Add("poll: Watch and Poll share one cursor and one sequence, so a switch replays nothing", PollWatchSwitch);
        runner.Add("poll: hints outside scope stop the loop", PollInvalidHint);
        runner.Add("poll: cancelling during the wait ends the loop", PollCancellation);
        runner.Add("readOutput: reads every 5 seconds with 20 percent jitter until the terminal outcome is read", ReadCadence);
        runner.Add("readOutput: retries, resets and typed failures", ReadFailures);
    }

    private static async Task PollCadence()
    {
        var rig = new PollRig { Random = 0.0 };
        rig.Transport.OnPoll(Make.PollReset("n1"));
        rig.Transport.OnPoll(Make.PollPage("n2", Make.Hint(1)));
        rig.Transport.OnPoll(Make.PollPage("n3"));
        rig.Start();
        await rig.PendingAsync("the cadence after the first Poll at the low jitter end", 8).ConfigureAwait(false);
        Check.Sequence(["first Poll"], rig.Observer.Snapshots, "the snapshot is read before the cursor is used");
        Check.Equal("n1", rig.Session.Cursor ?? string.Empty, "the first cursor");
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(7_999)).ConfigureAwait(false);
        Check.Equal(1, rig.Transport.PollCalls, "no Poll before the cadence elapsed");
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(1)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Transport.PollCalls == 2 && rig.Observer.Hints.Count == 1, "the second Poll").ConfigureAwait(false);
        await rig.PendingAsync("the next interval", 8).ConfigureAwait(false);
        rig.Random = 1.0;
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Transport.PollCalls == 3, "the third Poll").ConfigureAwait(false);
        await rig.PendingAsync("the high jitter end", 12).ConfigureAwait(false);
        Check.Sequence([null, "n1", "n2"], rig.Transport.PollCursors, "Poll cursors");
        Check.Equal("n3", rig.Session.Cursor ?? string.Empty, "the last cursor");
        Check.True(rig.Observer.States.Contains(ConnectionState.Live), "live after the first page");
        Check.Equal(StopReason.Cancelled, (await rig.StopAsync().ConfigureAwait(false)).Reason, "cancelled");
        Check.Equal(ConnectionState.Stopped, rig.Observer.States[^1], "stopped on cancellation");
    }

    private static async Task PollFirstMustReset()
    {
        var rig = new PollRig();
        rig.Transport.OnPoll(Make.PollPage("n1", Make.Hint(1)));
        rig.Start();
        WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
        Check.Equal(StopReason.ProtocolViolation, result.Reason, "reason");
        Check.Equal(0, rig.Observer.Hints.Count, "no hint was delivered");
        Check.Equal(0, rig.Observer.Snapshots.Count, "no snapshot was requested");
    }

    private static async Task PollCursorAfterPage()
    {
        var rig = new PollRig();
        rig.Observer.FailHint = hint => hint.Seq == 2 ? new InvalidOperationException("consumer failed") : null;
        rig.Transport.OnPoll(Make.PollReset("n1"));
        rig.Transport.OnPoll(Make.PollPage("n2", Make.Hint(1), Make.Hint(2)));
        rig.Start();
        await rig.PendingAsync("the first cadence wait", 8).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Run.IsCompleted, "the failing page").ConfigureAwait(false);
        await Check.ThrowsAsync<InvalidOperationException>(() => rig.Run, "the observer exception").ConfigureAwait(false);
        Check.Equal("n1", rig.Session.Cursor ?? string.Empty, "the cursor did not pass the failed page");
        Check.Equal(1UL, rig.Session.Tracker.Last ?? 0, "only the first hint was applied");

        rig.Observer.FailHint = null;
        var again = new EventPoller(rig.Session, rig.Transport, rig.Observer, rig.Time, () => 0.0, rig.Policy);
        rig.Transport.OnPoll(Make.PollPage("n3", Make.Hint(1), Make.Hint(2)));
        Task<WatchResult> run = again.RunAsync(rig.Cancel.Token);
        await Check.EventuallyAsync(() => rig.Session.Cursor == "n3", "the replayed page").ConfigureAwait(false);
        Check.Sequence([1UL, 2UL], rig.Observer.Hints.Select(hint => hint.Seq), "each hint was delivered exactly once across the retry");
        Check.Equal(1L, rig.Session.Tracker.Duplicates, "the replayed hint was discarded");
        Check.Sequence([null, "n1", "n1"], rig.Transport.PollCursors, "the retry polls the same cursor");
        await rig.Cancel.CancelAsync().ConfigureAwait(false);
        await run.ConfigureAwait(false);
    }

    private static async Task PollMalformedAndErrors()
    {
        (EventServicePollResponse Response, StopReason Expected, string Name)[] stops =
        [
            (new EventServicePollResponse { Value = new EventServicePollValue() }, StopReason.ProtocolViolation, "a page without a next cursor"),
            (new EventServicePollResponse { Value = new EventServicePollValue { NextCursor = string.Empty } }, StopReason.ProtocolViolation, "an empty next cursor"),
            (new EventServicePollResponse(), StopReason.ProtocolViolation, "a response without an outcome"),
            (new EventServicePollResponse { EncodedBody = new EncodedBodyRef() }, StopReason.ProtocolViolation, "an encoded body reference"),
            (new EventServicePollResponse { Error = Make.ErrorFrame(ErrorCategory.Authorization).Error }, StopReason.AuthorizationLost, "an authorization error"),
            (new EventServicePollResponse { Error = Make.ErrorFrame(ErrorCategory.Validation).Error }, StopReason.NonRetryable, "a validation error"),
        ];
        foreach ((EventServicePollResponse response, StopReason expected, string name) in stops)
        {
            var rig = new PollRig();
            rig.Transport.OnPoll(response);
            rig.Start();
            Check.Equal(expected, (await rig.FinishAsync().ConfigureAwait(false)).Reason, name);
            Check.Equal(1, rig.Transport.PollCalls, name + " is not retried");
        }

        var withEvents = new PollRig();
        withEvents.Transport.OnPoll(new EventServicePollResponse { Value = new EventServicePollValue { ResetRequired = true, NextCursor = "n", Events = { Make.Hint(1) } } });
        withEvents.Start();
        Check.Equal(StopReason.ProtocolViolation, (await withEvents.FinishAsync().ConfigureAwait(false)).Reason, "a reset page that carries hints");

        var timed = new PollRig();
        timed.Transport.OnPoll(new EventServicePollResponse { Error = Make.ErrorFrame(ErrorCategory.Resource, RetryMode.AfterTime, Make.At(timed.Time.GetUtcNow().AddSeconds(30))).Error });
        timed.Transport.OnPoll(Make.PollReset("n1"));
        timed.Start();
        await timed.PendingAsync("the server retry time", 30).ConfigureAwait(false);
        await timed.Time.AdvanceAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => timed.Transport.PollCalls == 2, "the retried Poll").ConfigureAwait(false);
        Check.Sequence([null, null], timed.Transport.PollCursors, "a retried Poll repeats the same cursor");
        await timed.StopAsync().ConfigureAwait(false);

        var status = new PollRig { Random = 1.0 };
        status.Transport.OnPoll((_, _) => throw new RpcException(new Status(StatusCode.Unavailable, "x")));
        status.Transport.OnPoll((_, _) => throw new RpcException(new Status(StatusCode.Unavailable, "x")));
        status.Transport.OnPoll(Make.PollReset("n1"));
        status.Start();
        await status.PendingAsync("the first backoff", 0.5).ConfigureAwait(false);
        await status.Time.AdvanceAsync(TimeSpan.FromSeconds(0.5)).ConfigureAwait(false);
        await status.PendingAsync("the second backoff climbs", 1).ConfigureAwait(false);
        await status.Time.AdvanceAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => status.Transport.PollCalls == 3, "the third Poll").ConfigureAwait(false);
        await status.PendingAsync("a success resets the ladder to the cadence", 12).ConfigureAwait(false);
        await status.StopAsync().ConfigureAwait(false);

        var denied = new PollRig();
        denied.Transport.OnPoll((_, _) => throw new RpcException(new Status(StatusCode.PermissionDenied, "x")));
        denied.Start();
        Check.Equal(StopReason.AuthorizationLost, (await denied.FinishAsync().ConfigureAwait(false)).Reason, "a PermissionDenied status");
        var unimplemented = new PollRig();
        unimplemented.Transport.OnPoll((_, _) => throw new RpcException(new Status(StatusCode.Unimplemented, "x")));
        unimplemented.Start();
        Check.Equal(StopReason.Unsupported, (await unimplemented.FinishAsync().ConfigureAwait(false)).Reason, "an Unimplemented status");
    }

    private static async Task PollResetWithCursor()
    {
        var rig = new PollRig();
        rig.Session.Cursor = "old";
        _ = rig.Session.Tracker.Evaluate(Make.Hint(4));
        rig.Session.Tracker.Accept(Make.Hint(4), rig.Session.Tracker.Evaluate(Make.Hint(4)));
        rig.Transport.OnPoll(Make.PollReset("n9"));
        rig.Start();
        await rig.PendingAsync("the cadence after the reset", 8).ConfigureAwait(false);
        Check.Sequence(["old"], rig.Transport.PollCursors, "the expired cursor was sent once");
        Check.Sequence(["Poll reset"], rig.Observer.Snapshots, "the snapshot reason");
        Check.Equal("n9", rig.Session.Cursor ?? string.Empty, "the new cursor");
        Check.True(rig.Session.Tracker.Last is null, "the baseline was cleared");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task PollNoOverlap()
    {
        var rig = new PollRig();
        int[] stage = [0];
        rig.Transport.OnPoll(async (_, _) =>
        {
            stage[0]++;
            for (int index = 0; index < 20; index++)
            {
                await Task.Yield();
            }

            return Make.PollReset("n1");
        });
        rig.Transport.OnPoll(async (_, _) =>
        {
            stage[0]++;
            for (int index = 0; index < 20; index++)
            {
                await Task.Yield();
            }

            return Make.PollPage("n2");
        });
        rig.Transport.OnPoll(async (_, _) =>
        {
            stage[0]++;
            await Task.Yield();
            return Make.PollPage("n3");
        });
        rig.Start();
        await rig.PendingAsync("the first cadence wait", 8).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        await rig.PendingAsync("the second cadence wait", 8).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        await rig.PendingAsync("the third cadence wait", 8).ConfigureAwait(false);
        Check.Equal(3, stage[0], "three Polls");
        Check.Equal(1, rig.Transport.MaximumConcurrentUnary, "the Polls never overlapped");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task PollWatchSwitch()
    {
        var rig = new PollRig();
        rig.Transport.OnPoll(Make.PollReset("n1"));
        rig.Transport.OnPoll(Make.PollPage("n3", Make.Hint(1), Make.Hint(2), Make.Hint(3)));
        rig.Start();
        await rig.PendingAsync("the first wait", 8).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Session.Cursor == "n3", "the page").ConfigureAwait(false);
        await rig.StopAsync().ConfigureAwait(false);

        var watcher = new EventWatcher(rig.Session, rig.Transport, rig.Observer, rig.Time, () => 0.0, rig.Policy);
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(3)), Step.Frame(Make.HintFrame(4)), Step.Hold);
        using var cancel = new CancellationTokenSource();
        Task<WatchResult> run = watcher.RunAsync(cancel.Token);
        await Check.EventuallyAsync(() => rig.Observer.Hints.Count == 4, "the stream hint after the switch").ConfigureAwait(false);
        Check.Sequence(["n3"], rig.Transport.WatchCursors, "the stream resumes from the Poll cursor");
        Check.Sequence([1UL, 2UL, 3UL, 4UL], rig.Observer.Hints.Select(hint => hint.Seq), "no hint was replayed or lost by the switch");
        Check.Equal(0, rig.Observer.Gaps.Count, "no gap across the switch");
        await cancel.CancelAsync().ConfigureAwait(false);
        await run.ConfigureAwait(false);
    }

    private static async Task PollInvalidHint()
    {
        var rig = new PollRig();
        rig.Transport.OnPoll(Make.PollReset("n1"));
        rig.Transport.OnPoll(Make.PollPage("n2", Make.Hint(1, "workspace:other")));
        rig.Start();
        await rig.PendingAsync("the first wait", 8).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        Check.Equal(StopReason.ProtocolViolation, (await rig.FinishAsync().ConfigureAwait(false)).Reason, "a hint outside the subscription");
        Check.Equal("n1", rig.Session.Cursor ?? string.Empty, "the cursor stays");
    }

    private static async Task PollCancellation()
    {
        var rig = new PollRig();
        rig.Transport.OnPoll(Make.PollReset("n1"));
        rig.Start();
        await rig.PendingAsync("the wait", 8).ConfigureAwait(false);
        Check.Equal(StopReason.Cancelled, (await rig.StopAsync().ConfigureAwait(false)).Reason, "cancelled");
        Check.Equal(0, rig.Time.Pending().Count, "no timer is left behind");
        var before = new PollRig();
        await before.Cancel.CancelAsync().ConfigureAwait(false);
        before.Start();
        Check.Equal(StopReason.Cancelled, (await before.FinishAsync().ConfigureAwait(false)).Reason, "cancelled before starting");
        Check.Equal(0, before.Transport.PollCalls, "nothing was polled");
    }

    private static async Task ReadCadence()
    {
        var rig = new ReadRig { Random = 0.0 };
        rig.Transport.OnReadOutput(Make.ReadPage("o2", null, Make.Chunk(0, "ab")));
        rig.Transport.OnReadOutput(Make.ReadPage("o2", Make.Terminal("final")));
        rig.Start();
        await Check.EventuallyAsync(() => rig.Time.Pending().SequenceEqual([TimeSpan.FromSeconds(4)]), "the 5 second cadence at the low jitter end").ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(3_999)).ConfigureAwait(false);
        Check.Equal(1, rig.Transport.ReadOutputCalls, "no read before the cadence elapsed");
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(1)).ConfigureAwait(false);
        WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
        Check.Equal(StopReason.Completed, result.Reason, "completed by the authoritative terminal");
        Check.Sequence([null, "o2"], rig.Transport.ReadOutputCursors, "the second read uses the first cursor");
        Check.Sequence([0UL], rig.Observer.Chunks.Select(chunk => chunk.Offset), "chunks");
        Check.Equal(1, rig.Observer.Terminals.Count, "one terminal");
        Check.Equal(1, rig.Transport.MaximumConcurrentUnary, "reads never overlap");
    }

    private static async Task ReadFailures()
    {
        var retry = new ReadRig { Random = 1.0 };
        retry.Transport.OnReadOutput((_, _) => throw new RpcException(new Status(StatusCode.Unavailable, "x")));
        retry.Transport.OnReadOutput(new ExecutionServiceReadOutputResponse { Error = Make.ErrorFrame(ErrorCategory.Resource).Error });
        retry.Transport.OnReadOutput(Make.ReadPage("o0"));
        retry.Start();
        await Check.EventuallyAsync(() => retry.Time.Pending().SequenceEqual([TimeSpan.FromSeconds(0.5)]), "the first backoff").ConfigureAwait(false);
        await retry.Time.AdvanceAsync(TimeSpan.FromSeconds(0.5)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => retry.Time.Pending().SequenceEqual([TimeSpan.FromSeconds(1)]), "the second backoff after a typed error").ConfigureAwait(false);
        await retry.Time.AdvanceAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => retry.Time.Pending().SequenceEqual([TimeSpan.FromSeconds(6)]), "a success returns to the cadence").ConfigureAwait(false);
        await retry.StopAsync().ConfigureAwait(false);

        var timed = new ReadRig();
        timed.Transport.OnReadOutput(new ExecutionServiceReadOutputResponse { Error = Make.ErrorFrame(ErrorCategory.Resource, RetryMode.AfterTime, Make.At(timed.Time.GetUtcNow().AddSeconds(25))).Error });
        timed.Start();
        await Check.EventuallyAsync(() => timed.Time.Pending().SequenceEqual([TimeSpan.FromSeconds(25)]), "the server retry time").ConfigureAwait(false);
        await timed.StopAsync().ConfigureAwait(false);

        (ExecutionServiceReadOutputResponse Response, StopReason Expected, string Name)[] stops =
        [
            (new ExecutionServiceReadOutputResponse { Error = Make.ErrorFrame(ErrorCategory.Authorization).Error }, StopReason.AuthorizationLost, "authorization"),
            (new ExecutionServiceReadOutputResponse { Error = Make.ErrorFrame(ErrorCategory.State).Error }, StopReason.NonRetryable, "state"),
            (new ExecutionServiceReadOutputResponse(), StopReason.ProtocolViolation, "no outcome"),
            (Make.ReadPage("o0", null, Make.Chunk(4, "gap")), StopReason.IntegrityViolation, "a gap"),
        ];
        foreach ((ExecutionServiceReadOutputResponse response, StopReason expected, string name) in stops)
        {
            var rig = new ReadRig();
            rig.Transport.OnReadOutput(response);
            rig.Start();
            Check.Equal(expected, (await rig.FinishAsync().ConfigureAwait(false)).Reason, name);
        }

        var reset = new ReadRig();
        reset.Session.Cursor = "stale";
        reset.Transport.OnReadOutput(Make.ReadReset());
        reset.Transport.OnReadOutput(Make.ReadPage("o1", null, Make.Chunk(0, "a")));
        reset.Start();
        await Check.EventuallyAsync(() => reset.Time.Pending().Count == 1, "the cadence after the reset").ConfigureAwait(false);
        await reset.Time.AdvanceAsync(TimeSpan.FromSeconds(4)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => reset.Transport.ReadOutputCalls == 2, "the read after the reset").ConfigureAwait(false);
        Check.Sequence(["stale", null], reset.Transport.ReadOutputCursors, "the reset drops the stale cursor");
        Check.Sequence(["ReadOutput required a reset"], reset.Observer.OutputResets, "the observer discards");
        await reset.StopAsync().ConfigureAwait(false);
    }
}
