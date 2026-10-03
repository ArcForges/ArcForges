// SPDX-License-Identifier: AGPL-3.0-only
// Test code runs on a console without a synchronization context and holds each fixture for the whole check, so these
// library-oriented rules do not apply here; the production-shaped files of this project keep them enabled.
#pragma warning disable CA1849, CA2007, CA2000, CA1508
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.PublicApi.V1;
using Grpc.Core;

namespace RealtimeAotProbe;

/// <summary>A watcher, its scripted transport, an observer and a manual clock, with no real time anywhere.</summary>
internal sealed class WatchRig
{
    public WatchRig()
    {
        Transport = new ScriptedTransport(Time);
        Watcher = new EventWatcher(Session, Transport, Observer, Time, () => Random, Policy);
    }

    public ManualTimeProvider Time { get; } = new();

    public ScriptedTransport Transport { get; }

    public RecordingObserver Observer { get; } = new();

    public RealtimePolicy Policy { get; } = new();

    public EventSession Session { get; } = new(Make.Key);

    public EventWatcher Watcher { get; }

    public CancellationTokenSource Cancel { get; } = new();

    public double Random { get; set; } = 1.0;

    public Task<WatchResult> Run { get; private set; } = Task.FromResult(default(WatchResult));

    public WatchRig Start()
    {
        Run = Watcher.RunAsync(Cancel.Token);
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

/// <summary>Reconnect, silence, reset, snapshot, gap and stop behavior of <c>EventService.Watch</c> and <c>WatchOutput</c>.</summary>
internal static class SelfTestStreams
{
    private static RpcException Rpc(StatusCode code) => new(new Status(code, "test"));

    public static void Register(SelfTestRunner runner)
    {
        ArgumentNullException.ThrowIfNull(runner);
        runner.Add("watch: no cursor yields a reset, the snapshot is read once, then the stream resumes after its high water", FirstConnectionSnapshot);
        runner.Add("watch: hints apply in order, the cursor follows the frames and a reconnect resumes it without replay", ReconnectResumesCursor);
        runner.Add("watch: a heartbeat position does not advance the cursor", HeartbeatDoesNotAdvance);
        runner.Add("watch: a sequence gap is recorded, reported to the observer and the hint still delivered", GapRecorded);
        runner.Add("watch: a reset that needs no snapshot resumes from its cursor and clears the baseline", ResetWithoutSnapshot);
        runner.Add("watch: a conflicting duplicate is an integrity failure", ConflictingDuplicate);
        runner.Add("watch: hints outside scope, without sequence or without payload stop the stream", InvalidHints);
        runner.Add("watch: output, terminal, progress and empty frames do not belong on the events stream", WrongVariants);
        runner.Add("watch: permission failures stop and are never retried", PermissionStops);
        runner.Add("watch: unsupported and non-retryable refusals stop", UnsupportedAndNonRetryable);
        runner.Add("watch: reconnect delays climb from 0.5 seconds and the ladder resets at 30 seconds of connectivity", ReconnectLadder);
        runner.Add("watch: 45 seconds of silence reconnects, 44.999 does not", SilenceBoundary);
        runner.Add("watch: a frame at 44.999 seconds and a heartbeat both restart the silence clock", SilenceRestarts);
        runner.Add("watch: a server retry time longer than the backoff is honored", RetryAfterHonored);
        runner.Add("watch: connection states report reconnecting, never stopped, while retrying", ConnectionStates);
        runner.Add("watch: cancelling during a read or a backoff ends the run without another connection", Cancellation);
        runner.Add("watch: an observer failure propagates and leaves the hint unapplied", ObserverFailure);
        runner.Add("output: chunks append in order and the cursor follows them", OutputAppends);
        runner.Add("output: a terminal frame completes only when the authoritative read returns the terminal", OutputTerminalConfirmed);
        runner.Add("output: an unconfirmed terminal reconnects and completes only later", OutputTerminalUnconfirmed);
        runner.Add("output: stream and authoritative terminals that disagree are an integrity failure", OutputTerminalDisagree);
        runner.Add("output: a dropped stream recovers missed chunks through ReadOutput and never completes", OutputDropRecovers);
        runner.Add("output: a gap is filled from the authoritative read, not invented", OutputGapRecovers);
        runner.Add("output: a recovery that appends nothing ends instead of spinning", OutputRecoveryProgress);
        runner.Add("output: a reset restarts the output from offset zero through ReadOutput", OutputReset);
        runner.Add("output: a ReadOutput that keeps requiring a reset backs off", OutputResetLoop);
        runner.Add("output: conflicts, oversize chunks and foreign owners stop the stream", OutputViolations);
        runner.Add("output: errors during recovery stop or delay by their typed class", OutputRecoveryErrors);
        runner.Add("output: ReadOutput page bounds and gaps are enforced", OutputPageBounds);
    }

    private static async Task FirstConnectionSnapshot()
    {
        var rig = new WatchRig { Random = 0.0 };
        rig.Transport.OnWatch(Step.Frame(Make.Reset("expired", true, "hw1")), Step.End);
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(5, "c5")), Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Observer.Hints.Count == 1, "the hint after the snapshot").ConfigureAwait(false);
        Check.Sequence([null, "hw1"], rig.Transport.WatchCursors, "watch cursors");
        Check.Sequence(["expired"], rig.Observer.Snapshots, "snapshots");
        Check.Equal(1L, rig.Session.Snapshots, "snapshot counter");
        Check.True(rig.Observer.Log.ToList().IndexOf("snapshot:expired") < rig.Observer.Log.ToList().IndexOf("hint:5"), "the snapshot is read before the first hint");
        Check.Equal(5UL, rig.Session.Tracker.Last ?? 0, "the first hint after a reset is the baseline");
        Check.Equal("c5", rig.Session.Cursor ?? string.Empty, "cursor");
        Check.Equal(StopReason.Cancelled, (await rig.StopAsync().ConfigureAwait(false)).Reason, "stop");
    }

    private static async Task ReconnectResumesCursor()
    {
        var rig = new WatchRig { Random = 0.0 };
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.Frame(Make.HintFrame(2)), Step.End);
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(2)), Step.Frame(Make.HintFrame(3)), Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Observer.Hints.Count == 3, "three hints").ConfigureAwait(false);
        Check.Sequence([1UL, 2UL, 3UL], rig.Observer.Hints.Select(hint => hint.Seq), "hints delivered once each, in order");
        Check.Sequence([null, "c2"], rig.Transport.WatchCursors, "the reconnect resumes the last cursor");
        Check.Equal(0, rig.Observer.Gaps.Count, "no gap across the reconnect");
        Check.Equal(1L, rig.Session.Tracker.Duplicates, "the replayed hint was discarded");
        Check.Equal(1L, rig.Watcher.Reconnects, "one reconnect");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task HeartbeatDoesNotAdvance()
    {
        var rig = new WatchRig { Random = 0.0 };
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1, "c1")), Step.Frame(Make.Heartbeat("hb")), Step.End);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Transport.WatchCalls == 2, "the reconnect").ConfigureAwait(false);
        Check.Sequence([null, "c1"], rig.Transport.WatchCursors, "cursors");
        Check.Equal(1L, rig.Watcher.Heartbeats, "heartbeat counted");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task GapRecorded()
    {
        var rig = new WatchRig();
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.Frame(Make.HintFrame(3)), Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Observer.Hints.Count == 2, "both hints").ConfigureAwait(false);
        Check.Equal(1, rig.Observer.Gaps.Count, "one gap");
        Check.Equal(new SequenceGap(Make.Key, 2, 3), rig.Observer.Gaps[0], "gap detail");
        Check.Equal(1L, rig.Session.Tracker.Gaps, "gap counter");
        Check.True(rig.Observer.Log.ToList().IndexOf("gap:2-3") < rig.Observer.Log.ToList().IndexOf("hint:3"), "the gap is reported before the hint");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task ResetWithoutSnapshot()
    {
        var rig = new WatchRig { Random = 0.0 };
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.Frame(Make.HintFrame(2)), Step.Frame(Make.Reset("gap", false, "r9")));
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(7)), Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Observer.Hints.Count == 3, "the hint after the reset").ConfigureAwait(false);
        Check.Sequence([null, "r9"], rig.Transport.WatchCursors, "the reset cursor is resumed");
        Check.Equal(0, rig.Observer.Snapshots.Count, "no snapshot was required");
        Check.Equal(0, rig.Observer.Gaps.Count, "the baseline was cleared by the reset");
        Check.Equal(1L, rig.Watcher.Resets, "reset counted");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task ConflictingDuplicate()
    {
        var rig = new WatchRig();
        var different = new StreamFrame { Position = Make.Position("c1", 1), Hint = new Event { SubscriptionKey = Make.Key, Seq = 1, TaskProgress = new TaskProgress() } };
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.Frame(different));
        rig.Start();
        WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
        Check.Equal(StopReason.IntegrityViolation, result.Reason, "reason");
        Check.Equal(1, rig.Observer.Hints.Count, "the conflicting hint was not delivered");
        Check.Equal(1, rig.Transport.WatchCalls, "an integrity failure is not retried");
    }

    private static async Task InvalidHints()
    {
        var noSeq = new Event { SubscriptionKey = Make.Key, SyncChanged = new SyncChanged() };
        var noKey = new Event { Seq = 1, SyncChanged = new SyncChanged() };
        StreamFrame[] frames =
        [
            Make.HintFrame(1, null, "workspace:other"),
            new StreamFrame { Hint = noSeq },
            new StreamFrame { Hint = noKey },
            new StreamFrame { Hint = Make.Hint(1, payload: false) },
        ];
        foreach (StreamFrame frame in frames)
        {
            var rig = new WatchRig();
            rig.Transport.OnWatch(Step.Frame(frame));
            rig.Start();
            WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
            Check.Equal(StopReason.ProtocolViolation, result.Reason, "reason for " + result.Detail);
            Check.Equal(0, rig.Observer.Hints.Count, "nothing is delivered: " + result.Detail);
        }
    }

    private static async Task WrongVariants()
    {
        StreamFrame[] frames =
        [
            Make.ChunkFrame(0, "a"),
            Make.TerminalFrame(),
            new StreamFrame { Progress = new ExecutionProgress { Execution = Make.Owner() } },
            new StreamFrame(),
        ];
        foreach (StreamFrame frame in frames)
        {
            var rig = new WatchRig();
            rig.Transport.OnWatch(Step.Frame(frame));
            rig.Start();
            WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
            Check.Equal(StopReason.ProtocolViolation, result.Reason, "reason for " + frame.FrameCase);
            Check.Equal(1, rig.Transport.WatchCalls, "no retry for " + frame.FrameCase);
        }
    }

    private static async Task PermissionStops()
    {
        (Step Step, string Name)[] cases =
        [
            (Step.Frame(Make.Reset("permissionChanged", true, "x")), "permissionChanged reset"),
            (Step.Frame(Make.ErrorFrame(ErrorCategory.Authorization)), "authorization error frame"),
            (Step.Frame(Make.ErrorFrame(ErrorCategory.Authentication, RetryMode.AfterTime)), "authentication error with retry advice"),
            (Step.Fail(Rpc(StatusCode.Unauthenticated)), "Unauthenticated status"),
            (Step.Fail(Rpc(StatusCode.PermissionDenied)), "PermissionDenied status"),
        ];
        foreach ((Step step, string name) in cases)
        {
            var rig = new WatchRig();
            rig.Transport.OnWatch(step);
            rig.Start();
            WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
            Check.Equal(StopReason.AuthorizationLost, result.Reason, name);
            Check.Equal(1, rig.Transport.WatchCalls, name + " is never retried");
            Check.Equal(0, rig.Observer.Snapshots.Count, name + " reads no snapshot");
            Check.Equal(ConnectionState.Stopped, rig.Observer.States[^1], name + " ends stopped");
        }
    }

    private static async Task UnsupportedAndNonRetryable()
    {
        (Step Step, StopReason Reason, string Name)[] cases =
        [
            (Step.Fail(Rpc(StatusCode.Unimplemented)), StopReason.Unsupported, "Unimplemented"),
            (Step.Fail(Rpc(StatusCode.InvalidArgument)), StopReason.NonRetryable, "InvalidArgument"),
            (Step.Frame(Make.ErrorFrame(ErrorCategory.Validation)), StopReason.NonRetryable, "validation error frame"),
            (Step.Frame(Make.ErrorFrame(ErrorCategory.Resource, RetryMode.Never)), StopReason.NonRetryable, "retry never"),
            (Step.Frame(new StreamFrame { Error = new ArcError() }), StopReason.NonRetryable, "an error without a category"),
            (Step.Fail(Make.Malformed()), StopReason.ProtocolViolation, "malformed message"),
        ];
        foreach ((Step step, StopReason expected, string name) in cases)
        {
            var rig = new WatchRig();
            rig.Transport.OnWatch(step);
            rig.Start();
            WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
            Check.Equal(expected, result.Reason, name);
            Check.Equal(1, rig.Transport.WatchCalls, name + " is not retried");
        }
    }

    private static async Task ReconnectLadder()
    {
        var rig = new WatchRig();
        rig.Transport.OnWatch(Step.Fail(Rpc(StatusCode.Unavailable)));
        rig.Transport.OnWatch(Step.After(TimeSpan.FromMilliseconds(29_999)), Step.Fail(Rpc(StatusCode.Unavailable)));
        rig.Transport.OnWatch(Step.After(TimeSpan.FromSeconds(30)), Step.Fail(Rpc(StatusCode.Unavailable)));
        rig.Transport.OnWatch(Step.Fail(Rpc(StatusCode.Unavailable)));
        rig.Start();
        await rig.PendingAsync("the first reconnect delay of 0.5 seconds", 0.5).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(499)).ConfigureAwait(false);
        Check.Equal(1, rig.Transport.WatchCalls, "no early reconnect");
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(1)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Transport.WatchCalls == 2, "the second connection").ConfigureAwait(false);

        // The second connection lived 29.999 seconds: not stable, so the ceiling doubles to 1 second.
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(29_999)).ConfigureAwait(false);
        await rig.PendingAsync("the second reconnect delay of 1 second", 1).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Transport.WatchCalls == 3, "the third connection").ConfigureAwait(false);

        // The third connection lived exactly 30 seconds: stable, so the ladder restarts at 0.5 seconds.
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        await rig.PendingAsync("the reconnect delay after a stable connection", 0.5).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(0.5)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Transport.WatchCalls == 4, "the fourth connection").ConfigureAwait(false);
        await rig.PendingAsync("the next delay climbs again", 1).ConfigureAwait(false);
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task SilenceBoundary()
    {
        var rig = new WatchRig();
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Observer.Hints.Count == 1, "the hint").ConfigureAwait(false);
        await rig.PendingAsync("the 45 second silence timer", 45).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(44_999)).ConfigureAwait(false);
        Check.Equal(0L, rig.Watcher.Silences, "44.999 seconds is not silence");
        Check.Equal(1, rig.Transport.WatchCalls, "no reconnect at 44.999 seconds");
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(1)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Watcher.Silences == 1, "silence at 45 seconds").ConfigureAwait(false);
        await rig.PendingAsync("a stable connection resets the ladder, so the delay is 0.5 seconds", 0.5).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromSeconds(0.5)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Transport.WatchCalls == 2, "the reconnect").ConfigureAwait(false);
        Check.Sequence([null, "c1"], rig.Transport.WatchCursors, "the reconnect resumes the cursor");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task SilenceRestarts()
    {
        var late = new WatchRig();
        late.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.After(TimeSpan.FromMilliseconds(44_999)), Step.Frame(Make.HintFrame(2)), Step.Hold);
        late.Start();
        await Check.EventuallyAsync(() => late.Observer.Hints.Count == 1, "the first hint").ConfigureAwait(false);
        await late.Time.AdvanceAsync(TimeSpan.FromMilliseconds(44_999)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => late.Observer.Hints.Count == 2, "the late hint").ConfigureAwait(false);
        Check.Equal(0L, late.Watcher.Silences, "a frame at 44.999 seconds keeps the stream");
        await late.PendingAsync("the silence clock restarted", 45).ConfigureAwait(false);
        await late.StopAsync().ConfigureAwait(false);

        var beat = new WatchRig();
        beat.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.After(TimeSpan.FromSeconds(44)), Step.Frame(Make.Heartbeat()), Step.Hold);
        beat.Start();
        await beat.PendingAsync("the delay and the silence timer", 44, 45).ConfigureAwait(false);
        await beat.Time.AdvanceAsync(TimeSpan.FromSeconds(44)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => beat.Watcher.Heartbeats == 1, "the heartbeat").ConfigureAwait(false);
        await beat.PendingAsync("the heartbeat restarted the silence clock", 45).ConfigureAwait(false);
        await beat.Time.AdvanceAsync(TimeSpan.FromMilliseconds(44_999)).ConfigureAwait(false);
        Check.Equal(0L, beat.Watcher.Silences, "still within 45 seconds of the heartbeat");
        await beat.StopAsync().ConfigureAwait(false);
    }

    private static async Task RetryAfterHonored()
    {
        var rig = new WatchRig();
        rig.Transport.OnWatch(Step.Frame(Make.ErrorFrame(ErrorCategory.Resource, RetryMode.AfterTime, Make.At(rig.Time.GetUtcNow().AddSeconds(20)))));
        rig.Start();
        await rig.PendingAsync("the server retry time of 20 seconds beats the 0.5 second ladder", 20).ConfigureAwait(false);
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(19_999)).ConfigureAwait(false);
        Check.Equal(1, rig.Transport.WatchCalls, "not before the server retry time");
        await rig.Time.AdvanceAsync(TimeSpan.FromMilliseconds(1)).ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Transport.WatchCalls == 2, "the reconnect at the retry time").ConfigureAwait(false);
        await rig.StopAsync().ConfigureAwait(false);

        var small = new WatchRig();
        small.Transport.OnWatch(Step.Frame(Make.ErrorFrame(ErrorCategory.Resource, RetryMode.AfterTime, Make.At(small.Time.GetUtcNow().AddSeconds(0)))));
        small.Start();
        await small.PendingAsync("a retry time already due leaves the ladder delay", 0.5).ConfigureAwait(false);
        await small.StopAsync().ConfigureAwait(false);
    }

    private static async Task ConnectionStates()
    {
        var rig = new WatchRig { Random = 0.0 };
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.End);
        rig.Transport.OnWatch(Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Transport.WatchCalls == 2, "the reconnect").ConfigureAwait(false);
        await Check.EventuallyAsync(() => rig.Observer.Count(states => states.Count) >= 4, "the states").ConfigureAwait(false);
        Check.Sequence([ConnectionState.Connecting, ConnectionState.Live, ConnectionState.Reconnecting, ConnectionState.Connecting], rig.Observer.States.Take(4), "state sequence");
        Check.True(!rig.Observer.States.Contains(ConnectionState.Stopped), "a drop is never reported as stopped");
        await rig.StopAsync().ConfigureAwait(false);
        Check.Equal(ConnectionState.Stopped, rig.Observer.States[^1], "stopped only after the caller stops");
    }

    private static async Task Cancellation()
    {
        var reading = new WatchRig();
        reading.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.Hold);
        reading.Start();
        await Check.EventuallyAsync(() => reading.Observer.Hints.Count == 1, "the hint").ConfigureAwait(false);
        Check.Equal(StopReason.Cancelled, (await reading.StopAsync().ConfigureAwait(false)).Reason, "cancelled while reading");
        Check.Equal(1, reading.Transport.WatchCalls, "no connection after cancellation");
        Check.Equal(0, reading.Time.Pending().Count, "no timer is left behind");

        var waiting = new WatchRig();
        waiting.Transport.OnWatch(Step.Fail(Rpc(StatusCode.Unavailable)));
        waiting.Start();
        await waiting.PendingAsync("the backoff delay", 0.5).ConfigureAwait(false);
        Check.Equal(StopReason.Cancelled, (await waiting.StopAsync().ConfigureAwait(false)).Reason, "cancelled while backing off");
        Check.Equal(1, waiting.Transport.WatchCalls, "no connection after cancellation");
        Check.Equal(0, waiting.Time.Pending().Count, "the delay timer is released");

        var before = new WatchRig();
        await before.Cancel.CancelAsync().ConfigureAwait(false);
        before.Start();
        Check.Equal(StopReason.Cancelled, (await before.FinishAsync().ConfigureAwait(false)).Reason, "cancelled before starting");
        Check.Equal(0, before.Transport.WatchCalls, "nothing was opened");
    }

    private static async Task ObserverFailure()
    {
        var rig = new WatchRig();
        rig.Observer.FailHint = hint => hint.Seq == 2 ? new InvalidOperationException("consumer failed") : null;
        rig.Transport.OnWatch(Step.Frame(Make.HintFrame(1)), Step.Frame(Make.HintFrame(2)), Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Run.IsCompleted, "the failing run").ConfigureAwait(false);
        await Check.ThrowsAsync<InvalidOperationException>(() => rig.Run, "the observer exception").ConfigureAwait(false);
        Check.Equal(1UL, rig.Session.Tracker.Last ?? 0, "the failed hint was not applied");
        Check.Equal("c1", rig.Session.Cursor ?? string.Empty, "the cursor did not pass the failed hint");
    }

    private sealed class OutputRig
    {
        public OutputRig()
        {
            Transport = new ScriptedTransport(Time);
            Session = new OutputSession(Make.Owner(), Policy);
            Watcher = new OutputWatcher(Session, Transport, Observer, Time, () => Random, Policy);
        }

        public ManualTimeProvider Time { get; } = new();

        public ScriptedTransport Transport { get; }

        public RecordingObserver Observer { get; } = new();

        public RealtimePolicy Policy { get; } = new();

        public OutputSession Session { get; }

        public OutputWatcher Watcher { get; }

        public double Random { get; set; }

        public Task<WatchResult> Run { get; private set; } = Task.FromResult(default(WatchResult));

        public CancellationTokenSource Cancel { get; } = new();

        public Task PendingAsync(string what, params double[] seconds) =>
            Check.EventuallyAsync(() => Time.Pending().SequenceEqual(seconds.Select(TimeSpan.FromSeconds)), what + " (pending timers " + string.Join(",", Time.Pending()) + ")");

        public OutputRig Start()
        {
            Run = Watcher.RunAsync(Cancel.Token);
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

    private static ExecutionServiceReadOutputResponse ReadError(ErrorCategory category, RetryMode? mode = null, Instant? at = null) =>
        new() { Error = Make.ErrorFrame(category, mode, at).Error };

    private static async Task OutputAppends()
    {
        var rig = new OutputRig();
        rig.Transport.OnWatchOutput(Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(Make.ChunkFrame(2, "cde")), Step.Frame(new StreamFrame { Progress = new ExecutionProgress { Execution = Make.Owner() } }), Step.Hold);
        rig.Start();
        await Check.EventuallyAsync(() => rig.Observer.Chunks.Count == 2 && rig.Session.Progress == 1, "two chunks and the progress frame").ConfigureAwait(false);
        Check.Sequence([0UL, 2UL], rig.Observer.Chunks.Select(chunk => chunk.Offset), "chunk offsets");
        Check.Equal("o5", rig.Session.Cursor ?? string.Empty, "cursor");
        Check.Equal(5UL, rig.Session.Tracker.NextOffset, "next offset");
        Check.Equal(0, rig.Observer.Terminals.Count, "progress is display only and completes nothing");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task OutputTerminalConfirmed()
    {
        var rig = new OutputRig();
        rig.Transport.OnWatchOutput(Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(Make.TerminalFrame("final")));
        rig.Transport.OnReadOutput(Make.ReadPage("o2", Make.Terminal("final")));
        rig.Start();
        WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
        Check.Equal(StopReason.Completed, result.Reason, "completed");
        Check.Equal(1, rig.Observer.Terminals.Count, "one confirmed terminal");
        Check.Sequence(["o2"], rig.Transport.ReadOutputCursors, "the confirmation reads from the verified cursor");
        Check.Equal(ConnectionState.Stopped, rig.Observer.States[^1], "stopped after completion");
    }

    private static async Task OutputTerminalUnconfirmed()
    {
        var rig = new OutputRig();
        rig.Transport.OnWatchOutput(Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(Make.TerminalFrame("final")));
        rig.Transport.OnWatchOutput(Step.Frame(Make.TerminalFrame("final")));
        rig.Transport.OnReadOutput(Make.ReadPage("o2"));
        rig.Transport.OnReadOutput(Make.ReadPage("o2", Make.Terminal("final")));
        rig.Start();
        WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
        Check.Equal(StopReason.Completed, result.Reason, "completed only after the second confirmation");
        Check.Equal(2, rig.Transport.WatchOutputCalls, "the stream was reopened after the unconfirmed terminal");
        Check.Equal(2, rig.Transport.ReadOutputCalls, "two authoritative reads");
        Check.True(rig.Observer.States.Contains(ConnectionState.Reconnecting), "the unconfirmed terminal was shown as reconnecting");
        Check.Equal(1, rig.Observer.Terminals.Count, "the terminal is reported once");
    }

    private static async Task OutputTerminalDisagree()
    {
        (ExecutionOutput Stream, ExecutionOutput Read, StopReason Expected, string Name)[] cases =
        [
            (Make.Terminal("A"), Make.Terminal("B"), StopReason.IntegrityViolation, "different final hash"),
            (Make.Terminal("A", "completed"), Make.Terminal("A", "failed"), StopReason.IntegrityViolation, "different state"),
            (new ExecutionOutput { Execution = Make.Owner(), State = "completed" }, Make.Terminal("B"), StopReason.Completed, "a stream terminal without a hash does not disagree"),
            (new ExecutionOutput { Execution = Make.Owner(), FinalHash = "A" }, new ExecutionOutput { Execution = Make.Owner(), FinalHash = "A", State = "completed" }, StopReason.Completed, "a stream terminal without a state does not disagree"),
            (Make.Terminal("A"), new ExecutionOutput { Execution = Make.Owner(), State = "completed" }, StopReason.Completed, "an authoritative terminal without a hash does not disagree"),
            (Make.Terminal("A", "completed"), new ExecutionOutput { Execution = Make.Owner(), FinalHash = "A" }, StopReason.Completed, "an authoritative terminal without a state does not disagree"),
            (Make.Terminal("A"), Make.Terminal("A"), StopReason.Completed, "agreeing terminals"),
        ];
        foreach ((ExecutionOutput stream, ExecutionOutput read, StopReason expected, string name) in cases)
        {
            var rig = new OutputRig();
            rig.Transport.OnWatchOutput(Step.Frame(new StreamFrame { Terminal = stream }));
            rig.Transport.OnReadOutput(Make.ReadPage("o0", read));
            rig.Start();
            WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
            Check.Equal(expected, result.Reason, name);
            Check.Equal(expected == StopReason.Completed ? 1 : 0, rig.Observer.Terminals.Count, name + ": terminals reported");
        }
    }

    private static async Task OutputDropRecovers()
    {
        var rig = new OutputRig();
        rig.Transport.OnWatchOutput(Step.Frame(Make.ChunkFrame(0, "ab")), Step.End);
        rig.Transport.OnReadOutput(Make.ReadPage("o4", null, Make.Chunk(2, "cd")));
        rig.Transport.OnReadOutput(Make.ReadPage("o4"));
        rig.Start();
        await Check.EventuallyAsync(() => rig.Transport.WatchOutputCalls == 2, "the reconnect").ConfigureAwait(false);
        Check.Sequence([0UL, 2UL], rig.Observer.Chunks.Select(chunk => chunk.Offset), "the missed chunk was read");
        Check.Sequence(["o2", "o4"], rig.Transport.ReadOutputCursors, "recovery reads until caught up");
        Check.Sequence([null, "o4"], rig.Transport.WatchOutputCursors, "the stream resumes after the recovered cursor");
        Check.True(!rig.Run.IsCompleted, "a dropped stream without a terminal outcome is never complete");
        Check.True(rig.Observer.States.Contains(ConnectionState.Reconnecting), "the drop is shown as reconnecting");
        Check.Equal(0, rig.Observer.Terminals.Count, "no terminal was invented");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task OutputGapRecovers()
    {
        var rig = new OutputRig();
        rig.Transport.OnWatchOutput(Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(Make.ChunkFrame(6, "gh", "o8")));
        rig.Transport.OnReadOutput(Make.ReadPage("o6", null, Make.Chunk(2, "cdef")));
        rig.Transport.OnReadOutput(Make.ReadPage("o6"));
        rig.Start();
        await Check.EventuallyAsync(() => rig.Transport.WatchOutputCalls == 2, "the reconnect").ConfigureAwait(false);
        Check.Sequence([0UL, 2UL], rig.Observer.Chunks.Select(chunk => chunk.Offset), "the gap chunk was not delivered ahead of the missing bytes");
        Check.Equal(1L, rig.Session.Tracker.Gaps, "gap counted");
        Check.Sequence([null, "o6"], rig.Transport.WatchOutputCursors, "the stream resumes from the authoritative cursor");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task OutputRecoveryProgress()
    {
        var rig = new OutputRig { Random = 1.0 };
        rig.Transport.OnWatchOutput(Step.End);
        rig.Transport.OnReadOutput(Make.ReadPage("o2", null, Make.Chunk(0, "ab")));
        rig.Transport.OnReadOutput(Make.ReadPage("o2", null, Make.Chunk(0, "ab")));
        rig.Start();
        await rig.PendingAsync("the backoff after a recovery that stopped making progress", 0.5).ConfigureAwait(false);
        Check.Equal(2, rig.Transport.ReadOutputCalls, "the repeated page ended the recovery loop");
        Check.Equal(1L, rig.Session.Tracker.Duplicates, "the repeated chunk was discarded as a duplicate");
        Check.Sequence([0UL], rig.Observer.Chunks.Select(chunk => chunk.Offset), "the chunk was delivered once");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task OutputReset()
    {
        var rig = new OutputRig();
        rig.Transport.OnWatchOutput(Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(Make.Reset("expired", true, "zz")));
        rig.Transport.OnReadOutput(Make.ReadPage("o2", null, Make.Chunk(0, "ab")));
        rig.Transport.OnReadOutput(Make.ReadPage("o2"));
        rig.Start();
        await Check.EventuallyAsync(() => rig.Transport.WatchOutputCalls == 2, "the reconnect").ConfigureAwait(false);
        Check.Sequence(["expired"], rig.Observer.OutputResets, "the observer discarded what it displayed");
        Check.Sequence([null, "o2"], rig.Transport.ReadOutputCursors, "the output is read again from the start, not from the reset cursor");
        Check.Sequence([0UL, 0UL], rig.Observer.Chunks.Select(chunk => chunk.Offset), "the restarted output replays from offset zero");
        Check.Equal(1L, rig.Session.Restarts, "restart counted");
        Check.Sequence([null, "o2"], rig.Transport.WatchOutputCursors, "the stream resumes after the re-read");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task OutputResetLoop()
    {
        var rig = new OutputRig();
        rig.Transport.OnWatchOutput(Step.End);
        rig.Transport.OnReadOutput(Make.ReadReset());
        rig.Transport.OnReadOutput(Make.ReadReset());
        rig.Start();
        await Check.EventuallyAsync(() => rig.Transport.WatchOutputCalls == 2, "the reconnect after the second reset").ConfigureAwait(false);
        Check.Equal(2, rig.Transport.ReadOutputCalls, "one restart is allowed per recovery");
        Check.Equal(2L, rig.Session.Restarts, "both resets restarted the output");
        Check.Equal(2, rig.Observer.OutputResets.Count, "the observer discarded twice");
        Check.True(!rig.Run.IsCompleted, "the run continues through the backoff");
        await rig.StopAsync().ConfigureAwait(false);
    }

    private static async Task OutputViolations()
    {
        string oversize = new('a', 32 * 1024 + 1);
        string atBound = new('a', 32 * 1024);
        (Step[] Steps, StopReason Expected, string Name)[] stops =
        [
            ([Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(new StreamFrame { Output = Make.Chunk(0, "xy") })], StopReason.IntegrityViolation, "different bytes at a received offset"),
            ([Step.Frame(new StreamFrame { Output = Make.Chunk(0, oversize) })], StopReason.ProtocolViolation, "a chunk over 32 KiB"),
            ([Step.Frame(Make.ChunkFrame(0, "a", null, 8))], StopReason.ProtocolViolation, "a chunk for another owner"),
            ([Step.Frame(new StreamFrame { Progress = new ExecutionProgress { Execution = Make.Owner(8) } })], StopReason.ProtocolViolation, "progress for another owner"),
            ([Step.Frame(new StreamFrame { Progress = new ExecutionProgress() })], StopReason.ProtocolViolation, "progress without an owner"),
            ([Step.Frame(Make.TerminalFrame("f", "completed", 8))], StopReason.ProtocolViolation, "a terminal for another owner"),
            ([Step.Frame(new StreamFrame { Terminal = new ExecutionOutput() })], StopReason.ProtocolViolation, "a terminal without an owner"),
            ([Step.Frame(Make.HintFrame(1))], StopReason.ProtocolViolation, "a hint on the output stream"),
            ([Step.Frame(new StreamFrame())], StopReason.ProtocolViolation, "an empty frame"),
            ([Step.Frame(Make.Reset("permissionChanged", true))], StopReason.AuthorizationLost, "a permission reset"),
            ([Step.Frame(Make.ErrorFrame(ErrorCategory.Authorization))], StopReason.AuthorizationLost, "an authorization error"),
            ([Step.Fail(Rpc(StatusCode.Unimplemented))], StopReason.Unsupported, "an unimplemented stream"),
        ];
        foreach ((Step[] steps, StopReason expected, string name) in stops)
        {
            var rig = new OutputRig();
            rig.Transport.OnWatchOutput(steps);
            rig.Start();
            WatchResult result = await rig.FinishAsync().ConfigureAwait(false);
            Check.Equal(expected, result.Reason, name);
            Check.Equal(0, rig.Transport.ReadOutputCalls, name + " stops without a recovery read");
        }

        var ok = new OutputRig();
        ok.Transport.OnWatchOutput(Step.Frame(new StreamFrame { Output = Make.Chunk(0, atBound) }), Step.Hold);
        ok.Start();
        await Check.EventuallyAsync(() => ok.Observer.Chunks.Count == 1, "a chunk at the 32 KiB bound").ConfigureAwait(false);
        await ok.StopAsync().ConfigureAwait(false);

        var duplicate = new OutputRig();
        duplicate.Transport.OnWatchOutput(Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(Make.ChunkFrame(0, "ab")), Step.Frame(Make.ChunkFrame(2, "c")), Step.Hold);
        duplicate.Start();
        await Check.EventuallyAsync(() => duplicate.Observer.Chunks.Count == 2, "the chunks around an identical duplicate").ConfigureAwait(false);
        Check.Equal(1L, duplicate.Session.Tracker.Duplicates, "the identical duplicate was discarded");
        await duplicate.StopAsync().ConfigureAwait(false);
    }

    private static async Task OutputRecoveryErrors()
    {
        var auth = new OutputRig();
        auth.Transport.OnWatchOutput(Step.End);
        auth.Transport.OnReadOutput(ReadError(ErrorCategory.Authorization));
        auth.Start();
        Check.Equal(StopReason.AuthorizationLost, (await auth.FinishAsync().ConfigureAwait(false)).Reason, "an authorization error in recovery");

        var validation = new OutputRig();
        validation.Transport.OnWatchOutput(Step.End);
        validation.Transport.OnReadOutput(ReadError(ErrorCategory.Validation));
        validation.Start();
        Check.Equal(StopReason.NonRetryable, (await validation.FinishAsync().ConfigureAwait(false)).Reason, "a validation error in recovery");

        var timed = new OutputRig();
        timed.Transport.OnWatchOutput(Step.End);
        timed.Transport.OnReadOutput(ReadError(ErrorCategory.Resource, RetryMode.AfterTime, Make.At(timed.Time.GetUtcNow().AddSeconds(20))));
        timed.Start();
        await Check.EventuallyAsync(() => timed.Time.Pending().SequenceEqual([TimeSpan.FromSeconds(20)]), "the server retry time").ConfigureAwait(false);
        await timed.StopAsync().ConfigureAwait(false);

        var status = new OutputRig { Random = 1.0 };
        status.Transport.OnWatchOutput(Step.End);
        status.Transport.OnReadOutput((_, _) => throw Rpc(StatusCode.Unavailable));
        status.Start();
        await Check.EventuallyAsync(() => status.Time.Pending().Count == 1, "a retryable status in recovery").ConfigureAwait(false);
        Check.Equal(1, status.Transport.WatchOutputCalls, "recovery failed before any reconnect");
        await status.StopAsync().ConfigureAwait(false);

        var empty = new OutputRig();
        empty.Transport.OnWatchOutput(Step.End);
        empty.Transport.OnReadOutput(new ExecutionServiceReadOutputResponse());
        empty.Start();
        Check.Equal(StopReason.ProtocolViolation, (await empty.FinishAsync().ConfigureAwait(false)).Reason, "a response without an outcome");
    }

    private static async Task OutputPageBounds()
    {
        var policy = new RealtimePolicy();
        async Task<PageResult> Apply(OutputSession session, ExecutionServiceReadOutputResponse response) =>
            await OutputDelivery.ApplyPageAsync(session, new RecordingObserver(), policy, TimeProvider.System, response, CancellationToken.None).ConfigureAwait(false);

        OutputChunk[] chunks(int count) => [.. Enumerable.Range(0, count).Select(index => Make.Chunk((ulong)index, "a"))];
        Check.Equal(PageKind.Consumed, (await Apply(new OutputSession(Make.Owner(), policy), Make.ReadPage("c", null, chunks(100))).ConfigureAwait(false)).Kind, "100 chunks");
        PageResult tooMany = await Apply(new OutputSession(Make.Owner(), policy), Make.ReadPage("c", null, chunks(101))).ConfigureAwait(false);
        Check.Equal(StopReason.ProtocolViolation, tooMany.Stop.Reason, "101 chunks");

        OutputChunk[] heavy(int total) => [.. Enumerable.Range(0, total / 32768).Select(index => Make.Chunk((ulong)index * 32768, new string('a', 32768)))];
        Check.Equal(PageKind.Consumed, (await Apply(new OutputSession(Make.Owner(), policy), Make.ReadPage("c", null, heavy(256 * 1024))).ConfigureAwait(false)).Kind, "256 KiB of chunk bytes");
        OutputChunk[] over = [.. heavy(256 * 1024), Make.Chunk(256 * 1024, "a")];
        PageResult tooHeavy = await Apply(new OutputSession(Make.Owner(), policy), Make.ReadPage("c", null, over)).ConfigureAwait(false);
        Check.Equal(StopReason.ProtocolViolation, tooHeavy.Stop.Reason, "256 KiB and one byte");

        PageResult gap = await Apply(new OutputSession(Make.Owner(), policy), Make.ReadPage("c", null, Make.Chunk(5, "a"))).ConfigureAwait(false);
        Check.Equal(StopReason.IntegrityViolation, gap.Stop.Reason, "a gap in an authoritative read");

        PageResult foreign = await Apply(new OutputSession(Make.Owner(), policy), Make.ReadPage("c", Make.Terminal("f", "completed", 8))).ConfigureAwait(false);
        Check.Equal(StopReason.ProtocolViolation, foreign.Stop.Reason, "a terminal for another owner");

        var restart = new OutputSession(Make.Owner(), policy) { Cursor = "stale" };
        PageResult reset = await Apply(restart, Make.ReadReset()).ConfigureAwait(false);
        Check.Equal(PageKind.Restart, reset.Kind, "reset required");
        Check.Equal<string?>(null, restart.Cursor, "the stale cursor was dropped");
        var chunksIgnored = new ExecutionServiceReadOutputValue { ResetRequired = true };
        chunksIgnored.Chunks.Add(Make.Chunk(0, "a"));
        var ignoring = new OutputSession(Make.Owner(), policy);
        PageResult resetWithChunks = await Apply(ignoring, new ExecutionServiceReadOutputResponse { Value = chunksIgnored }).ConfigureAwait(false);
        Check.Equal(PageKind.Restart, resetWithChunks.Kind, "reset with chunks");
        Check.Equal(0UL, ignoring.Tracker.NextOffset, "a reset page applies none of its chunks");

        var advancing = new OutputSession(Make.Owner(), policy);
        PageResult page = await Apply(advancing, Make.ReadPage("next", null, Make.Chunk(0, "ab"), Make.Chunk(2, "c"))).ConfigureAwait(false);
        Check.Equal(2, page.Chunks, "chunks consumed");
        Check.Equal("next", advancing.Cursor ?? string.Empty, "the cursor advances after the page");
        Check.Equal(3UL, advancing.Tracker.NextOffset, "offset after the page");
    }
}
