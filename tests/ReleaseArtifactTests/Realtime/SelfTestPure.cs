// SPDX-License-Identifier: AGPL-3.0-only
// Test code runs on a console without a synchronization context and holds each fixture for the whole check, so these
// library-oriented rules do not apply here; the production-shaped files of this project keep them enabled.
#pragma warning disable CA1849, CA2007, CA2000, CA1508
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.PublicApi.V1;
using Google.Protobuf;
using Grpc.Core;

namespace RealtimeAotProbe;

/// <summary>Synchronous checks of the contract codecs, the sequence rules, the schedules and the classification table.</summary>
internal static class SelfTestPure
{
    private const ulong BeyondJsSafe = (1UL << 53) + 1;

    public static void Register(SelfTestRunner runner)
    {
        ArgumentNullException.ThrowIfNull(runner);
        runner.Add("codec: every StreamFrame variant round trips with 64 bit values beyond 2^53", () => { StreamFrameVariants(); return Task.CompletedTask; });
        runner.Add("codec: all 17 event hint payloads round trip", () => { SeventeenHints(); return Task.CompletedTask; });
        runner.Add("codec: optional cursor presence survives the wire", () => { CursorPresence(); return Task.CompletedTask; });
        runner.Add("sequence: baseline, next, gap and duplicate", () => { Sequence(); return Task.CompletedTask; });
        runner.Add("sequence: conflicting duplicate inside and outside the window", () => { SequenceConflictWindow(); return Task.CompletedTask; });
        runner.Add("sequence: 64 bit boundaries and reset", () => { SequenceBoundaries(); return Task.CompletedTask; });
        runner.Add("output tracker: append, duplicate, gap, conflict and bounds", () => { OutputTrackerRules(); return Task.CompletedTask; });
        runner.Add("output tracker: owner, attempt binding, straddle and overflow", () => { OutputTrackerBinding(); return Task.CompletedTask; });
        runner.Add("policy: the defaults are the limits annex 10 states", () => { PolicyDefaults(); return Task.CompletedTask; });
        runner.Add("backoff: ceiling ladder, cap, jitter bounds and the 30 second reset", () => { Backoff(); return Task.CompletedTask; });
        runner.Add("pacing: plus or minus 20 percent around the interval", () => { PacingBounds(); return Task.CompletedTask; });
        runner.Add("classification: ArcError categories, retry modes and retry time", () => { ArcErrors(); return Task.CompletedTask; });
        runner.Add("classification: gRPC status table", () => { RpcStatuses(); return Task.CompletedTask; });
        runner.Add("live options: required, bounded and credentials only from the environment", () => { LiveOptionsRules(); return Task.CompletedTask; });
    }

    private static T RoundTrip<T>(T message, MessageParser<T> parser)
        where T : IMessage<T> => parser.ParseFrom(message.ToByteArray());

    private static void StreamFrameVariants()
    {
        var owner = Make.Owner();
        StreamFrame[] frames =
        [
            new() { Position = Make.Position("p", ulong.MaxValue), Hint = Make.Hint(BeyondJsSafe) },
            new() { Position = new StreamPosition { Cursor = "c", Sequence = BeyondJsSafe, Generation = ulong.MaxValue, ContentHash = "h" }, Output = Make.Chunk(BeyondJsSafe, "x") },
            new() { Reset = new StreamReset { Reason = "expired", ResumeFrom = "r", SnapshotRequired = true, Truncated = true, SuccessorStreamId = Make.NewId(9) } },
            new() { Terminal = new ExecutionOutput { Execution = owner, State = "completed", FinalHash = "f", Truncated = true, SuccessorStreamId = Make.NewId(3) } },
            new() { Heartbeat = new Instant { UnixSeconds = -1, Nanos = 999_999_999 } },
            Make.ErrorFrame(ErrorCategory.Authorization),
            new() { Progress = new ExecutionProgress { Execution = owner, StreamState = "open", RetryAfterMs = uint.MaxValue } },
        ];
        StreamFrame.FrameOneofCase[] expected =
        [
            StreamFrame.FrameOneofCase.Hint,
            StreamFrame.FrameOneofCase.Output,
            StreamFrame.FrameOneofCase.Reset,
            StreamFrame.FrameOneofCase.Terminal,
            StreamFrame.FrameOneofCase.Heartbeat,
            StreamFrame.FrameOneofCase.Error,
            StreamFrame.FrameOneofCase.Progress,
        ];
        for (int index = 0; index < frames.Length; index++)
        {
            StreamFrame copy = RoundTrip(frames[index], StreamFrame.Parser);
            Check.Equal(expected[index], copy.FrameCase, "variant " + index);
            Check.True(copy.Equals(frames[index]), "frame " + index + " changed on the wire");
        }

        StreamFrame first = RoundTrip(frames[0], StreamFrame.Parser);
        Check.Equal(ulong.MaxValue, first.Position.Sequence, "position sequence");
        Check.Equal(BeyondJsSafe, first.Hint.Seq, "hint sequence");
        StreamFrame second = RoundTrip(frames[1], StreamFrame.Parser);
        Check.Equal(ulong.MaxValue, second.Position.Generation, "generation");
        Check.Equal(BeyondJsSafe, second.Output.Offset, "output offset");
        Check.Equal(-1L, RoundTrip(frames[4], StreamFrame.Parser).Heartbeat.UnixSeconds, "heartbeat seconds");
    }

    private static void SeventeenHints()
    {
        Action<Event>[] setters =
        [
            e => e.SyncChanged = new SyncChanged(),
            e => e.SyncConflictRaised = new SyncConflictRaised(),
            e => e.TaskStateChanged = new TaskStateChanged(),
            e => e.TaskProgress = new TaskProgress(),
            e => e.TaskOutputAppended = new TaskOutputAppended(),
            e => e.ApprovalRaised = new ApprovalRaised(),
            e => e.ApprovalResolved = new ApprovalResolved(),
            e => e.EntitlementChanged = new EntitlementChanged { EntitlementVersion = long.MinValue },
            e => e.ApplicationPresenceChanged = new ApplicationPresenceChanged(),
            e => e.BridgeRequestAvailable = new BridgeRequestAvailable(),
            e => e.NotificationRaised = new NotificationRaised(),
            e => e.PolicyBundleAvailable = new PolicyBundleAvailable(),
            e => e.ResourceCommitted = new ResourceCommitted(),
            e => e.CapacityChanged = new CapacityChanged(),
            e => e.ServiceTermChanged = new ServiceTermChanged(),
            e => e.SimulationStateChanged = new SimulationStateChanged(),
            e => e.ConfigRevisionActivated = new ConfigRevisionActivated(),
        ];
        Check.Equal(17, setters.Length, "payload alternatives under test");
        Check.Equal(17, Enum.GetValues<Event.PayloadOneofCase>().Count(value => value != Event.PayloadOneofCase.None), "payload alternatives in the contract");
        var seen = new HashSet<Event.PayloadOneofCase>();
        foreach (Action<Event> set in setters)
        {
            var hint = new Event { SubscriptionKey = Make.Key, Seq = 1 };
            set(hint);
            Event copy = RoundTrip(hint, Event.Parser);
            Check.True(copy.PayloadCase != Event.PayloadOneofCase.None, "a payload was lost on the wire");
            Check.Equal(hint.PayloadCase, copy.PayloadCase, "payload case");
            Check.True(seen.Add(copy.PayloadCase), "two setters produced the same payload case");
        }

        Check.Equal(long.MinValue, RoundTrip(new Event { SubscriptionKey = Make.Key, Seq = 1, EntitlementChanged = new EntitlementChanged { EntitlementVersion = long.MinValue } }, Event.Parser).EntitlementChanged.EntitlementVersion, "int64 payload field");
    }

    private static void CursorPresence()
    {
        var absent = RoundTrip(new EventServiceWatchRequest { SubscriptionKey = Make.Key }, EventServiceWatchRequest.Parser);
        Check.True(!absent.HasCursor, "an absent cursor became present");
        var empty = RoundTrip(new EventServiceWatchRequest { SubscriptionKey = Make.Key, Cursor = string.Empty }, EventServiceWatchRequest.Parser);
        Check.True(empty.HasCursor, "an empty cursor became absent");
        var poll = RoundTrip(new EventServicePollRequest { SubscriptionKey = Make.Key }, EventServicePollRequest.Parser);
        Check.True(!poll.HasCursor, "a first Poll carried a cursor");
    }

    private static void Sequence()
    {
        var tracker = new EventSequenceTracker();
        Event one = Make.Hint(10);
        SequenceVerdict baseline = tracker.Evaluate(one);
        Check.Equal(SequenceOutcome.Apply, baseline.Outcome, "baseline");
        tracker.Accept(one, baseline);
        Event two = Make.Hint(11);
        SequenceVerdict next = tracker.Evaluate(two);
        Check.Equal(SequenceOutcome.Apply, next.Outcome, "next");
        tracker.Accept(two, next);
        SequenceVerdict gap = tracker.Evaluate(Make.Hint(13));
        Check.Equal(SequenceOutcome.Gap, gap.Outcome, "gap");
        Check.Equal(12UL, gap.Expected, "gap expected");
        Check.Equal(13UL, gap.Actual, "gap actual");
        Check.Equal(SequenceOutcome.Duplicate, tracker.Evaluate(Make.Hint(11)).Outcome, "same sequence");
        Check.Equal(SequenceOutcome.Duplicate, tracker.Evaluate(Make.Hint(10)).Outcome, "older sequence");
        Check.Equal(SequenceOutcome.Duplicate, tracker.Evaluate(Make.Hint(1)).Outcome, "far older sequence");
        Check.Equal(11UL, tracker.Last ?? 0, "evaluation must not mutate");
        Event gapHint = Make.Hint(13);
        tracker.Accept(gapHint, gap);
        Check.Equal(1L, tracker.Gaps, "gaps counted");
        Check.Equal(13UL, tracker.Last ?? 0, "a gap hint still advances");
        Check.Throws<InvalidOperationException>(() => tracker.Accept(one, new SequenceVerdict(SequenceOutcome.Duplicate, 0, 0)), "accepting a duplicate");
        Check.Throws<InvalidOperationException>(() => tracker.Accept(one, new SequenceVerdict(SequenceOutcome.Conflict, 0, 0)), "accepting a conflict");
    }

    private static void SequenceConflictWindow()
    {
        var tracker = new EventSequenceTracker();
        int window = EventSequenceTracker.ConflictWindow;
        for (ulong sequence = 1; sequence <= (ulong)window + 10; sequence++)
        {
            Event hint = Make.Hint(sequence);
            tracker.Accept(hint, tracker.Evaluate(hint));
        }

        ulong last = (ulong)window + 10;
        Event different(ulong sequence) => new() { SubscriptionKey = Make.Key, Seq = sequence, CorrelationId = Make.NewId(5), TaskProgress = new TaskProgress() };
        Check.Equal(SequenceOutcome.Conflict, tracker.Evaluate(different(last)).Outcome, "conflict at the last sequence");
        Check.Equal(SequenceOutcome.Conflict, tracker.Evaluate(different(last - (ulong)window + 1)).Outcome, "conflict at the oldest remembered sequence");
        Check.Equal(SequenceOutcome.Duplicate, tracker.Evaluate(different(last - (ulong)window)).Outcome, "just outside the window is a plain duplicate");
        Check.Equal(SequenceOutcome.Duplicate, tracker.Evaluate(Make.Hint(last - 3)).Outcome, "an identical duplicate inside the window");
    }

    private static void SequenceBoundaries()
    {
        var tracker = new EventSequenceTracker();
        Event big = Make.Hint(ulong.MaxValue - 1);
        tracker.Accept(big, tracker.Evaluate(big));
        Event max = Make.Hint(ulong.MaxValue);
        SequenceVerdict toMax = tracker.Evaluate(max);
        Check.Equal(SequenceOutcome.Apply, toMax.Outcome, "next to the maximum");
        tracker.Accept(max, toMax);
        Check.Equal(SequenceOutcome.Duplicate, tracker.Evaluate(Make.Hint(ulong.MaxValue)).Outcome, "nothing follows the maximum");
        var js = new EventSequenceTracker();
        Event safe = Make.Hint(1UL << 53);
        js.Accept(safe, js.Evaluate(safe));
        Check.Equal(SequenceOutcome.Apply, js.Evaluate(Make.Hint(BeyondJsSafe)).Outcome, "2^53 + 1 is the exact next sequence");
        Check.Equal(SequenceOutcome.Gap, js.Evaluate(Make.Hint(BeyondJsSafe + 1)).Outcome, "2^53 + 2 is a gap");
        js.Reset();
        Check.True(js.Last is null, "reset clears the baseline");
        Check.Equal(SequenceOutcome.Apply, js.Evaluate(Make.Hint(500)).Outcome, "any sequence is a baseline after reset");
    }

    private static void OutputTrackerRules()
    {
        var policy = new RealtimePolicy();
        var tracker = new OutputTracker(Make.Owner(), policy);
        OutputChunk first = Make.Chunk(0, "ab");
        Check.Equal(OutputOutcome.Append, tracker.Evaluate(first).Outcome, "first chunk");
        tracker.Accept(first, tracker.Evaluate(first));
        Check.Equal(2UL, tracker.NextOffset, "next offset");
        OutputChunk second = Make.Chunk(2, "cde");
        tracker.Accept(second, tracker.Evaluate(second));
        Check.Equal(5UL, tracker.NextOffset, "next offset after the second chunk");
        Check.Equal(OutputOutcome.Duplicate, tracker.Evaluate(Make.Chunk(2, "cde")).Outcome, "identical duplicate");
        Check.Equal(OutputOutcome.Conflict, tracker.Evaluate(Make.Chunk(2, "cdx")).Outcome, "different bytes at a received offset");
        Check.Equal(OutputOutcome.Conflict, tracker.Evaluate(Make.Chunk(2, "cde", hash: "other")).Outcome, "different hash at a received offset");
        OutputVerdict gap = tracker.Evaluate(Make.Chunk(9, "z"));
        Check.Equal(OutputOutcome.Gap, gap.Outcome, "gap");
        Check.Equal(5UL, gap.Expected, "gap expected");
        Check.Equal(9UL, gap.Actual, "gap actual");
        Check.Equal(OutputOutcome.Append, tracker.Evaluate(Make.Chunk(5, string.Empty)).Outcome, "an empty chunk at the next offset");
        string atBound = new('a', policy.MaximumChunkBytes);
        Check.Equal(OutputOutcome.Append, tracker.Evaluate(Make.Chunk(5, atBound)).Outcome, "a chunk at the 32 KiB bound");
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(Make.Chunk(5, atBound + "a")).Outcome, "a chunk over the 32 KiB bound");
        var missing = Make.Chunk(5, "x");
        missing.ClearOffset();
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(missing).Outcome, "a chunk without an offset");
        Check.Throws<InvalidOperationException>(() => tracker.Accept(first, new OutputVerdict(OutputOutcome.Duplicate, 0, 0, string.Empty)), "accepting a duplicate");
        tracker.RecordGap();
        tracker.RecordDuplicate();
        Check.Equal(1L, tracker.Gaps, "gaps counted");
        Check.Equal(1L, tracker.Duplicates, "duplicates counted");
        tracker.Reset();
        Check.Equal(0UL, tracker.NextOffset, "reset offset");
        Check.Equal(OutputOutcome.Append, tracker.Evaluate(Make.Chunk(0, "ab", attempt: 9, stream: 9)).Outcome, "a new attempt after reset");
    }

    private static void OutputTrackerBinding()
    {
        var tracker = new OutputTracker(Make.Owner(), new RealtimePolicy());
        OutputChunk first = Make.Chunk(0, "ab");
        tracker.Accept(first, tracker.Evaluate(first));
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(Make.Chunk(2, "c", owner: 8)).Outcome, "another execution owner");
        var noOwner = Make.Chunk(2, "c");
        noOwner.Execution = null;
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(noOwner).Outcome, "no execution owner");
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(Make.Chunk(2, "c", attempt: 9)).Outcome, "another attempt without a reset");
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(Make.Chunk(2, "c", stream: 9)).Outcome, "another stream without a reset");
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(Make.Chunk(1, "bcd")).Outcome, "a chunk straddling the received end");
        Check.Equal(OutputOutcome.Duplicate, tracker.Evaluate(Make.Chunk(1, "b")).Outcome, "a short chunk inside the received range outside the window match");
        Check.Equal(OutputOutcome.Violation, tracker.Evaluate(Make.Chunk(ulong.MaxValue, "c")).Outcome, "a range overflowing 64 bits");
        Check.Equal(OutputOutcome.Gap, tracker.Evaluate(Make.Chunk(ulong.MaxValue - 1, "c")).Outcome, "the last representable range is a gap, not an overflow");
        var window = new OutputTracker(Make.Owner(), new RealtimePolicy());
        for (int index = 0; index <= OutputTracker.ConflictWindow; index++)
        {
            OutputChunk chunk = Make.Chunk((ulong)index, "a");
            window.Accept(chunk, window.Evaluate(chunk));
        }

        Check.Equal(OutputOutcome.Conflict, window.Evaluate(Make.Chunk(1, "z")).Outcome, "the oldest remembered chunk is still compared");
        Check.Equal(OutputOutcome.Duplicate, window.Evaluate(Make.Chunk(0, "z")).Outcome, "a chunk older than the window is a plain duplicate");
    }

    private static void PolicyDefaults()
    {
        var policy = new RealtimePolicy();
        Check.Equal(TimeSpan.FromSeconds(45), policy.SilenceTimeout, "silence timeout");
        Check.Equal(TimeSpan.FromMilliseconds(500), policy.ReconnectBase, "reconnect base");
        Check.Equal(TimeSpan.FromSeconds(30), policy.ReconnectCap, "reconnect cap");
        Check.Equal(TimeSpan.FromSeconds(30), policy.StableConnection, "stable connectivity");
        Check.Equal(TimeSpan.FromSeconds(10), policy.PollInterval, "poll interval");
        Check.Equal(TimeSpan.FromSeconds(5), policy.ReadOutputInterval, "ReadOutput interval");
        Check.Equal(0.2, policy.CadenceJitter, "cadence jitter");
        Check.Equal(TimeSpan.FromMinutes(5), policy.MaximumRetryAfter, "the probe's own retry-time bound");
        Check.Equal(32 * 1024, policy.MaximumChunkBytes, "chunk data bound");
        Check.Equal(100, policy.MaximumPageChunks, "page chunk bound");
        Check.Equal(256 * 1024, policy.MaximumPageBytes, "page byte bound");
        Check.Equal(512 * 1024, RealtimeChannel.MaximumReceiveBytes, "received message bound");
        Check.Equal(64, EventSequenceTracker.ConflictWindow, "event conflict window");
        Check.Equal(64, OutputTracker.ConflictWindow, "output conflict window");
    }

    private static void Backoff()
    {
        var policy = new RealtimePolicy();
        var backoff = new ReconnectBackoff(policy);
        double[] ceilings = [0.5, 1, 2, 4, 8, 16, 30, 30, 30];
        foreach (double seconds in ceilings)
        {
            Check.Equal(TimeSpan.FromSeconds(seconds), backoff.NextCeiling(), "ceiling " + seconds);
            Check.Equal(TimeSpan.FromSeconds(seconds), backoff.NextDelay(() => 1.0), "delay at r=1 equals the ceiling " + seconds);
        }

        backoff.Succeeded();
        Check.Equal(0, backoff.Attempt, "success resets the ladder");
        Check.Equal(TimeSpan.Zero, backoff.NextDelay(() => 0.0), "full jitter can draw zero");
        Check.Equal(TimeSpan.FromSeconds(1), backoff.NextCeiling(), "the ladder climbed once");
        Check.Equal(TimeSpan.FromSeconds(0.5), TimeSpan.FromTicks(new ReconnectBackoff(policy).NextDelay(() => 0.5).Ticks * 2), "half jitter on the first ceiling is a quarter second");
        Check.Equal(TimeSpan.FromSeconds(0.5), new ReconnectBackoff(policy).NextDelay(() => 7.0), "a random source above one is clamped");
        Check.Equal(TimeSpan.Zero, new ReconnectBackoff(policy).NextDelay(() => -3.0), "a random source below zero is clamped");
        var stable = new ReconnectBackoff(policy);
        _ = stable.NextDelay(() => 1.0);
        _ = stable.NextDelay(() => 1.0);
        stable.ConnectionEnded(TimeSpan.FromSeconds(30) - TimeSpan.FromTicks(1));
        Check.Equal(2, stable.Attempt, "just under 30 seconds of connectivity is not stable");
        stable.ConnectionEnded(TimeSpan.FromSeconds(30));
        Check.Equal(0, stable.Attempt, "30 seconds of connectivity is stable");
        Check.Throws<ArgumentNullException>(() => stable.NextDelay(null!), "a missing random source");
    }

    private static void PacingBounds()
    {
        TimeSpan ten = TimeSpan.FromSeconds(10);
        Check.Equal(TimeSpan.FromSeconds(8), Pacing.Next(ten, 0.2, () => 0.0), "lowest jitter");
        Check.Equal(ten, Pacing.Next(ten, 0.2, () => 0.5), "middle jitter");
        Check.Equal(TimeSpan.FromSeconds(12), Pacing.Next(ten, 0.2, () => 1.0), "highest jitter");
        Check.Equal(TimeSpan.FromSeconds(12), Pacing.Next(ten, 0.2, () => 9.0), "a random source above one is clamped");
        Check.Equal(TimeSpan.FromSeconds(4), Pacing.Next(TimeSpan.FromSeconds(5), 0.2, () => 0.0), "ReadOutput cadence lower bound");
        Check.Equal(TimeSpan.FromSeconds(6), Pacing.Next(TimeSpan.FromSeconds(5), 0.2, () => 1.0), "ReadOutput cadence upper bound");
    }

    private static void ArcErrors()
    {
        var policy = new RealtimePolicy();
        DateTimeOffset now = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
        Classified Of(ErrorCategory category, RetryMode? mode = null, Instant? at = null) =>
            ErrorClassifier.FromArcError(Make.ErrorFrame(category, mode, at).Error, now, policy);
        foreach (ErrorCategory auth in new[] { ErrorCategory.Authentication, ErrorCategory.Authorization, ErrorCategory.Entitlement })
        {
            Check.Equal(Disposition.StopAuthorization, Of(auth).Disposition, auth + " stops");
            Check.Equal(Disposition.StopAuthorization, Of(auth, RetryMode.AfterTime, Make.At(now.AddSeconds(5))).Disposition, auth + " ignores retry advice");
            Check.Equal(Disposition.StopAuthorization, Of(auth, RetryMode.SameCommand).Disposition, auth + " ignores same-command advice");
        }

        foreach (ErrorCategory transient in new[] { ErrorCategory.Resource, ErrorCategory.Execution, ErrorCategory.Internal })
        {
            Check.Equal(Disposition.Retry, Of(transient).Disposition, transient + " retries");
            Check.Equal(Disposition.Retry, Of(transient, RetryMode.SameCommand).Disposition, transient + " same command retries");
            Check.Equal(Disposition.Retry, Of(transient, RetryMode.Reconcile).Disposition, transient + " reconcile retries");
            Check.Equal(Disposition.StopNonRetryable, Of(transient, RetryMode.Never).Disposition, transient + " never stops");
        }

        foreach (ErrorCategory permanent in new[] { ErrorCategory.Validation, ErrorCategory.Conflict, ErrorCategory.State, ErrorCategory.Unspecified })
        {
            Check.Equal(Disposition.StopNonRetryable, Of(permanent).Disposition, permanent + " stops");
            Check.Equal(Disposition.StopNonRetryable, Of(permanent, RetryMode.SameCommand).Disposition, permanent + " same command stops");
        }

        Classified timed = Of(ErrorCategory.State, RetryMode.AfterTime, Make.At(now.AddSeconds(20)));
        Check.Equal(Disposition.Retry, timed.Disposition, "an explicit retry time retries any non-permission category");
        Check.Equal(TimeSpan.FromSeconds(20), timed.RetryAfter, "retry time in the future");
        Check.Equal(TimeSpan.Zero, Of(ErrorCategory.Resource, RetryMode.AfterTime, Make.At(now.AddSeconds(-5))).RetryAfter, "retry time in the past");
        Check.Equal(TimeSpan.Zero, Of(ErrorCategory.Resource, RetryMode.AfterTime).RetryAfter, "no retry time");
        Check.Equal(policy.MaximumRetryAfter, Of(ErrorCategory.Resource, RetryMode.AfterTime, Make.At(now.AddHours(3))).RetryAfter, "retry time is bounded");
        Check.Equal(policy.MaximumRetryAfter, Of(ErrorCategory.Resource, RetryMode.AfterTime, new Instant { UnixSeconds = long.MaxValue }).RetryAfter, "an unrepresentable retry time is bounded");
        Check.Equal(Disposition.StopNonRetryable, ErrorClassifier.FromArcError(null, now, policy).Disposition, "an error frame without an ArcError");
        Check.True(Of(ErrorCategory.Authorization).Detail.Contains("test.error", StringComparison.Ordinal), "the detail names the code");
    }

    private static void RpcStatuses()
    {
        Disposition Of(StatusCode code) => ErrorClassifier.FromRpc(new RpcException(new Status(code, "x"))).Disposition;
        foreach (StatusCode code in new[] { StatusCode.Unauthenticated, StatusCode.PermissionDenied })
        {
            Check.Equal(Disposition.StopAuthorization, Of(code), code.ToString());
        }

        Check.Equal(Disposition.StopUnsupported, Of(StatusCode.Unimplemented), "Unimplemented");
        foreach (StatusCode code in new[] { StatusCode.InvalidArgument, StatusCode.NotFound, StatusCode.AlreadyExists, StatusCode.FailedPrecondition, StatusCode.OutOfRange })
        {
            Check.Equal(Disposition.StopNonRetryable, Of(code), code.ToString());
        }

        foreach (StatusCode code in new[] { StatusCode.Unavailable, StatusCode.DeadlineExceeded, StatusCode.ResourceExhausted, StatusCode.Aborted, StatusCode.Internal, StatusCode.Unknown, StatusCode.DataLoss, StatusCode.Cancelled })
        {
            Check.Equal(Disposition.Retry, Of(code), code.ToString());
        }

        var malformed = new RpcException(new Status(StatusCode.Internal, "x", Make.Malformed()));
        Check.Equal(Disposition.StopProtocol, ErrorClassifier.FromRpc(malformed).Disposition, "a malformed message");
    }

    private static void LiveOptionsRules()
    {
        string? Env(string name) => name == LiveOptions.AuthorizationVariable ? "Bearer test-value" : null;
        string? NoEnv(string name) => null;
        LiveOptions parsed = LiveOptions.Parse(["--live", "https://example.test", "--subscription", "workspace:1"], Env);
        Check.Equal("workspace:1", parsed.SubscriptionKey, "subscription");
        Check.Equal(LiveOptions.DefaultSeconds, parsed.Seconds, "default seconds");
        Check.True(!parsed.Poll && parsed.OutputTask is null, "defaults");
        Check.Equal("Bearer test-value", parsed.Authorization ?? string.Empty, "authorization from the environment");
        Check.True(LiveOptions.Parse(["--live", "https://example.test", "--subscription", "k"], NoEnv).Authorization is null, "no authorization without the variable");
        LiveOptions all = LiveOptions.Parse(["--live", "http://localhost:8787", "--subscription", "k", "--mode", "poll", "--seconds", "3600", "--output-task", "11111111-2222-3333-4444-555555555555"], NoEnv);
        Check.True(all.Poll && all.Seconds == 3600 && all.OutputTask is not null, "all options");
        string[][] invalid =
        [
            [],
            ["--live"],
            ["--live", "not a uri", "--subscription", "k"],
            ["--live", "http://example.test", "--subscription", "k"],
            ["--live", "https://user:pass@example.test", "--subscription", "k"],
            ["--live", "https://example.test?x=1", "--subscription", "k"],
            ["--live", "https://example.test"],
            ["--live", "https://example.test", "--subscription"],
            ["--live", "https://example.test", "--subscription", "k", "--seconds", "0"],
            ["--live", "https://example.test", "--subscription", "k", "--seconds", "3601"],
            ["--live", "https://example.test", "--subscription", "k", "--seconds", "-5"],
            ["--live", "https://example.test", "--subscription", "k", "--mode", "stream"],
            ["--live", "https://example.test", "--subscription", "k", "--output-task", "nope"],
            ["--live", "https://example.test", "--subscription", "k", "--authorization", "Bearer x"],
        ];
        foreach (string[] args in invalid)
        {
            Check.Throws<ArgumentException>(() => LiveOptions.Parse(args, NoEnv), "invalid arguments: " + string.Join(' ', args));
        }

        Uri normalized = RealtimeChannel.NormalizeAddress(new Uri("https://example.test/base"));
        Check.Equal("https://example.test/base/", normalized.AbsoluteUri, "a trailing slash is added once");
        Check.Equal("/base/api", RealtimeChannel.ApiPath(normalized), "the API path follows the base path");
        Check.Equal("/api", RealtimeChannel.ApiPath(RealtimeChannel.NormalizeAddress(new Uri("https://example.test"))), "the API path after an empty path");
        Check.Equal("/base/api", RealtimeChannel.ApiPath(RealtimeChannel.NormalizeAddress(new Uri("https://example.test/base/"))), "no doubled slash");
        Check.Equal("http://127.0.0.1:8787/", RealtimeChannel.NormalizeAddress(new Uri("http://127.0.0.1:8787/")).AbsoluteUri, "loopback HTTP");
        Check.Throws<ArgumentException>(() => RealtimeChannel.NormalizeAddress(new Uri("ftp://example.test")), "another scheme");
        Check.Throws<ArgumentException>(() => RealtimeChannel.NormalizeAddress(new Uri("https://example.test/#x")), "a fragment");
        using SocketsHttpHandler handler = RealtimeChannel.NewTransportHandler();
        Check.True(!handler.AllowAutoRedirect, "the transport never follows a redirect");
    }
}
