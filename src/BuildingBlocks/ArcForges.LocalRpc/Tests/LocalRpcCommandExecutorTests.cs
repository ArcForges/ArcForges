// SPDX-License-Identifier: AGPL-3.0-only
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCommandExecutorTests
{
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ASuccessIsRecordedUnderItsCommandIdWithItsResponse()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();

        var outcome = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("r1")), cancellationToken: Ct);

        Assert.Equal(command.CommandId, outcome.CommandId);
        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Happened, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.None, outcome.Reason);
        Assert.Equal(1, outcome.Attempts);
        Assert.True(outcome.Sent);
        Assert.True(outcome.HasResponse);
        Assert.Equal("r1", outcome.Response);
        Assert.Null(outcome.Status);
        Assert.Null(outcome.Refusal);
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(LocalRpcCommandState.Resolved, record.State);
        Assert.Equal(LocalRpcOutcomeKind.Success, record.Kind);
        Assert.Equal(LocalRpcEffect.Happened, record.Effect);
        Assert.Equal(1, record.Attempts);
        Assert.Equal(ExecutorRig.Gen, record.Generation);
        Assert.Equal(ExecutorRig.Operation, record.Operation);
        Assert.Equal(LocalRpcIdempotency.NonIdempotent, record.Idempotency);
        Assert.True(record.HasResponse);
        Assert.False(record.CancelRequested);
        Assert.Equal(1, rig.Executor.RecordedCommands);
        Assert.Null(rig.Executor.GetRecord(Guid.NewGuid()));
    }

    [Fact]
    public async Task ADuplicateOfASettledCommandIsAnsweredFromTheRecordWithoutSendingAgain()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        _ = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("r1")), cancellationToken: Ct);

        var again = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("r2")), ExecutorRig.OtherGen, cancellationToken: Ct);

        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Success, again.Kind);
        Assert.Equal("r1", again.Response);
        Assert.False(again.Sent);
        Assert.Equal(1, again.Attempts);
        Assert.Equal(LocalRpcFailureReason.None, again.Reason);
        Assert.Equal(ExecutorRig.Gen, rig.Executor.GetRecord(command.CommandId)!.Generation);
    }

    [Fact]
    public async Task ARecordedResponseOfAnotherTypeIsNotHandedBack()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        _ = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("r1")), cancellationToken: Ct);

        var wrongType = await rig.Executor.ExecuteAsync(command, ExecutorRig.Gen, (_, _) => Task.FromResult(42), null, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, wrongType.Kind);
        Assert.False(wrongType.HasResponse);
        Assert.Equal(0, wrongType.Response);
        Assert.False(wrongType.Sent);
    }

    [Fact]
    public async Task TheSameIdWithAnotherOperationInputOrClassIsAConflictThatSendsNothing()
    {
        var rig = new ExecutorRig();
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        var variants = new[]
        {
            ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, digest: 2),
            ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, operation: "pkg.Service/Other"),
            ExecutorRig.Command(id, LocalRpcIdempotency.NonIdempotent),
        };
        foreach (var variant in variants)
        {
            var outcome = await rig.RunAsync(variant, rig.Script(ExecutorRig.Ok("must not run")), cancellationToken: Ct);

            Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
            Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
            Assert.Equal(LocalRpcFailureReason.CommandConflict, outcome.Reason);
            Assert.False(outcome.Sent);
            Assert.Equal(0, outcome.Attempts);
        }

        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Success, rig.Executor.GetRecord(id)!.Kind);
    }

    [Fact]
    public async Task ATransientRefusalIsRetriedAfterTheBackoffThatDoublesEveryAttempt()
    {
        var rig = new ExecutorRig(maxAttempts: 4);
        var command = ExecutorRig.Command();
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull()), ExecutorRig.Fail(ExecutorRig.DataQueueFull()), ExecutorRig.Ok("late")), cancellationToken: Ct);

        await rig.WaitingAsync(Ct);
        Assert.Equal(1, rig.Sends);
        rig.Time.Advance(ExecutorRig.FirstWait - TimeSpan.FromMilliseconds(1));
        await Task.Delay(30, Ct);
        Assert.Equal(1, rig.Sends);
        Assert.False(running.IsCompleted);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));

        // The second wait is twice the first.
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2 && rig.Time.ArmedTimers == 1, "the second backoff wait", Ct);
        rig.Time.Advance(TimeSpan.FromMilliseconds(199));
        await Task.Delay(30, Ct);
        Assert.Equal(2, rig.Sends);
        Assert.False(running.IsCompleted);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal("late", outcome.Response);
        Assert.Equal(3, outcome.Attempts);
        Assert.Equal(3, rig.Sends);
    }

    [Theory]
    [InlineData(LocalRpcRefusalReason.RecursiveCallback)]
    [InlineData(LocalRpcRefusalReason.CommandConflict)]
    public async Task ARefusalThatWillRepeatItselfIsNotRetried(LocalRpcRefusalReason reason)
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();

        var outcome = await rig.RunAsync(command, rig.Script(ExecutorRig.Fail(Failures.Refusal(reason, LocalRpcRefusal.StatusOf(reason)))), cancellationToken: Ct);

        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.Refused, outcome.Reason);
        Assert.Equal(reason, outcome.Refusal!.Reason);
        Assert.Equal(LocalRpcRefusal.StatusOf(reason), outcome.Status);
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(command.CommandId)!.State);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    public async Task ARefusalThatNeverClearsStopsAtTheAttemptBoundWithATypedDidNotHappenFailure(int maxAttempts)
    {
        var rig = new ExecutorRig(maxAttempts);
        var command = ExecutorRig.Command();
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull())), cancellationToken: Ct);

        for (var attempt = 1; attempt < maxAttempts; attempt++)
        {
            // One wait at a time, each exactly its ceiling: a longer jump would run the following attempts inside the same advance.
            await rig.AfterWaitingAdvanceAsync(LocalRpcBackoff.Ceiling(attempt, ExecutorRig.FirstWait, ExecutorRig.MaxWait), Ct);
            await BoundsHarness.WaitUntilAsync(() => rig.Sends > attempt || running.IsCompleted, "the next attempt", Ct);
        }

        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(maxAttempts, rig.Sends);
        Assert.Equal(maxAttempts, outcome.Attempts);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.Refused, outcome.Reason);
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, outcome.Refusal!.Reason);
        Assert.Equal(StatusCode.ResourceExhausted, outcome.Status);
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(command.CommandId)!.State);
    }

    [Fact]
    public async Task AFailureThatProvedNothingWasSentMayBeStartedAgainUnderTheSameId()
    {
        var rig = new ExecutorRig(maxAttempts: 1);
        var command = ExecutorRig.Command();
        var first = await rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull())), cancellationToken: Ct);
        Assert.Equal(LocalRpcEffect.DidNotHappen, first.Effect);

        var second = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("now")), ExecutorRig.OtherGen, cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, second.Kind);
        Assert.Equal("now", second.Response);
        Assert.Equal(2, second.Attempts);
        Assert.True(second.Sent);
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(ExecutorRig.OtherGen, record.Generation);
        Assert.Equal(2, record.Attempts);
        Assert.Equal(1, rig.Executor.RecordedCommands);
    }

    [Fact]
    public async Task AMissingConnectionIsRetriedAndProvesNothingWasSent()
    {
        var rig = new ExecutorRig(maxAttempts: 3);
        var command = ExecutorRig.Command();
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.ConnectFailure())), cancellationToken: Ct);

        await rig.AfterWaitingAdvanceAsync(ExecutorRig.FirstWait, Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2 && rig.Time.ArmedTimers == 1, "the second wait", Ct);
        rig.Time.Advance(TimeSpan.FromMilliseconds(200));
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(3, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.ConnectFailed, outcome.Reason);
        Assert.Equal(StatusCode.Unavailable, outcome.Status);
        Assert.Equal(LocalRpcEffect.DidNotHappen, rig.Executor.GetRecord(command.CommandId)!.Effect);
    }

    [Theory]
    [InlineData(StatusCode.Unavailable, LocalRpcFailureReason.TransportLost)]
    [InlineData(StatusCode.DeadlineExceeded, LocalRpcFailureReason.DeadlineExceeded)]
    [InlineData(StatusCode.Internal, LocalRpcFailureReason.PeerError)]
    public async Task ANonIdempotentCommandWithAnUnknownEffectIsRecordedAsUnknownAndNeverSentAgain(StatusCode status, LocalRpcFailureReason reason)
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();

        var outcome = await rig.RunAsync(command, rig.Script(ExecutorRig.Fail(Failures.Status(status))), cancellationToken: Ct);

        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(reason, outcome.Reason);
        Assert.Equal(status, outcome.Status);
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(LocalRpcCommandState.Unknown, record.State);
        Assert.Equal(LocalRpcOutcomeKind.Failure, record.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, record.Effect);

        var again = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, again.Reason);
        Assert.Equal(LocalRpcEffect.Unknown, again.Effect);
        Assert.Equal(LocalRpcOutcomeKind.Failure, again.Kind);
        Assert.False(again.Sent);
        Assert.Equal(1, again.Attempts);
    }

    [Fact]
    public async Task ADuplicateSafeCommandIsNotReplayedWithoutTheExplicitPermission()
    {
        var rig = new ExecutorRig();
        var id = Guid.NewGuid();
        var withoutPermission = ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: false);

        var first = await rig.RunAsync(withoutPermission, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        var again = await rig.RunAsync(withoutPermission, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(LocalRpcEffect.Unknown, first.Effect);
        Assert.Equal(1, first.Attempts);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, again.Reason);
        Assert.Equal(1, rig.Sends);
    }

    [Fact]
    public async Task APermittedReplayToTheSameLaunchInsideTheWindowSendsTheCommandAgain()
    {
        var rig = new ExecutorRig();
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Ok("answered")), cancellationToken: Ct);

        var replayed = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Ok("answered")), cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, replayed.Kind);
        Assert.Equal(LocalRpcEffect.Happened, replayed.Effect);
        Assert.Equal("answered", replayed.Response);
        Assert.Equal(2, replayed.Attempts);
        Assert.True(replayed.Sent);
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(id)!.State);
    }

    [Fact]
    public async Task APermittedReplayToAnotherLaunchIsRefusedBecauseThatLaunchHasNoReceipts()
    {
        var rig = new ExecutorRig();
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), ExecutorRig.Gen, cancellationToken: Ct);

        var replayed = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Ok("must not run")), ExecutorRig.OtherGen, cancellationToken: Ct);

        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, replayed.Reason);
        Assert.Equal(LocalRpcEffect.Unknown, replayed.Effect);
        Assert.False(replayed.Sent);
        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(id)!.State);
        Assert.Equal(ExecutorRig.Gen, rig.Executor.GetRecord(id)!.Generation);
    }

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public async Task AReplayIsAllowedUpToAndIncludingTheWindowAndRefusedOneTickAfter(long ticksPastTheWindow, bool allowed)
    {
        var window = TimeSpan.FromMinutes(5);
        var rig = new ExecutorRig(replayWindow: window);
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Ok()), cancellationToken: Ct);
        rig.Time.Advance(window + TimeSpan.FromTicks(ticksPastTheWindow));

        var replayed = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(allowed, replayed.Sent);
        Assert.Equal(allowed ? LocalRpcOutcomeKind.Success : LocalRpcOutcomeKind.Failure, replayed.Kind);
        Assert.Equal(allowed ? LocalRpcFailureReason.None : LocalRpcFailureReason.ReplayNotAllowed, replayed.Reason);
    }

    [Fact]
    public async Task APermittedCallReplaysAnUnknownAttemptAfterTheBackoffWithinTheSameCall()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe, replay: true);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Ok("second")), cancellationToken: Ct);

        await rig.AfterWaitingAdvanceAsync(ExecutorRig.FirstWait, Ct);
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal(2, outcome.Attempts);
        Assert.Equal(2, rig.Sends);
    }

    [Theory]
    [InlineData(StatusCode.DeadlineExceeded)]
    [InlineData(StatusCode.Unavailable)]
    public async Task ADeadlineOrALostStreamIsReplayedWhenPermittedButAnAnswerThatProvesNothingIsNot(StatusCode status)
    {
        var rig = new ExecutorRig();
        var replayable = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe, replay: true);
        var running = rig.RunAsync(replayable, rig.Script(ExecutorRig.Fail(Failures.Status(status)), ExecutorRig.Ok()), cancellationToken: Ct);
        await rig.AfterWaitingAdvanceAsync(ExecutorRig.FirstWait, Ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, (await running.WaitAsync(Patience, Ct)).Kind);

        var peerError = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe, replay: true);
        var before = rig.Sends;
        var refused = await rig.RunAsync(peerError, rig.Script(ExecutorRig.Fail(Failures.Status(StatusCode.Internal))), cancellationToken: Ct);

        Assert.Equal(LocalRpcEffect.Unknown, refused.Effect);
        Assert.Equal(LocalRpcFailureReason.PeerError, refused.Reason);
        Assert.Equal(1, rig.Sends - before);
    }

    [Fact]
    public async Task AReplayWithinACallStopsOnceTheWindowHasPassed()
    {
        var window = TimeSpan.FromSeconds(30);
        var rig = new ExecutorRig(replayWindow: window);
        var command = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe, replay: true);

        // The first attempt takes longer than the window: a helper's receipts may be gone by now, so no replay.
        var outcome = await rig.RunAsync(command, rig.Script((_, _) =>
        {
            rig.Time.Advance(window + TimeSpan.FromTicks(1));
            return Task.FromException<string>(ExecutorRig.Unavailable());
        }, ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.TransportLost, outcome.Reason);
        Assert.Equal(1, outcome.Attempts);
    }

    [Fact]
    public async Task ALaterAttemptThatIsRefusedCannotTurnAnEarlierUnknownIntoDidNotHappen()
    {
        var rig = new ExecutorRig(maxAttempts: 3);
        var command = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe, replay: true);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Fail(ExecutorRig.DataQueueFull()), ExecutorRig.Fail(ExecutorRig.ConnectFailure())), cancellationToken: Ct);

        await rig.AfterWaitingAdvanceAsync(ExecutorRig.FirstWait, Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2 && rig.Time.ArmedTimers == 1, "the second wait", Ct);
        rig.Time.Advance(TimeSpan.FromMilliseconds(200));
        var outcome = await running.WaitAsync(Patience, Ct);

        // The first attempt may have been executed; a refusal and then a missing connection prove only themselves.
        Assert.Equal(3, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.ConnectFailed, outcome.Reason);
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(command.CommandId)!.State);
    }

    [Fact]
    public async Task APeersOwnReportThatTheEffectDidNotHappenResolvesAnEarlierUnknown()
    {
        var rig = new ExecutorRig(maxAttempts: 3);
        var command = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe, replay: true);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Fail(Failures.Effect(StatusCode.Cancelled, "did-not-happen"))), cancellationToken: Ct);

        await rig.AfterWaitingAdvanceAsync(ExecutorRig.FirstWait, Ct);
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(2, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.ReportedByPeer, outcome.Reason);
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(command.CommandId)!.State);
    }

    [Fact]
    public async Task APeersOwnReportThatTheEffectHappenedIsASuccessWithoutAResponse()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();

        var outcome = await rig.RunAsync(command, rig.Script(ExecutorRig.Fail(Failures.Effect(StatusCode.FailedPrecondition, "happened"))), cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Happened, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.None, outcome.Reason);
        Assert.False(outcome.HasResponse);
        Assert.Equal(1, rig.Sends);
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(LocalRpcCommandState.Resolved, record.State);
        Assert.False(record.HasResponse);
    }

    [Fact]
    public async Task ACallerWhoseTokenIsAlreadyCancelledSendsNothingAndRecordsNothing()
    {
        var rig = new ExecutorRig();
        using var source = new CancellationTokenSource();
        await source.CancelAsync();

        var outcome = await rig.RunAsync(ExecutorRig.Command(), rig.Script(ExecutorRig.Ok()), cancellationToken: source.Token);

        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, outcome.Reason);
        Assert.False(outcome.Sent);
        Assert.Equal(0, outcome.Attempts);
        Assert.Equal(0, rig.Sends);
        Assert.Equal(0, rig.Executor.RecordedCommands);
    }

    [Fact]
    public async Task ACallerWhoCancelsAfterTheSendLeavesAnUnknownEffectThatIsNotReplayedOnItsOwn()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe);
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.UntilCancelled()), cancellationToken: source.Token);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);

        await source.CancelAsync();
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, outcome.Reason);
        Assert.True(outcome.Sent);
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(LocalRpcCommandState.Unknown, record.State);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, record.Kind);

        var again = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, again.Reason);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, again.Kind);
        Assert.Equal(1, rig.Sends);
    }

    [Fact]
    public async Task ACallerWhoCancelsWhileWaitingToRetryAfterARefusalEndsWithACancelledDidNotHappenThatIsNeverRestarted()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull()), ExecutorRig.Ok()), cancellationToken: source.Token);
        await rig.WaitingAsync(Ct);

        await source.CancelAsync();
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, outcome.Reason);
        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(command.CommandId)!.State);

        var again = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Cancelled, again.Kind);
        Assert.False(again.Sent);
        Assert.Equal(1, rig.Sends);
    }

    [Fact]
    public async Task TheSendDelegateGetsATokenThatCarriesTheCallersCancellation()
    {
        var rig = new ExecutorRig();
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        CancellationToken seen = default;
        var running = rig.RunAsync(ExecutorRig.Command(), rig.Script(async (_, token) =>
        {
            seen = token;
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return "never";
        }), cancellationToken: source.Token);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);
        Assert.False(seen.IsCancellationRequested);

        await source.CancelAsync();

        Assert.True(seen.IsCancellationRequested);
        _ = await running.WaitAsync(Patience, Ct);
    }

    [Fact]
    public async Task TheSendDelegateIsToldTheAttemptNumber()
    {
        var rig = new ExecutorRig(maxAttempts: 3);
        var seen = new List<int>();
        var running = rig.RunAsync(ExecutorRig.Command(), rig.Script((attempt, _) =>
        {
            seen.Add(attempt);
            return Task.FromException<string>(ExecutorRig.DataQueueFull());
        }), cancellationToken: Ct);

        await rig.AfterWaitingAdvanceAsync(ExecutorRig.FirstWait, Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2 && rig.Time.ArmedTimers == 1, "the second wait", Ct);
        rig.Time.Advance(TimeSpan.FromMilliseconds(200));
        _ = await running.WaitAsync(Patience, Ct);

        Assert.Equal([1, 2, 3], seen);
    }

    [Fact]
    public async Task ALostLaunchAbortsTheRunningAttemptAndLeavesAnUnknownEffectOnlyForCommandsSentToIt()
    {
        var rig = new ExecutorRig();
        var lost = ExecutorRig.Command();
        var healthy = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var abortedToken = false;
        var onLost = rig.RunAsync(lost, rig.Script(async (_, token) =>
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            }
            catch (OperationCanceledException)
            {
                abortedToken = true;
                throw;
            }

            return "never";
        }), ExecutorRig.Gen, cancellationToken: Ct);
        var onOther = rig.RunAsync(healthy, rig.Script(ExecutorRig.Gated(gate, "kept")), ExecutorRig.OtherGen, cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2, "both sends", Ct);

        var stopped = rig.Executor.PeerLost(ExecutorRig.Gen);
        var outcome = await onLost.WaitAsync(Patience, Ct);

        Assert.Equal(1, stopped);
        Assert.True(abortedToken);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.PeerLost, outcome.Reason);
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(lost.CommandId)!.State);
        Assert.Equal(LocalRpcCommandState.InFlight, rig.Executor.GetRecord(healthy.CommandId)!.State);
        gate.SetResult();
        Assert.Equal("kept", (await onOther.WaitAsync(Patience, Ct)).Response);

        // Declaring the same launch lost again finds nothing in flight, and settled commands are untouched.
        Assert.Equal(0, rig.Executor.PeerLost(ExecutorRig.Gen));
        Assert.Equal(0, rig.Executor.PeerLost(ExecutorRig.OtherGen));
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(healthy.CommandId)!.State);
    }

    [Fact]
    public async Task ALostLaunchWhileACommandWaitsToRetryEndsItAsDidNotHappenBecauseNothingWasSentToIt()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull()), ExecutorRig.Ok()), cancellationToken: Ct);
        await rig.WaitingAsync(Ct);

        Assert.Equal(1, rig.Executor.PeerLost(ExecutorRig.Gen));
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.PeerLost, outcome.Reason);
        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(command.CommandId)!.State);

        // It certainly did not happen, so it may be started again on the relaunched helper.
        var rerun = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("fresh")), ExecutorRig.OtherGen, cancellationToken: Ct);
        Assert.Equal("fresh", rerun.Response);
    }

    [Fact]
    public async Task ALostLaunchWhileARetryIsPendingAfterAnUnknownKeepsTheEffectUnknown()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command(null, LocalRpcIdempotency.DuplicateSafe, replay: true);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Ok()), cancellationToken: Ct);
        await rig.WaitingAsync(Ct);

        Assert.Equal(1, rig.Executor.PeerLost(ExecutorRig.Gen));
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.PeerLost, outcome.Reason);
        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(command.CommandId)!.State);
    }

    [Fact]
    public async Task WatchingAPeerDeclaresItLostWhenTheTokenIsCancelledAndNotAfterTheRegistrationIsDisposed()
    {
        var rig = new ExecutorRig();
        var first = ExecutorRig.Command();
        using var lostSource = new CancellationTokenSource();
        var registration = rig.Executor.WatchPeer(ExecutorRig.Gen, lostSource.Token);
        var running = rig.RunAsync(first, rig.Script(ExecutorRig.UntilCancelled()), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);

        await lostSource.CancelAsync();

        Assert.Equal(LocalRpcFailureReason.PeerLost, (await running.WaitAsync(Patience, Ct)).Reason);
        await registration.DisposeAsync();

        // A watch that was disposed before the token fired does nothing.
        using var other = new CancellationTokenSource();
        var disposed = rig.Executor.WatchPeer(ExecutorRig.OtherGen, other.Token);
        await disposed.DisposeAsync();
        var second = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var runningOther = rig.RunAsync(second, rig.Script(ExecutorRig.Gated(gate)), ExecutorRig.OtherGen, cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2, "the second send", Ct);
        await other.CancelAsync();
        gate.SetResult();
        Assert.Equal(LocalRpcOutcomeKind.Success, (await runningOther.WaitAsync(Patience, Ct)).Kind);
    }

    [Fact]
    public async Task WatchingAPeerWhoseTokenIsAlreadyCancelledDeclaresItLostAtOnce()
    {
        var rig = new ExecutorRig();
        using var source = new CancellationTokenSource();
        await source.CancelAsync();
        var running = rig.RunAsync(ExecutorRig.Command(), rig.Script(ExecutorRig.UntilCancelled()), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);

        await using var registration = rig.Executor.WatchPeer(ExecutorRig.Gen, source.Token);

        Assert.Equal(LocalRpcFailureReason.PeerLost, (await running.WaitAsync(Patience, Ct)).Reason);
    }

    [Fact]
    public async Task ADelegateThatThrowsSomethingThatIsNotATransportFailureLeavesTheCommandUnknownAndTheExceptionReachesTheCaller()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => rig.RunAsync(command, rig.Script(ExecutorRig.Fail(new InvalidOperationException("bug"))), cancellationToken: Ct));

        Assert.Equal("bug", thrown.Message);
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(LocalRpcCommandState.Unknown, record.State);
        Assert.Equal(LocalRpcEffect.Unknown, record.Effect);
        Assert.Equal(LocalRpcFailureReason.Unclassified, record.Reason);
        Assert.Equal(1, record.Attempts);

        // The same goes for a delegate that throws before it returns a task, and for the interpretation of a response.
        var syncThrow = ExecutorRig.Command();
        _ = await Assert.ThrowsAsync<ArgumentException>(() => rig.RunAsync(syncThrow, rig.Script(ExecutorRig.Throw(new ArgumentException("sync"))), cancellationToken: Ct));
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(syncThrow.CommandId)!.State);
        var interpretThrows = ExecutorRig.Command();
        _ = await Assert.ThrowsAsync<NotSupportedException>(() => rig.RunAsync(interpretThrows, rig.Script(ExecutorRig.Ok()), interpret: _ => throw new NotSupportedException(), cancellationToken: Ct));
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(interpretThrows.CommandId)!.State);

        var again = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, again.Reason);
    }

    [Theory]
    [InlineData(LocalRpcEffect.DidNotHappen, LocalRpcCommandState.Resolved)]
    [InlineData(LocalRpcEffect.Unknown, LocalRpcCommandState.Unknown)]
    public async Task AResponseThatReportsAnEffectOtherThanHappenedIsATypedFailureThatKeepsItsResponse(LocalRpcEffect reported, LocalRpcCommandState state)
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();

        var outcome = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("business error")), interpret: _ => reported, cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(reported, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.ReportedByPeer, outcome.Reason);
        Assert.True(outcome.HasResponse);
        Assert.Equal("business error", outcome.Response);
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(state, record.State);
        Assert.True(record.HasResponse);
    }

    [Fact]
    public async Task AResponseThatReportsDidNotHappenMayBeSentAgainAndOneThatReportsHappenedIsASuccess()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        _ = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("no")), interpret: _ => LocalRpcEffect.DidNotHappen, cancellationToken: Ct);

        var second = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("yes")), interpret: _ => LocalRpcEffect.Happened, cancellationToken: Ct);

        Assert.Equal(2, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Success, second.Kind);
        Assert.Equal("yes", second.Response);
        Assert.Equal(2, second.Attempts);
    }

    [Fact]
    public async Task ASecondCallForACommandThatIsRunningIsRefusedWithoutSendingAndTheFirstIsUnaffected()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = rig.RunAsync(command, rig.Script(ExecutorRig.Gated(gate, "done")), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);

        var second = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("must not run")), cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Failure, second.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, second.Effect);
        Assert.Equal(LocalRpcFailureReason.AlreadyInFlight, second.Reason);
        Assert.False(second.Sent);
        Assert.Equal(1, second.Attempts);
        Assert.Equal(LocalRpcCommandState.InFlight, rig.Executor.GetRecord(command.CommandId)!.State);
        Assert.Null(rig.Executor.GetRecord(command.CommandId)!.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, rig.Executor.GetRecord(command.CommandId)!.Effect);
        gate.SetResult();
        Assert.Equal("done", (await first.WaitAsync(Patience, Ct)).Response);
        Assert.Equal(1, rig.Sends);
    }

    [Fact]
    public async Task AFullJournalOfCommandsItMayNotForgetRefusesANewCommandBeforeSendingIt()
    {
        var rig = new ExecutorRig(capacity: 2);
        _ = await rig.RunAsync(ExecutorRig.Command(), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        _ = await rig.RunAsync(ExecutorRig.Command(), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        var sends = rig.Sends;

        var third = await rig.RunAsync(ExecutorRig.Command(), rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Failure, third.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, third.Effect);
        Assert.Equal(LocalRpcFailureReason.JournalFull, third.Reason);
        Assert.False(third.Sent);
        Assert.Equal(0, third.Attempts);
        Assert.Equal(sends, rig.Sends);
        Assert.Equal(2, rig.Executor.RecordedCommands);
    }

    [Fact]
    public async Task ASettledCommandIsKeptForTheRetentionAndOnlyThenForgottenToMakeRoom()
    {
        var retention = TimeSpan.FromMinutes(10);
        var rig = new ExecutorRig(capacity: 1, retention: retention);
        var old = ExecutorRig.Command();
        _ = await rig.RunAsync(old, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        rig.Time.Advance(retention - TimeSpan.FromTicks(1));
        var early = await rig.RunAsync(ExecutorRig.Command(), rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);
        Assert.Equal(LocalRpcFailureReason.JournalFull, early.Reason);
        Assert.NotNull(rig.Executor.GetRecord(old.CommandId));

        rig.Time.Advance(TimeSpan.FromTicks(1));
        var next = ExecutorRig.Command();
        var admitted = await rig.RunAsync(next, rig.Script(ExecutorRig.Ok("room")), cancellationToken: Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, admitted.Kind);
        Assert.Null(rig.Executor.GetRecord(old.CommandId));
        Assert.NotNull(rig.Executor.GetRecord(next.CommandId));
        Assert.Equal(1, rig.Executor.RecordedCommands);
    }

    [Fact]
    public async Task OnlyTheSettledCommandsThatHaveOutlivedTheRetentionAreForgotten()
    {
        var retention = TimeSpan.FromMinutes(10);
        var rig = new ExecutorRig(capacity: 2, retention: retention);
        var a = ExecutorRig.Command();
        var b = ExecutorRig.Command();
        _ = await rig.RunAsync(a, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);
        rig.Time.Advance(TimeSpan.FromMinutes(5));
        _ = await rig.RunAsync(b, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);
        rig.Time.Advance(TimeSpan.FromMinutes(5));

        var c = ExecutorRig.Command();
        _ = await rig.RunAsync(c, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Null(rig.Executor.GetRecord(a.CommandId));
        Assert.NotNull(rig.Executor.GetRecord(b.CommandId));
        Assert.NotNull(rig.Executor.GetRecord(c.CommandId));
        Assert.Equal(2, rig.Executor.RecordedCommands);
    }

    [Fact]
    public async Task ACommandInFlightIsNeverForgottenHoweverLongItRuns()
    {
        var rig = new ExecutorRig(capacity: 1, retention: TimeSpan.FromMinutes(1));
        var running = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = rig.RunAsync(running, rig.Script(ExecutorRig.Gated(gate)), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);
        rig.Time.Advance(TimeSpan.FromHours(5));

        var refused = await rig.RunAsync(ExecutorRig.Command(), rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        Assert.Equal(LocalRpcFailureReason.JournalFull, refused.Reason);
        Assert.NotNull(rig.Executor.GetRecord(running.CommandId));
        gate.SetResult();
        _ = await first.WaitAsync(Patience, Ct);
    }

    [Fact]
    public async Task ACommandKeepsItsStableIdentityAcrossLaunchesAndCountsItsAttempts()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        _ = await rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), ExecutorRig.Gen, cancellationToken: Ct);
        var before = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(ExecutorRig.Gen, before.Generation);
        _ = await rig.Executor.ReconcileAsync(command.CommandId, (_, _) => ValueTask.FromResult(LocalRpcEffect.DidNotHappen), Ct);

        var outcome = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("on the new launch")), ExecutorRig.OtherGen, cancellationToken: Ct);

        Assert.Equal(command.CommandId, outcome.CommandId);
        var after = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(command.CommandId, after.CommandId);
        Assert.Equal(ExecutorRig.OtherGen, after.Generation);
        Assert.Equal(2, after.Attempts);
        Assert.Equal(LocalRpcEffect.Happened, after.Effect);
    }

    [Fact]
    public async Task ArgumentsAreValidated()
    {
        var rig = new ExecutorRig();

        _ = await Assert.ThrowsAsync<ArgumentNullException>(() => rig.Executor.ExecuteAsync(null!, ExecutorRig.Gen, (_, _) => Task.FromResult("x"), null, Ct));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(() => rig.Executor.ExecuteAsync<string>(ExecutorRig.Command(), ExecutorRig.Gen, null!, null, Ct));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(() => rig.Executor.ReconcileAsync(Guid.NewGuid(), null!, Ct));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(() => rig.Executor.CancelAsync(Guid.NewGuid(), null!, Ct));
    }

    [Fact]
    public void OptionsAreValidatedAndHaveTheDocumentedDefaults()
    {
        var defaults = new LocalRpcCommandExecutorOptions();
        Assert.Equal(3, defaults.MaxAttempts);
        Assert.Equal(TimeSpan.FromMinutes(5), defaults.ReplayWindow);
        Assert.Equal(4096, defaults.JournalCapacity);
        Assert.Equal(TimeSpan.FromMinutes(10), defaults.SettledRetention);
        Assert.Equal(LocalRpcBackoff.DefaultInitial, defaults.Backoff.Initial);
        _ = new LocalRpcCommandExecutor();
        _ = new LocalRpcCommandExecutor(new LocalRpcCommandExecutorOptions { MaxAttempts = 10, JournalCapacity = 65536, ReplayWindow = TimeSpan.FromHours(1), SettledRetention = TimeSpan.FromHours(24) });
        _ = new LocalRpcCommandExecutor(new LocalRpcCommandExecutorOptions { MaxAttempts = 1, JournalCapacity = 1, ReplayWindow = TimeSpan.FromTicks(1), SettledRetention = TimeSpan.FromTicks(1) });

        foreach (var invalid in new LocalRpcCommandExecutorOptions[]
        {
            new() { MaxAttempts = 0 },
            new() { MaxAttempts = 11 },
            new() { Backoff = null! },
            new() { ReplayWindow = TimeSpan.Zero },
            new() { ReplayWindow = TimeSpan.FromHours(1) + TimeSpan.FromTicks(1) },
            new() { JournalCapacity = 0 },
            new() { JournalCapacity = 65537 },
            new() { SettledRetention = TimeSpan.Zero },
            new() { SettledRetention = TimeSpan.FromHours(24) + TimeSpan.FromTicks(1) },
        })
        {
            _ = Assert.ThrowsAny<ArgumentException>(() => new LocalRpcCommandExecutor(invalid));
        }
    }
}
