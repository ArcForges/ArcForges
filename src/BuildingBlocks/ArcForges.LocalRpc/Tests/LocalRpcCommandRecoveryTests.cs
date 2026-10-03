// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>Reconciliation, explicit cancellation, queries and concurrency of the command executor, on a manual clock and scripted sends.</summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCommandRecoveryTests
{
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<LocalRpcCommand> UnknownAsync(ExecutorRig rig, LocalRpcIdempotency idempotency = LocalRpcIdempotency.NonIdempotent)
    {
        var command = ExecutorRig.Command(null, idempotency);
        var outcome = await rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        return command;
    }

    private static ValueTask<LocalRpcEffect> Resolves(LocalRpcEffect effect) => ValueTask.FromResult(effect);

    [Fact]
    public async Task AnUnknownCommandReconciledToHappenedIsASuccessWithoutAResponseAndNeverSentAgain()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);
        LocalRpcCommandRecord? seen = null;

        var record = await rig.Executor.ReconcileAsync(command.CommandId, (seenRecord, _) =>
        {
            seen = seenRecord;
            return Resolves(LocalRpcEffect.Happened);
        }, Ct);

        Assert.Equal(LocalRpcCommandState.Unknown, seen!.State);
        Assert.Equal(command.CommandId, seen.CommandId);
        Assert.Equal(LocalRpcCommandState.Resolved, record!.State);
        Assert.Equal(LocalRpcOutcomeKind.Success, record.Kind);
        Assert.Equal(LocalRpcEffect.Happened, record.Effect);
        Assert.False(record.HasResponse);

        var again = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("must not run")), cancellationToken: Ct);

        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Success, again.Kind);
        Assert.Equal(LocalRpcEffect.Happened, again.Effect);
        Assert.Equal(LocalRpcFailureReason.None, again.Reason);
        Assert.False(again.HasResponse);
        Assert.False(again.Sent);
    }

    [Fact]
    public async Task AnUnknownCommandReconciledToDidNotHappenMayBeStartedAgainAndRunsOnce()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);

        var record = await rig.Executor.ReconcileAsync(command.CommandId, (_, _) => Resolves(LocalRpcEffect.DidNotHappen), Ct);

        Assert.Equal(LocalRpcCommandState.Resolved, record!.State);
        Assert.Equal(LocalRpcOutcomeKind.Failure, record.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, record.Effect);
        var again = await rig.RunAsync(command, rig.Script(ExecutorRig.Ok("rerun")), cancellationToken: Ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, again.Kind);
        Assert.Equal("rerun", again.Response);
        Assert.Equal(2, again.Attempts);
        Assert.Equal(2, rig.Sends);
    }

    [Fact]
    public async Task ReconciliationThatCannotSayLeavesTheCommandUnknownAndMayBeTriedAgain()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);
        var calls = 0;

        var first = await rig.Executor.ReconcileAsync(command.CommandId, (_, _) =>
        {
            calls++;
            return Resolves(LocalRpcEffect.Unknown);
        }, Ct);
        var second = await rig.Executor.ReconcileAsync(command.CommandId, (_, _) =>
        {
            calls++;
            return Resolves(LocalRpcEffect.Happened);
        }, Ct);

        Assert.Equal(LocalRpcCommandState.Unknown, first!.State);
        Assert.Equal(2, calls);
        Assert.Equal(LocalRpcEffect.Happened, second!.Effect);
    }

    [Fact]
    public async Task AnUnspecifiedAnswerFromTheOwnerIsNotAnEffect()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);

        var record = await rig.Executor.ReconcileAsync(command.CommandId, (_, _) => Resolves(LocalRpcEffect.Unspecified), Ct);

        Assert.Equal(LocalRpcCommandState.Unknown, record!.State);
    }

    [Fact]
    public async Task OnlyAnUnknownCommandIsReconciledAndTheOthersAreReturnedUnchanged()
    {
        var rig = new ExecutorRig();
        var settled = ExecutorRig.Command();
        _ = await rig.RunAsync(settled, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = ExecutorRig.Command();
        var inFlight = rig.RunAsync(running, rig.Script(ExecutorRig.Gated(gate)), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2, "the send", Ct);
        var calls = 0;

        var a = await rig.Executor.ReconcileAsync(settled.CommandId, (_, _) =>
        {
            calls++;
            return Resolves(LocalRpcEffect.DidNotHappen);
        }, Ct);
        var b = await rig.Executor.ReconcileAsync(running.CommandId, (_, _) =>
        {
            calls++;
            return Resolves(LocalRpcEffect.DidNotHappen);
        }, Ct);
        var c = await rig.Executor.ReconcileAsync(Guid.NewGuid(), (_, _) =>
        {
            calls++;
            return Resolves(LocalRpcEffect.DidNotHappen);
        }, Ct);

        Assert.Equal(0, calls);
        Assert.Equal(LocalRpcEffect.Happened, a!.Effect);
        Assert.Equal(LocalRpcCommandState.InFlight, b!.State);
        Assert.Null(c);
        gate.SetResult();
        Assert.Equal(LocalRpcOutcomeKind.Success, (await inFlight.WaitAsync(Patience, Ct)).Kind);
    }

    [Fact]
    public async Task ASecondReconciliationWhileOneRunsDoesNotAskAgainAndAReplayIsRefusedWhileItRuns()
    {
        var rig = new ExecutorRig();
        var id = Guid.NewGuid();
        var withoutPermission = ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe);
        _ = await rig.RunAsync(withoutPermission, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<LocalRpcEffect>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var first = rig.Executor.ReconcileAsync(id, async (_, _) =>
        {
            calls++;
            started.SetResult();
            return await release.Task;
        }, Ct);
        await started.Task.WaitAsync(Patience, Ct);

        var second = await rig.Executor.ReconcileAsync(id, (_, _) =>
        {
            calls++;
            return Resolves(LocalRpcEffect.Happened);
        }, Ct);
        var replay = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Ok("must not run")), cancellationToken: Ct);

        Assert.Equal(1, calls);
        Assert.Equal(LocalRpcCommandState.Unknown, second!.State);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, replay.Reason);
        Assert.False(replay.Sent);
        Assert.Equal(1, rig.Sends);
        release.SetResult(LocalRpcEffect.DidNotHappen);
        Assert.Equal(LocalRpcCommandState.Resolved, (await first.WaitAsync(Patience, Ct))!.State);
    }

    [Fact]
    public async Task AReconciliationThatThrowsLeavesTheCommandUnknownAndFreeToBeReconciledAgain()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);

        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => rig.Executor.ReconcileAsync(command.CommandId, (_, _) => throw new InvalidOperationException("owner store down"), Ct));
        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.Equal(LocalRpcCommandState.Unknown, record.State);

        var again = await rig.Executor.ReconcileAsync(command.CommandId, (_, _) => Resolves(LocalRpcEffect.Happened), Ct);
        Assert.Equal(LocalRpcCommandState.Resolved, again!.State);
    }

    [Fact]
    public async Task TheReconciliationDelegateIsHandedTheCallersToken()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);
        using var source = new CancellationTokenSource();
        CancellationToken seen = default;

        _ = await rig.Executor.ReconcileAsync(command.CommandId, (_, token) =>
        {
            seen = token;
            return Resolves(LocalRpcEffect.Unknown);
        }, source.Token);

        Assert.Equal(source.Token, seen);
    }

    [Fact]
    public async Task AReplayBeforeReconciliationCannotRunWhileAnotherCallOwnsTheCommand()
    {
        var rig = new ExecutorRig();
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var replayCommand = ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true);
        var replay = rig.RunAsync(replayCommand, rig.Script(ExecutorRig.Gated(gate)), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2, "the replay send", Ct);

        var contender = await rig.RunAsync(replayCommand, rig.Script(ExecutorRig.Ok("must not run")), cancellationToken: Ct);

        Assert.Equal(LocalRpcFailureReason.AlreadyInFlight, contender.Reason);
        Assert.Equal(2, rig.Sends);
        gate.SetResult();
        Assert.Equal(LocalRpcOutcomeKind.Success, (await replay.WaitAsync(Patience, Ct)).Kind);
    }

    // Explicit cancellation.
    [Fact]
    public async Task CancellingAnUnknownCommandIsNotFoundTooLateOrDoneWithoutSendingWhereThereIsNothingToSend()
    {
        var rig = new ExecutorRig();
        var sent = 0;
        Task<LocalRpcEffect> Send(LocalRpcCommandRecord record, CancellationToken token)
        {
            sent++;
            return Task.FromResult(LocalRpcEffect.DidNotHappen);
        }

        var notFound = await rig.Executor.CancelAsync(Guid.NewGuid(), Send, Ct);
        Assert.Equal(LocalRpcCancelDisposition.NotFound, notFound.Disposition);
        Assert.False(notFound.Delivered);
        Assert.Null(notFound.Record);

        var done = ExecutorRig.Command();
        _ = await rig.RunAsync(done, rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);
        var tooLate = await rig.Executor.CancelAsync(done.CommandId, Send, Ct);
        Assert.Equal(LocalRpcCancelDisposition.TooLate, tooLate.Disposition);
        Assert.False(tooLate.Delivered);
        Assert.Equal(LocalRpcOutcomeKind.Success, tooLate.Record!.Kind);
        Assert.False(tooLate.Record.CancelRequested);

        var refused = ExecutorRig.Command();
        _ = await rig.RunAsync(refused, rig.Script(ExecutorRig.Fail(Failures.Refusal(LocalRpcRefusalReason.RecursiveCallback))), cancellationToken: Ct);
        var cancelled = await rig.Executor.CancelAsync(refused.CommandId, Send, Ct);
        Assert.Equal(LocalRpcCancelDisposition.Cancelled, cancelled.Disposition);
        Assert.False(cancelled.Delivered);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, cancelled.Record!.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, cancelled.Record.Effect);
        Assert.True(cancelled.Record.CancelRequested);
        Assert.Equal(LocalRpcFailureReason.CancelRequested, cancelled.Record.Reason);

        var again = await rig.Executor.CancelAsync(refused.CommandId, Send, Ct);
        Assert.Equal(LocalRpcCancelDisposition.Cancelled, again.Disposition);
        Assert.Equal(0, sent);

        // A cancelled command is final: the same id is not restarted.
        var rerun = await rig.RunAsync(refused, rig.Script(ExecutorRig.Ok("must not run")), cancellationToken: Ct);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, rerun.Kind);
        Assert.False(rerun.Sent);
        Assert.Equal(LocalRpcFailureReason.CancelRequested, rerun.Reason);
    }

    [Theory]
    [InlineData(LocalRpcEffect.DidNotHappen, LocalRpcCancelDisposition.Cancelled, LocalRpcOutcomeKind.Cancelled, LocalRpcEffect.DidNotHappen, LocalRpcCommandState.Resolved)]
    [InlineData(LocalRpcEffect.Happened, LocalRpcCancelDisposition.TooLate, LocalRpcOutcomeKind.Success, LocalRpcEffect.Happened, LocalRpcCommandState.Resolved)]
    [InlineData(LocalRpcEffect.Unknown, LocalRpcCancelDisposition.Requested, LocalRpcOutcomeKind.Cancelled, LocalRpcEffect.Unknown, LocalRpcCommandState.Unknown)]
    public async Task TheHelpersReportOnACancelSettlesAnUnknownCommand(
        LocalRpcEffect reported,
        LocalRpcCancelDisposition disposition,
        LocalRpcOutcomeKind kind,
        LocalRpcEffect effect,
        LocalRpcCommandState state)
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);
        LocalRpcCommandRecord? sentRecord = null;

        var result = await rig.Executor.CancelAsync(command.CommandId, (record, _) =>
        {
            sentRecord = record;
            return Task.FromResult(reported);
        }, Ct);

        // The intent was recorded before it was sent.
        Assert.True(sentRecord!.CancelRequested);
        Assert.Equal(LocalRpcCommandState.Unknown, sentRecord.State);
        Assert.Equal(disposition, result.Disposition);
        Assert.True(result.Delivered);
        Assert.Equal(state, result.Record!.State);
        Assert.Equal(kind, result.Record.Kind);
        Assert.Equal(effect, result.Record.Effect);
        Assert.True(result.Record.CancelRequested);
        Assert.False(result.Record.HasResponse);
    }

    [Fact]
    public async Task ACancelRequestedForAnUnknownCommandStopsEveryReplayEvenWhenTheCommandAllowsIt()
    {
        var rig = new ExecutorRig();
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);

        // The helper cannot say, and the cancel could not even be delivered: the intent is what is recorded.
        var undelivered = await rig.Executor.CancelAsync(id, (_, _) => Task.FromException<LocalRpcEffect>(ExecutorRig.Unavailable()), Ct);

        Assert.Equal(LocalRpcCancelDisposition.Requested, undelivered.Disposition);
        Assert.False(undelivered.Delivered);
        Assert.True(undelivered.Record!.CancelRequested);
        Assert.Equal(LocalRpcCommandState.Unknown, undelivered.Record.State);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, undelivered.Record.Kind);
        var replay = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Ok("must not run")), cancellationToken: Ct);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, replay.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, replay.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelRequested, replay.Reason);
        Assert.False(replay.Sent);
        Assert.Equal(1, rig.Sends);

        // When the helper is back the same cancel is delivered and settles it.
        var delivered = await rig.Executor.CancelAsync(id, (_, _) => Task.FromResult(LocalRpcEffect.DidNotHappen), Ct);
        Assert.Equal(LocalRpcCancelDisposition.Cancelled, delivered.Disposition);
        Assert.True(delivered.Delivered);
        Assert.Equal(LocalRpcEffect.DidNotHappen, delivered.Record!.Effect);
    }

    [Fact]
    public async Task ACancelWhileTheCommandWaitsToRetryStopsTheRetryAndEndsAsCancelledBeforeAnythingWasSent()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull()), ExecutorRig.Ok()), cancellationToken: Ct);
        await rig.WaitingAsync(Ct);

        var result = await rig.Executor.CancelAsync(command.CommandId, (_, _) => Task.FromResult(LocalRpcEffect.Unknown), Ct);
        var outcome = await running.WaitAsync(Patience, Ct);

        // The helper could not say, but the last attempt was refused before dispatch, so nothing is running to cancel: it did not happen.
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelRequested, outcome.Reason);
        Assert.Equal(1, rig.Sends);
        Assert.Equal(LocalRpcCommandState.Resolved, rig.Executor.GetRecord(command.CommandId)!.State);
        Assert.True(result.Delivered);
    }

    [Fact]
    public async Task ACancelThatTheHelperConfirmedBeforeTheCommitPointSettlesARunningCommandAndTheCallReturnsItsSettlement()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = rig.RunAsync(command, rig.Script(async (_, token) =>
        {
            await gate.Task.WaitAsync(token);
            throw Failures.Effect(StatusCode.Cancelled, "did-not-happen");
        }), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);

        var result = await rig.Executor.CancelAsync(command.CommandId, (_, _) => Task.FromResult(LocalRpcEffect.DidNotHappen), Ct);

        Assert.Equal(LocalRpcCancelDisposition.Cancelled, result.Disposition);
        Assert.Equal(LocalRpcEffect.DidNotHappen, result.Record!.Effect);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, result.Record.Kind);
        gate.SetResult();
        var outcome = await running.WaitAsync(Patience, Ct);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelRequested, outcome.Reason);
        Assert.Equal(1, rig.Sends);
    }

    [Fact]
    public async Task ACancelThatLostTheRaceWithTheCommitLeavesTheRunningCallFreeToSucceed()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Gated(gate, "committed")), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);

        var result = await rig.Executor.CancelAsync(command.CommandId, (_, _) => Task.FromResult(LocalRpcEffect.Happened), Ct);

        Assert.Equal(LocalRpcCancelDisposition.Requested, result.Disposition);
        Assert.Equal(LocalRpcCommandState.InFlight, result.Record!.State);
        Assert.True(result.Record.CancelRequested);
        gate.SetResult();
        var outcome = await running.WaitAsync(Patience, Ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal("committed", outcome.Response);
        Assert.Equal(LocalRpcEffect.Happened, outcome.Effect);
    }

    [Fact]
    public async Task ACancelThatLostTheRaceAndAStreamThatThenBreaksIsASuccessWithoutAResponse()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = rig.RunAsync(command, rig.Script(async (_, token) =>
        {
            await gate.Task.WaitAsync(token);
            throw ExecutorRig.Unavailable();
        }), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);
        _ = await rig.Executor.CancelAsync(command.CommandId, (_, _) => Task.FromResult(LocalRpcEffect.Happened), Ct);

        gate.SetResult();
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Happened, outcome.Effect);
        Assert.False(outcome.HasResponse);
        Assert.Equal(LocalRpcFailureReason.None, outcome.Reason);
    }

    [Fact]
    public async Task ACancelThatCouldNotBeDeliveredToARunningCommandLeavesItCancelledWithAnUnknownEffectWhenTheStreamBreaks()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = rig.RunAsync(command, rig.Script(async (_, token) =>
        {
            await gate.Task.WaitAsync(token);
            throw ExecutorRig.Unavailable();
        }), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);

        var result = await rig.Executor.CancelAsync(command.CommandId, (_, _) => Task.FromException<LocalRpcEffect>(ExecutorRig.Unavailable()), Ct);
        gate.SetResult();
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.False(result.Delivered);
        Assert.Equal(LocalRpcCancelDisposition.Requested, result.Disposition);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelRequested, outcome.Reason);
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(command.CommandId)!.State);
    }

    [Fact]
    public async Task ACancelDelegateThatThrowsSomethingThatIsNotATransportFailureLeavesTheIntentRecorded()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);

        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => rig.Executor.CancelAsync(command.CommandId, (_, _) => throw new InvalidOperationException("bug"), Ct));

        var record = rig.Executor.GetRecord(command.CommandId)!;
        Assert.True(record.CancelRequested);
        Assert.Equal(LocalRpcCommandState.Unknown, record.State);
    }

    [Fact]
    public async Task ACancelThatTheCallerAbandonsIsNotDeliveredAndLeavesTheIntentRecorded()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var cancelling = rig.Executor.CancelAsync(command.CommandId, async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return LocalRpcEffect.DidNotHappen;
        }, source.Token);
        await BoundsHarness.WaitUntilAsync(() => rig.Executor.GetRecord(command.CommandId)!.CancelRequested, "the intent", Ct);

        await source.CancelAsync();
        var result = await cancelling.WaitAsync(Patience, Ct);

        Assert.False(result.Delivered);
        Assert.Equal(LocalRpcCancelDisposition.Requested, result.Disposition);
        Assert.True(result.Record!.CancelRequested);
    }

    // Queries: no effect to preserve, so they are retried and never recorded.
    [Fact]
    public async Task AQueryIsRetriedAfterATransientFailureWithTheBackoffAndIsNeverRecorded()
    {
        var rig = new ExecutorRig();
        var query = ExecutorRig.Command(null, LocalRpcIdempotency.Query);
        var running = rig.RunAsync(query, rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Ok("read")), cancellationToken: Ct);

        await rig.WaitingAsync(Ct);
        rig.Time.Advance(ExecutorRig.FirstWait - TimeSpan.FromMilliseconds(1));
        await Task.Delay(30, Ct);
        Assert.Equal(1, rig.Sends);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2 && rig.Time.ArmedTimers == 1, "the second wait", Ct);
        rig.Time.Advance(TimeSpan.FromMilliseconds(199));
        await Task.Delay(30, Ct);
        Assert.Equal(2, rig.Sends);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Happened, outcome.Effect);
        Assert.Equal("read", outcome.Response);
        Assert.Equal(3, outcome.Attempts);
        Assert.True(outcome.Sent);
        Assert.Equal(0, rig.Executor.RecordedCommands);
    }

    [Fact]
    public async Task AQueryIsRetriedForEveryTransientFailureAndNotForAnAnswerThatWillRepeat()
    {
        var transient = new Exception[]
        {
            ExecutorRig.ConnectFailure(),
            Failures.Status(StatusCode.DeadlineExceeded),
            Failures.Status(StatusCode.Unavailable),
            ExecutorRig.DataQueueFull(),
            Failures.Refusal(LocalRpcRefusalReason.DeadlineBeforeDispatch, StatusCode.DeadlineExceeded),
            new IOException("reset"),
        };
        foreach (var failure in transient)
        {
            var rig = new ExecutorRig(maxAttempts: 2);
            var running = rig.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), rig.Script(ExecutorRig.Fail(failure), ExecutorRig.Ok()), cancellationToken: Ct);
            await rig.AfterWaitingAdvanceAsync(TimeSpan.FromMinutes(1), Ct);
            Assert.Equal(LocalRpcOutcomeKind.Success, (await running.WaitAsync(Patience, Ct)).Kind);
            Assert.Equal(2, rig.Sends);
        }

        var permanent = new Exception[]
        {
            Failures.Status(StatusCode.Internal),
            Failures.Status(StatusCode.InvalidArgument),
            Failures.Refusal(LocalRpcRefusalReason.RecursiveCallback, StatusCode.FailedPrecondition),
            Failures.Effect(StatusCode.Internal, "unknown"),
        };
        foreach (var failure in permanent)
        {
            var rig = new ExecutorRig(maxAttempts: 3);

            var outcome = await rig.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), rig.Script(ExecutorRig.Fail(failure), ExecutorRig.Ok()), cancellationToken: Ct);

            Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
            Assert.Equal(1, rig.Sends);
            Assert.Equal(1, outcome.Attempts);
        }
    }

    [Fact]
    public async Task AQueryThatKeepsFailingStopsAtTheAttemptBoundWithTheLastFailuresTypedFields()
    {
        var rig = new ExecutorRig(maxAttempts: 2);
        var running = rig.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);

        await rig.AfterWaitingAdvanceAsync(TimeSpan.FromMinutes(1), Ct);
        var outcome = await running.WaitAsync(Patience, Ct);

        Assert.Equal(2, rig.Sends);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.TransportLost, outcome.Reason);
        Assert.Equal(StatusCode.Unavailable, outcome.Status);
        Assert.Equal(2, outcome.Attempts);
        Assert.True(outcome.Sent);
        Assert.False(outcome.HasResponse);
        Assert.Equal(0, rig.Executor.RecordedCommands);

        var refused = new ExecutorRig(maxAttempts: 1);
        var byRefusal = await refused.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), refused.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull())), cancellationToken: Ct);
        Assert.Equal(LocalRpcEffect.DidNotHappen, byRefusal.Effect);
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, byRefusal.Refusal!.Reason);
    }

    [Fact]
    public async Task AQueryTheCallerCancelsIsCancelledWhereverItWas()
    {
        var before = new ExecutorRig();
        using var done = new CancellationTokenSource();
        await done.CancelAsync();
        var early = await before.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), before.Script(ExecutorRig.Ok()), cancellationToken: done.Token);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, early.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, early.Effect);
        Assert.Equal(0, early.Attempts);
        Assert.False(early.Sent);
        Assert.Equal(0, before.Sends);

        var during = new ExecutorRig();
        using var midSend = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var running = during.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), during.Script(ExecutorRig.UntilCancelled()), cancellationToken: midSend.Token);
        await BoundsHarness.WaitUntilAsync(() => during.Sends == 1, "the send", Ct);
        await midSend.CancelAsync();
        var cancelled = await running.WaitAsync(Patience, Ct);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, cancelled.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, cancelled.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, cancelled.Reason);
        Assert.Equal(1, cancelled.Attempts);

        var waiting = new ExecutorRig();
        using var midWait = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var retrying = waiting.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), waiting.Script(ExecutorRig.Fail(ExecutorRig.Unavailable()), ExecutorRig.Ok()), cancellationToken: midWait.Token);
        await waiting.WaitingAsync(Ct);
        await midWait.CancelAsync();
        var stopped = await retrying.WaitAsync(Patience, Ct);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, stopped.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, stopped.Effect);
        Assert.Equal(1, waiting.Sends);
        Assert.Equal(1, stopped.Attempts);
    }

    [Fact]
    public async Task AQueryWhoseDelegateThrowsSomethingThatIsNotATransportFailurePropagatesIt()
    {
        var rig = new ExecutorRig();

        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => rig.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), rig.Script(ExecutorRig.Fail(new InvalidOperationException("bug"))), cancellationToken: Ct));

        Assert.Equal(1, rig.Sends);
        Assert.Equal(0, rig.Executor.RecordedCommands);
    }

    // Guards that only a sharper test can see.
    [Fact]
    public async Task AReplayThatIsRefusedCannotTurnTheEarlierUnknownIntoDidNotHappen()
    {
        var rig = new ExecutorRig(maxAttempts: 1);
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);

        var replay = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Fail(ExecutorRig.DataQueueFull())), cancellationToken: Ct);

        // The replayed attempt was refused before dispatch, but the first attempt may have run on that launch.
        Assert.True(replay.Sent);
        Assert.Equal(LocalRpcFailureReason.Refused, replay.Reason);
        Assert.Equal(LocalRpcEffect.Unknown, replay.Effect);
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(id)!.State);
    }

    [Fact]
    public async Task TheReplayWindowRunsFromTheFirstAttemptAndNotFromTheLatestOne()
    {
        var rig = new ExecutorRig(maxAttempts: 2);
        var id = Guid.NewGuid();
        _ = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        rig.Time.Advance(TimeSpan.FromMinutes(4));
        var second = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Fail(ExecutorRig.Unavailable())), cancellationToken: Ct);
        Assert.True(second.Sent);
        rig.Time.Advance(TimeSpan.FromMinutes(2));

        var third = await rig.RunAsync(ExecutorRig.Command(id, LocalRpcIdempotency.DuplicateSafe, replay: true), rig.Script(ExecutorRig.Ok()), cancellationToken: Ct);

        // Six minutes since the first send, two since the latest: the helper may already have forgotten the command.
        Assert.False(third.Sent);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, third.Reason);
        Assert.Equal(2, rig.Sends);
    }

    [Fact]
    public async Task ACancelSettledByTheHelpersReportIsNotOverwrittenByTheLateEndOfTheCallThatWasRunning()
    {
        var rig = new ExecutorRig();
        var command = ExecutorRig.Command();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = rig.RunAsync(command, rig.Script(ExecutorRig.Gated(gate, "late answer")), cancellationToken: Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 1, "the send", Ct);
        _ = await rig.Executor.CancelAsync(command.CommandId, (_, _) => Task.FromResult(LocalRpcEffect.DidNotHappen), Ct);

        gate.SetResult();
        var outcome = await running.WaitAsync(Patience, Ct);

        // The first settlement stands: the command was cancelled before its commit point, whatever the call that was still running returns.
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.False(outcome.HasResponse);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, rig.Executor.GetRecord(command.CommandId)!.Kind);
    }

    [Fact]
    public async Task ReconcilingACancelRequestedCommandToDidNotHappenReadsAsCancelled()
    {
        var rig = new ExecutorRig();
        var command = await UnknownAsync(rig);
        _ = await rig.Executor.CancelAsync(command.CommandId, (_, _) => Task.FromException<LocalRpcEffect>(ExecutorRig.Unavailable()), Ct);

        var record = await rig.Executor.ReconcileAsync(command.CommandId, (_, _) => Resolves(LocalRpcEffect.DidNotHappen), Ct);

        Assert.Equal(LocalRpcCommandState.Resolved, record!.State);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, record.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, record.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelRequested, record.Reason);
        Assert.True(record.CancelRequested);
    }

    [Fact]
    public async Task AQueryIsToldItsAttemptNumber()
    {
        var rig = new ExecutorRig(maxAttempts: 3);
        var seen = new List<int>();
        var running = rig.RunAsync(ExecutorRig.Command(null, LocalRpcIdempotency.Query), rig.Script((attempt, _) =>
        {
            seen.Add(attempt);
            return Task.FromException<string>(ExecutorRig.Unavailable());
        }), cancellationToken: Ct);

        await rig.AfterWaitingAdvanceAsync(ExecutorRig.FirstWait, Ct);
        await BoundsHarness.WaitUntilAsync(() => rig.Sends == 2 && rig.Time.ArmedTimers == 1, "the second wait", Ct);
        rig.Time.Advance(TimeSpan.FromMilliseconds(200));
        _ = await running.WaitAsync(Patience, Ct);

        Assert.Equal([1, 2, 3], seen);
    }

    [Fact]
    public void ACommandThatIsCancelledOrLostBeforeItsFirstAttemptDidNotHappenBecauseNothingWasSent()
    {
        var journal = new LocalRpcCommandJournal(new ManualTimeProvider(), 16, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(5));

        var cancelled = journal.Begin(ExecutorRig.Command(), ExecutorRig.Gen).Entry!;
        _ = journal.RequestCancel(cancelled.Id);
        Assert.Null(journal.StartAttempt(cancelled, callerCancelled: false));
        var a = journal.SettleWithoutAttempt(cancelled, callerCancelled: false);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, a.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, a.Effect);
        Assert.Equal(LocalRpcCommandState.Resolved, a.State);
        Assert.Equal(0, a.Attempts);

        var lost = journal.Begin(ExecutorRig.Command(), ExecutorRig.Gen).Entry!;
        Assert.Equal(1, journal.PeerLost(ExecutorRig.Gen));
        Assert.Null(journal.StartAttempt(lost, callerCancelled: false));
        var b = journal.SettleWithoutAttempt(lost, callerCancelled: false);
        Assert.Equal(LocalRpcOutcomeKind.Failure, b.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, b.Effect);
        Assert.Equal(LocalRpcFailureReason.PeerLost, b.Reason);

        var abandoned = journal.Begin(ExecutorRig.Command(), ExecutorRig.Gen).Entry!;
        Assert.Null(journal.StartAttempt(abandoned, callerCancelled: true));
        var c = journal.SettleWithoutAttempt(abandoned, callerCancelled: true);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, c.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, c.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, c.Reason);
    }

    [Theory]
    [InlineData(LocalRpcEffect.Unspecified)]
    [InlineData((LocalRpcEffect)9)]
    [InlineData((LocalRpcEffect)(-1))]
    public async Task AnEffectThatIsNotOneOfTheThreeCertaintiesIsUnknownWhetherItComesFromAResponseOrACancelReport(LocalRpcEffect odd)
    {
        var rig = new ExecutorRig();
        var viaResponse = ExecutorRig.Command();

        var outcome = await rig.RunAsync(viaResponse, rig.Script(ExecutorRig.Ok("odd")), interpret: _ => odd, cancellationToken: Ct);

        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcCommandState.Unknown, rig.Executor.GetRecord(viaResponse.CommandId)!.State);

        var viaCancel = await UnknownAsync(rig);
        var result = await rig.Executor.CancelAsync(viaCancel.CommandId, (_, _) => Task.FromResult(odd), Ct);

        Assert.Equal(LocalRpcCancelDisposition.Requested, result.Disposition);
        Assert.Equal(LocalRpcCommandState.Unknown, result.Record!.State);
        Assert.Equal(LocalRpcEffect.Unknown, result.Record.Effect);
    }

    // Concurrency.
    [Fact]
    public async Task ManyCommandsRacingEachOtherLaunchLossesAndDuplicatesNeverRunTwiceAtOnceAndAllSettle()
    {
        var executor = new LocalRpcCommandExecutor(
            new LocalRpcCommandExecutorOptions { MaxAttempts = 4, Backoff = new LocalRpcBackoff(TimeSpan.FromTicks(1000), TimeSpan.FromMilliseconds(2)) },
            TimeProvider.System);
        const int commands = 150;
        var ids = Enumerable.Range(0, commands).Select(_ => Guid.NewGuid()).ToArray();
        var active = new ConcurrentDictionary<Guid, int>();
        var peak = new ConcurrentDictionary<Guid, int>();
        var sends = new ConcurrentDictionary<Guid, int>();

        LocalRpcCommand CommandFor(int index) => ExecutorRig.Command(ids[index], index % 2 == 0 ? LocalRpcIdempotency.DuplicateSafe : LocalRpcIdempotency.NonIdempotent, replay: index % 4 == 0);

        Func<int, CancellationToken, Task<string>> SendFor(int index) => async (_, token) =>
        {
            var id = ids[index];
            var now = active.AddOrUpdate(id, 1, (_, count) => count + 1);
            _ = peak.AddOrUpdate(id, now, (_, old) => Math.Max(old, now));
            _ = sends.AddOrUpdate(id, 1, (_, count) => count + 1);
            try
            {
                await Task.Yield();
                var step = RandomNumberGenerator.GetInt32(5);
                await Task.Delay(step, token);
                switch (step)
                {
                    case 0:
                        throw ExecutorRig.Unavailable();
                    case 1:
                        throw ExecutorRig.DataQueueFull();
                    case 2:
                        throw ExecutorRig.ConnectFailure();
                    default:
                        return "ok";
                }
            }
            finally
            {
                _ = active.AddOrUpdate(id, 0, (_, count) => count - 1);
            }
        };

        using var stop = new CancellationTokenSource();
        var losses = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                _ = executor.PeerLost(ExecutorRig.Gen);
                await Task.Delay(1, Ct);
            }
        }, Ct);
        var calls = new List<Task<LocalRpcCommandOutcome<string>>>();
        for (var index = 0; index < commands; index++)
        {
            var i = index;
            for (var copy = 0; copy < 3; copy++)
            {
                calls.Add(Task.Run(() => executor.ExecuteAsync(CommandFor(i), ExecutorRig.Gen, SendFor(i), null, Ct), Ct));
            }
        }

        var outcomes = await Task.WhenAll(calls).WaitAsync(TimeSpan.FromSeconds(60), Ct);
        await stop.CancelAsync();
        await losses;

        Assert.All(outcomes, outcome => Assert.True(outcome.Kind is LocalRpcOutcomeKind.Success or LocalRpcOutcomeKind.Failure or LocalRpcOutcomeKind.Cancelled));
        Assert.All(ids, id => Assert.True(peak.GetValueOrDefault(id) <= 1, "A command id never has two sends running at once."));
        foreach (var id in ids)
        {
            var record = executor.GetRecord(id)!;
            Assert.NotEqual(LocalRpcCommandState.InFlight, record.State);
            Assert.Equal(sends.GetValueOrDefault(id), record.Attempts);
        }

        Assert.Equal(0, active.Values.Sum());
    }
}
