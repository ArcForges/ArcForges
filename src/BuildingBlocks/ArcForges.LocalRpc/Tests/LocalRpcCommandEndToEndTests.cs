// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Commands over a real Kestrel HTTP/2 server and Grpc.Net.Client on in-memory streams, through the executor, with the generated
/// <c>ConnectorBrokerService</c> stubs (a real contract with real idempotency classes) and a hand-written test-only cancel method. A helper's
/// death is simulated by dropping every stream and losing its receipt table; the real-process version of these scenarios is the opt-in
/// <see cref="LocalRpcCommandProcessChecks"/>. The owner store stands in for the durable record an owner reconciles against.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCommandEndToEndTests
{
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    /// <summary>An executor on the real clock; <paramref name="pinned"/> makes every wait its full ceiling (50 ms doubling to 200 ms) so a test can act between attempts.</summary>
    private static LocalRpcCommandExecutor Executor(int maxAttempts = 3, bool pinned = false) => new(new LocalRpcCommandExecutorOptions
    {
        MaxAttempts = maxAttempts,
        Backoff = pinned
            ? new LocalRpcBackoff(TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(200), () => 1.0)
            : new LocalRpcBackoff(TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(20)),
    });

    [Fact]
    public async Task AKilledHelperBeforeTheCommitPointLeavesAnUnknownEffectThatReconciliationResolvesToDidNotHappenAndAReplayThenRunsOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        var id = Guid.NewGuid();
        var command = CommandClient.CompleteCommand(id);
        var first = await CommandHarness.StartAsync(store, cancellationToken: ct);
        first.Broker.ParkBeforeCommit = true;
        var channel = first.NewChannel();
        var running = CommandClient.CompleteAsync(executor, channel, first.Generation, command, cancellationToken: ct);
        await first.Broker.WhenReachedBeforeCommit(id).WaitAsync(Patience, ct);

        await first.Kill();
        var outcome = await running.WaitAsync(Patience, ct);

        // The caller sees only a broken stream after the request was sent: the effect is unknown, never guessed, never replayed on its own.
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.TransportLost, outcome.Reason);
        Assert.Equal(1, outcome.Attempts);
        Assert.Equal(0, store.Commits(id));
        Assert.Equal(LocalRpcCommandState.Unknown, executor.GetRecord(id)!.State);

        // The helper is relaunched under a new generation; its receipts are empty, so nothing proves anything and the command is not replayed.
        await using var second = await CommandHarness.StartAsync(store, cancellationToken: ct);
        await using var secondChannel = second.NewChannel();
        var refused = await CommandClient.CompleteAsync(executor, secondChannel, second.Generation, command, cancellationToken: ct);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, refused.Reason);
        Assert.False(refused.Sent);
        Assert.Equal(0, second.Broker.Dispatched);

        // The owner reconciles against its own durable record: nothing committed.
        var reconciled = await executor.ReconcileAsync(id, (_, token) => ValueTask.FromResult(store.Commits(id) > 0 ? LocalRpcEffect.Happened : LocalRpcEffect.DidNotHappen), ct);
        Assert.Equal(LocalRpcCommandState.Resolved, reconciled!.State);
        Assert.Equal(LocalRpcEffect.DidNotHappen, reconciled.Effect);

        // Now it certainly did not happen, so the same command id runs on the new helper and commits exactly once.
        var rerun = await CommandClient.CompleteAsync(executor, secondChannel, second.Generation, command, cancellationToken: ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, rerun.Kind);
        Assert.Equal(LocalRpcEffect.Happened, rerun.Effect);
        Assert.Equal(2, rerun.Attempts);
        Assert.Equal(1, store.Commits(id));
        await channel.DisposeAsync();
    }

    [Fact]
    public async Task AKilledHelperAfterTheCommitPointIsNeverReplayedEvenWhenTheCommandAllowsIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        var id = Guid.NewGuid();
        var first = await CommandHarness.StartAsync(store, cancellationToken: ct);
        first.Broker.ParkAfterCommit = true;
        var channel = first.NewChannel();

        // A duplicate-safe command that explicitly allows replay: it is replayed only to the launch that first received it.
        var running = CommandClient.BeginAsync(executor, channel, first.Generation, id, replay: true, cancellationToken: ct);
        await first.Broker.WhenReachedAfterCommit(id).WaitAsync(Patience, ct);
        Assert.Equal(1, store.Commits(id));

        await first.Kill();
        var outcome = await running.WaitAsync(Patience, ct);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);

        await using var second = await CommandHarness.StartAsync(store, cancellationToken: ct);
        await using var secondChannel = second.NewChannel();
        var again = await CommandClient.BeginAsync(executor, secondChannel, second.Generation, id, replay: true, cancellationToken: ct);

        // The new launch has no receipts, so a replay would run the effect a second time: it is refused, and the owner's record is the truth.
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, again.Reason);
        Assert.False(again.Sent);
        Assert.Equal(0, second.Broker.Dispatched);
        Assert.Equal(1, store.Commits(id));

        var reconciled = await executor.ReconcileAsync(id, (_, _) => ValueTask.FromResult(store.Commits(id) > 0 ? LocalRpcEffect.Happened : LocalRpcEffect.DidNotHappen), ct);
        Assert.Equal(LocalRpcCommandState.Resolved, reconciled!.State);
        Assert.Equal(LocalRpcEffect.Happened, reconciled.Effect);
        Assert.Equal(LocalRpcOutcomeKind.Success, reconciled.Kind);
        Assert.False(reconciled.HasResponse);
        var settled = await CommandClient.BeginAsync(executor, secondChannel, second.Generation, id, replay: true, cancellationToken: ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, settled.Kind);
        Assert.False(settled.Sent);
        Assert.False(settled.HasResponse);
        Assert.Equal(1, store.Commits(id));
        await channel.DisposeAsync();
    }

    [Fact]
    public async Task ALostAcknowledgementIsResolvedByReplayToTheSameLaunchAndTheEffectHappensOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        var id = Guid.NewGuid();
        await using var helper = await CommandHarness.StartAsync(store, cancellationToken: ct);
        helper.Broker.ParkAfterCommit = true;
        await using var channel = helper.NewChannel();

        // The caller abandons the call after the effect committed but before the answer: the answer is lost.
        using var abandon = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var first = CommandClient.BeginAsync(executor, channel, helper.Generation, id, replay: true, abandon.Token);
        await helper.Broker.WhenReachedAfterCommit(id).WaitAsync(Patience, ct);
        await abandon.CancelAsync();
        var lost = await first.WaitAsync(Patience, ct);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, lost.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, lost.Effect);
        helper.Broker.ReleaseAfterCommit(id);
        await BoundsHarness.WaitUntilAsync(() => helper.Receipts.Get(id) is { State: LocalRpcReceiptState.Succeeded }, "the helper to finish the abandoned effect", ct);

        // Same command id, same launch, replay explicitly allowed: the helper answers from its receipt and the effect is not run again.
        var replayed = await CommandClient.BeginAsync(executor, channel, helper.Generation, id, replay: true, cancellationToken: ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, replayed.Kind);
        Assert.Equal(LocalRpcEffect.Happened, replayed.Effect);
        Assert.True(replayed.HasResponse);
        Assert.Equal(2, replayed.Attempts);
        Assert.Equal(1, helper.Broker.EffectsStarted);
        Assert.Equal(1, store.Commits(id));
    }

    [Fact]
    public async Task ADisconnectDoesNotStopTheEffectAndAReplayJoinsOrIsAnsweredFromTheReceipt()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        var id = Guid.NewGuid();
        await using var helper = await CommandHarness.StartAsync(store, cancellationToken: ct);
        helper.Broker.ParkBeforeCommit = true;
        await using var channel = helper.NewChannel();
        var running = CommandClient.BeginAsync(executor, channel, helper.Generation, id, replay: true, ct);
        await helper.Broker.WhenReachedBeforeCommit(id).WaitAsync(Patience, ct);

        await helper.DropConnections();

        // The connection is gone and the call with it, but the effect is still running under the helper's own token.
        Assert.Equal(LocalRpcReceiptState.InFlight, helper.Receipts.Get(id)!.Value.State);
        helper.Broker.ReleaseBeforeCommit(id);

        // The replay (explicitly allowed, same launch) reconnects and gets the one effect's answer.
        var outcome = await running.WaitAsync(Patience, ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.Equal(1, helper.Broker.EffectsStarted);
        Assert.Equal(1, store.Commits(id));
        Assert.True(helper.Connects >= 2, "The retry reconnected through a new stream.");
    }

    [Fact]
    public async Task ANonIdempotentCommandWithAnUnknownEffectIsNeverReplayedAndTheContractsOwnReadReconcilesIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        var id = Guid.NewGuid();
        await using var helper = await CommandHarness.StartAsync(store, cancellationToken: ct);
        helper.Broker.ParkAfterCommit = true;
        await using var channel = helper.NewChannel();
        var command = CommandClient.CompleteCommand(id);
        using var abandon = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var first = CommandClient.CompleteAsync(executor, channel, helper.Generation, command, cancellationToken: abandon.Token);
        await helper.Broker.WhenReachedAfterCommit(id).WaitAsync(Patience, ct);
        await abandon.CancelAsync();
        Assert.Equal(LocalRpcEffect.Unknown, (await first.WaitAsync(Patience, ct)).Effect);
        helper.Broker.ReleaseAfterCommit(id);

        var again = await CommandClient.CompleteAsync(executor, channel, helper.Generation, command, cancellationToken: ct);

        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, again.Reason);
        Assert.Equal(LocalRpcEffect.Unknown, again.Effect);
        Assert.False(again.Sent);
        Assert.Equal(1, helper.Broker.Dispatched);

        // Reconciliation reads the contract's own query (GetConnection) and finds the connection: the command happened.
        var reconciled = await executor.ReconcileAsync(id, (_, token) => CommandClient.ReconcileThroughReadAsync(channel, id, token), ct);
        Assert.Equal(LocalRpcEffect.Happened, reconciled!.Effect);
        Assert.Equal(LocalRpcCommandState.Resolved, reconciled.State);
        Assert.Equal(1, store.Commits(id));
    }

    [Fact]
    public async Task CancellationProgressesThroughAReservedControlSlotWhileTheDataLaneIsSaturated()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        await using var helper = await CommandHarness.StartAsync(store, cancellationToken: ct);
        helper.Broker.ParkBeforeCommit = true;
        await using var channel = helper.NewChannel();

        // 16 running and 64 queued data commands, every one parked before its commit point.
        var ids = Enumerable.Range(0, LocalRpcLimits.DefaultMaxActiveCalls + LocalRpcLimits.DefaultMaxQueuedCalls).Select(_ => Guid.NewGuid()).ToArray();
        var calls = new List<Task<LocalRpcCommandOutcome<ConnectorBrokerServiceCompleteConnectionResponse>>>();
        foreach (var id in ids)
        {
            calls.Add(CommandClient.CompleteAsync(executor, channel, helper.Generation, CommandClient.CompleteCommand(id), cancellationToken: ct));
            await BoundsHarness.WaitUntilAsync(() => helper.Server.GetBoundsSnapshot().DataActive + helper.Server.GetBoundsSnapshot().DataQueued == calls.Count, "the call to be admitted", ct);
        }

        var saturated = helper.Server.GetBoundsSnapshot();
        Assert.Equal(LocalRpcLimits.DefaultMaxActiveCalls, saturated.DataActive);
        Assert.Equal(LocalRpcLimits.DefaultMaxQueuedCalls, saturated.DataQueued);
        var victim = ids.First(id => helper.Receipts.Get(id) is { State: LocalRpcReceiptState.InFlight });
        var queued = ids[^1];
        Assert.Null(helper.Receipts.Get(queued));
        Assert.Equal(0, saturated.ControlAdmitted.GetValueOrDefault(LocalRpcControlOperation.Cancellation));

        // A data call is refused before dispatch (the lane is full), but the cancel goes through a control slot and frees a data slot.
        var result = await executor.CancelAsync(victim, (_, token) => CommandClient.CancelThroughProbeAsync(channel, victim, token), ct);

        Assert.Equal(LocalRpcCancelDisposition.Cancelled, result.Disposition);
        Assert.True(result.Delivered);
        Assert.Equal(LocalRpcEffect.DidNotHappen, result.Record!.Effect);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, result.Record.Kind);
        var after = helper.Server.GetBoundsSnapshot();
        Assert.Equal(1, after.ControlAdmitted[LocalRpcControlOperation.Cancellation]);
        var victimOutcome = await calls[Array.IndexOf(ids, victim)].WaitAsync(Patience, ct);
        Assert.Equal(LocalRpcOutcomeKind.Cancelled, victimOutcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, victimOutcome.Effect);
        await BoundsHarness.WaitUntilAsync(() => helper.Server.GetBoundsSnapshot().DataQueued == LocalRpcLimits.DefaultMaxQueuedCalls - 1, "the oldest queued command to take the freed slot", ct);
        Assert.Equal(LocalRpcLimits.DefaultMaxActiveCalls, helper.Server.GetBoundsSnapshot().DataActive);

        // The data lane stays full for new data work while another control call (health) is still served.
        var health = await channel.CallInvoker.AsyncUnaryCall(CommandProbe.Health, null, new CallOptions(deadline: DateTime.UtcNow + Patience), [0]).ResponseAsync;
        Assert.Equal(1, health[0]);

        foreach (var id in ids)
        {
            helper.Broker.ReleaseBeforeCommit(id);
        }

        var outcomes = await Task.WhenAll(calls).WaitAsync(Patience, ct);
        Assert.Equal(ids.Length - 1, outcomes.Count(outcome => outcome.Kind == LocalRpcOutcomeKind.Success));
        Assert.Equal(ids.Length - 1, store.Total);
        Assert.Equal(0, store.Commits(victim));
    }

    [Fact]
    public async Task WithoutAReservedSlotTheSameCancelIsRefusedWhileTheDataLaneIsFull()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        var limits = new LocalRpcLimits { MaxActiveCalls = 2, MaxQueuedCalls = 0, ShutdownTimeout = TimeSpan.FromMilliseconds(100) };

        // The negative control: the cancel method is registered as an ordinary data method instead of a control method.
        await using var helper = await CommandHarness.StartAsync(store, limits, cancelIsControl: false, cancellationToken: ct);
        helper.Broker.ParkBeforeCommit = true;
        await using var channel = helper.NewChannel();
        var ids = new[] { Guid.NewGuid(), Guid.NewGuid() };
        var calls = ids.Select(id => CommandClient.CompleteAsync(executor, channel, helper.Generation, CommandClient.CompleteCommand(id), cancellationToken: ct)).ToArray();
        await BoundsHarness.WaitUntilAsync(() => helper.Server.GetBoundsSnapshot().DataActive == 2, "both slots to fill", ct);

        var result = await executor.CancelAsync(ids[0], (_, token) => CommandClient.CancelThroughProbeAsync(channel, ids[0], token), ct);

        Assert.False(result.Delivered);
        Assert.Equal(LocalRpcCancelDisposition.Requested, result.Disposition);
        Assert.Equal(1L, helper.Server.GetBoundsSnapshot().Refused[LocalRpcRefusalReason.DataQueueFull]);
        Assert.Equal(0, helper.Probe.Cancels);
        Assert.Equal(LocalRpcReceiptState.InFlight, helper.Receipts.Get(ids[0])!.Value.State);

        foreach (var id in ids)
        {
            helper.Broker.ReleaseBeforeCommit(id);
        }

        _ = await Task.WhenAll(calls).WaitAsync(Patience, ct);
    }

    [Fact]
    public async Task AnOverloadRefusalIsRetriedWithBackoffUntilASlotFreesAndThenTheCommandRunsOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor(maxAttempts: 10, pinned: true);
        var limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 0, ShutdownTimeout = TimeSpan.FromMilliseconds(100) };
        await using var helper = await CommandHarness.StartAsync(store, limits, cancellationToken: ct);
        helper.Broker.ParkBeforeCommit = true;
        await using var channel = helper.NewChannel();
        var holder = Guid.NewGuid();
        var held = CommandClient.CompleteAsync(executor, channel, helper.Generation, CommandClient.CompleteCommand(holder), cancellationToken: ct);
        await helper.Broker.WhenReachedBeforeCommit(holder).WaitAsync(Patience, ct);

        var id = Guid.NewGuid();
        var refused = CommandClient.CompleteAsync(executor, channel, helper.Generation, CommandClient.CompleteCommand(id), cancellationToken: ct);
        await BoundsHarness.WaitUntilAsync(() => helper.Server.GetBoundsSnapshot().Refused.GetValueOrDefault(LocalRpcRefusalReason.DataQueueFull) >= 2, "the command to be refused twice", ct);
        Assert.False(refused.IsCompleted);
        Assert.Equal(0, store.Commits(id));

        helper.Broker.ReleaseBeforeCommit(holder);
        helper.Broker.ReleaseBeforeCommit(id);
        var outcome = await refused.WaitAsync(Patience, ct);

        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.True(outcome.Attempts >= 3);
        Assert.Equal(1, store.Commits(id));
        Assert.Equal(LocalRpcOutcomeKind.Success, (await held.WaitAsync(Patience, ct)).Kind);
    }

    [Fact]
    public async Task AnOverloadRefusalThatNeverClearsEndsAsATypedDidNotHappenFailureThatMayBeStartedAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor(maxAttempts: 2);
        var limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 0, ShutdownTimeout = TimeSpan.FromMilliseconds(100) };
        await using var helper = await CommandHarness.StartAsync(store, limits, cancellationToken: ct);
        helper.Broker.ParkBeforeCommit = true;
        await using var channel = helper.NewChannel();
        var holder = Guid.NewGuid();
        var held = CommandClient.CompleteAsync(executor, channel, helper.Generation, CommandClient.CompleteCommand(holder), cancellationToken: ct);
        await helper.Broker.WhenReachedBeforeCommit(holder).WaitAsync(Patience, ct);

        var id = Guid.NewGuid();
        var outcome = await CommandClient.CompleteAsync(executor, channel, helper.Generation, CommandClient.CompleteCommand(id), cancellationToken: ct);

        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.Refused, outcome.Reason);
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, outcome.Refusal!.Reason);
        Assert.Equal(StatusCode.ResourceExhausted, outcome.Status);
        Assert.Equal(2, outcome.Attempts);
        Assert.Equal(LocalRpcCommandState.Resolved, executor.GetRecord(id)!.State);

        helper.Broker.ReleaseBeforeCommit(holder);
        helper.Broker.ReleaseBeforeCommit(id);
        _ = await held.WaitAsync(Patience, ct);
        var again = await CommandClient.CompleteAsync(executor, channel, helper.Generation, CommandClient.CompleteCommand(id), cancellationToken: ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, again.Kind);
        Assert.Equal(3, again.Attempts);
        Assert.Equal(1, store.Commits(id));
    }

    [Fact]
    public async Task AChannelWhoseStreamNeverOpensFailsWithAConnectFailureThatProvesNothingWasSent()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor(maxAttempts: 3);
        await using var helper = await CommandHarness.StartAsync(store, cancellationToken: ct);
        var opens = 0;
        await using var broken = LocalRpcClientChannel.CreateFromStreams(token =>
        {
            token.ThrowIfCancellationRequested();
            _ = Interlocked.Increment(ref opens);
            throw new IOException("the launcher has no stream for this child");
        });
        var id = Guid.NewGuid();

        var outcome = await CommandClient.CompleteAsync(executor, broken, helper.Generation, CommandClient.CompleteCommand(id), cancellationToken: ct);

        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.ConnectFailed, outcome.Reason);
        Assert.Equal(3, outcome.Attempts);
        Assert.True(opens >= 3);
        Assert.Equal(0, helper.Broker.Dispatched);
    }

    [Fact]
    public async Task AStreamThatTakesLongerThanTheConnectTimeoutFailsAsAConnectFailureThatProvesNothingWasSent()
    {
        var ct = TestContext.Current.CancellationToken;
        var executor = Executor(maxAttempts: 1);
        var opened = 0;
        await using var channel = LocalRpcClientChannel.CreateFromStreams(
            async token =>
            {
                _ = Interlocked.Increment(ref opened);
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                throw new InvalidOperationException("unreachable");
            },
            new LocalRpcLimits { ConnectTimeout = TimeSpan.FromMilliseconds(200) });
        var id = Guid.NewGuid();
        var generation = new LocalRpcPeerGeneration(Guid.NewGuid(), 1);

        var outcome = await CommandClient.CompleteAsync(executor, channel, generation, CommandClient.CompleteCommand(id), cancellationToken: ct);

        Assert.Equal(1, opened);
        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.ConnectFailed, outcome.Reason);
    }

    [Fact]
    public async Task ACallerWhoCancelsWhileTheStreamIsStillOpeningIsCancelledBeforeAnythingWasSent()
    {
        var ct = TestContext.Current.CancellationToken;
        var executor = Executor(maxAttempts: 1);
        var opening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var channel = LocalRpcClientChannel.CreateFromStreams(async token =>
        {
            opening.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new InvalidOperationException("unreachable");
        });
        var id = Guid.NewGuid();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var running = CommandClient.CompleteAsync(executor, channel, new LocalRpcPeerGeneration(Guid.NewGuid(), 1), CommandClient.CompleteCommand(id), cancellationToken: cancel.Token);
        await opening.Task.WaitAsync(Patience, ct);

        await cancel.CancelAsync();
        var outcome = await running.WaitAsync(Patience, ct);

        Assert.Equal(LocalRpcOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(LocalRpcEffect.DidNotHappen, outcome.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, outcome.Reason);
    }

    [Fact]
    public async Task AQueryIsRetriedOverANewConnectionAfterTheStreamDropsAndIsNotRecorded()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new OwnerStore();
        var executor = Executor();
        await using var helper = await CommandHarness.StartAsync(store, cancellationToken: ct);
        await using var channel = helper.NewChannel();
        var id = Guid.NewGuid();
        var client = new ConnectorBrokerService.ConnectorBrokerServiceClient(channel.CallInvoker);
        var query = new LocalRpcCommand(Guid.NewGuid(), ConnectorBrokerService.Descriptor.FullName + "/GetConnection", LocalRpcCommand.DigestOf(id.ToByteArray()), LocalRpcIdempotency.Query);
        _ = await client.GetConnectionAsync(BrokerDouble.Get(id), cancellationToken: ct);
        await helper.DropConnections();

        var outcome = await executor.ExecuteAsync(
            query,
            helper.Generation,
            (_, token) => client.GetConnectionAsync(BrokerDouble.Get(id), new CallOptions(deadline: DateTime.UtcNow + Patience, cancellationToken: token)).ResponseAsync,
            null,
            ct);

        // The HTTP stack may reconnect on its own before the first attempt fails, so one or two attempts are both correct.
        Assert.Equal(LocalRpcOutcomeKind.Success, outcome.Kind);
        Assert.InRange(outcome.Attempts, 1, 2);
        Assert.Equal("absent", outcome.Response!.Value.Connection.State);
        Assert.Equal(0, executor.RecordedCommands);
    }
}
