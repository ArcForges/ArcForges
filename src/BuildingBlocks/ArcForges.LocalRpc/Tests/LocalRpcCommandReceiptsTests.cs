// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCommandReceiptsTests
{
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static byte[] Digest(byte fill = 1) => Enumerable.Repeat(fill, LocalRpcCommand.DigestBytes).ToArray();

    private static long Size(string value) => value.Length;

    private static TaskCompletionSource Gate() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static (LocalRpcCommandReceipts Receipts, ManualTimeProvider Time) Table(LocalRpcCommandReceiptOptions? options = null)
    {
        var time = new ManualTimeProvider();
        return (new LocalRpcCommandReceipts(options, time), time);
    }

    private static Task<string> Run(
        LocalRpcCommandReceipts receipts,
        Guid id,
        Func<LocalRpcCommandContext, Task<string>> effect,
        byte digest = 1) =>
        receipts.ExecuteAsync(id, Digest(digest), effect, Size, Ct);

    private static Task<string> RunWith(
        LocalRpcCommandReceipts receipts,
        Guid id,
        Func<LocalRpcCommandContext, Task<string>> effect,
        CancellationToken callToken) =>
        receipts.ExecuteAsync(id, Digest(), effect, Size, callToken);

    private static async Task<RpcException> FailureOf(Task<string> call)
    {
        try
        {
            _ = await call.WaitAsync(Patience, Ct);
        }
        catch (RpcException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("The call was expected to fail.");
    }

    private static LocalRpcEffect EffectOn(RpcException exception)
    {
        Assert.True(LocalRpcCommandReceipts.TryReadEffect(exception, out var effect));
        return effect;
    }

    [Fact]
    public async Task AFirstArrivalRunsTheEffectOnceAndRecordsItsResponse()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var runs = 0;

        var response = await Run(receipts, id, _ =>
        {
            runs++;
            return Task.FromResult("done");
        });

        Assert.Equal("done", response);
        Assert.Equal(1, runs);
        Assert.Equal(1, receipts.RecordedCommands);
        Assert.Equal("done".Length, receipts.RetainedResponseBytes);
        var snapshot = receipts.Get(id)!.Value;
        Assert.Equal(LocalRpcReceiptState.Succeeded, snapshot.State);
        Assert.Equal(LocalRpcEffect.Happened, snapshot.Effect);
        Assert.False(snapshot.Committed);
        Assert.True(snapshot.ResponseRetained);
        Assert.Null(receipts.Get(Guid.NewGuid()));
    }

    [Fact]
    public async Task ADuplicateIsAnsweredFromTheRecordAndTheEffectIsNotRunAgain()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var runs = 0;
        Task<string> Effect(LocalRpcCommandContext context)
        {
            runs++;
            return Task.FromResult("answer " + runs);
        }

        var first = await Run(receipts, id, Effect);
        var second = await Run(receipts, id, Effect);
        var third = await Run(receipts, id, Effect);

        Assert.Equal("answer 1", first);
        Assert.Equal("answer 1", second);
        Assert.Equal("answer 1", third);
        Assert.Equal(1, runs);
    }

    [Fact]
    public async Task ADuplicateThatArrivesWhileTheEffectRunsJoinsItAndBothGetTheSameAnswer()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        var runs = 0;
        Task<string> Effect(LocalRpcCommandContext context)
        {
            runs++;
            return Task.Run(async () =>
            {
                await gate.Task;
                return "joined";
            });
        }

        var first = Run(receipts, id, Effect);
        var second = Run(receipts, id, Effect);
        await Task.Delay(50, Ct);
        Assert.False(first.IsCompleted);
        Assert.False(second.IsCompleted);
        gate.SetResult();

        Assert.Equal("joined", await first.WaitAsync(Patience, Ct));
        Assert.Equal("joined", await second.WaitAsync(Patience, Ct));
        Assert.Equal(1, runs);
    }

    [Fact]
    public async Task AJoinerWhoGivesUpLeavesTheEffectAndTheOtherCallUntouched()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        var first = Run(receipts, id, _ => gate.Task.ContinueWith(_ => "kept", TaskScheduler.Default));
        using var giveUp = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var joiner = RunWith(receipts, id, _ => Task.FromResult("never"), giveUp.Token);

        await giveUp.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => joiner);
        gate.SetResult();

        Assert.Equal("kept", await first.WaitAsync(Patience, Ct));
    }

    [Fact]
    public async Task TheSameIdWithAnotherInputIsRefusedBeforeTheEffectRunsWhetherTheFirstIsRunningOrDone()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var running = Guid.NewGuid();
        var done = Guid.NewGuid();
        var gate = Gate();
        var runs = 0;
        var inFlight = Run(receipts, running, _ =>
        {
            runs++;
            return gate.Task.ContinueWith(_ => "slow", TaskScheduler.Default);
        }, digest: 1);
        _ = await Run(receipts, done, _ =>
        {
            runs++;
            return Task.FromResult("quick");
        }, digest: 1);

        foreach (var id in new[] { running, done })
        {
            var conflict = await FailureOf(Run(receipts, id, _ =>
            {
                runs++;
                return Task.FromResult("must not run");
            }, digest: 2));

            Assert.Equal(StatusCode.FailedPrecondition, conflict.StatusCode);
            Assert.True(LocalRpcRefusal.TryRead(conflict, out var refusal));
            Assert.Equal(LocalRpcRefusalReason.CommandConflict, refusal!.Reason);
            Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(conflict));
        }

        Assert.Equal(2, runs);
        gate.SetResult();
        Assert.Equal("slow", await inFlight.WaitAsync(Patience, Ct));
        Assert.Equal(LocalRpcReceiptState.Succeeded, receipts.Get(running)!.Value.State);
    }

    [Fact]
    public async Task AFullTableRefusesANewCommandBeforeItsEffectRunsAndAnExistingOneStillJoins()
    {
        var (receipts, _) = Table(new LocalRpcCommandReceiptOptions { Capacity = 2 });
        await using var disposer = receipts;
        var gate = Gate();
        var ids = new[] { Guid.NewGuid(), Guid.NewGuid() };
        var calls = ids.Select(id => Run(receipts, id, _ => gate.Task.ContinueWith(_ => id.ToString(), TaskScheduler.Default))).ToArray();
        var runs = 0;

        var refused = await FailureOf(Run(receipts, Guid.NewGuid(), _ =>
        {
            runs++;
            return Task.FromResult("must not run");
        }));

        Assert.Equal(StatusCode.ResourceExhausted, refused.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(refused, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.ReceiptsFull, refusal!.Reason);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(refused));
        Assert.Equal(0, runs);
        Assert.Equal(2, receipts.RecordedCommands);
        var joined = Run(receipts, ids[0], _ => Task.FromResult("must not run"));
        gate.SetResult();
        Assert.Equal(ids[0].ToString(), await joined.WaitAsync(Patience, Ct));
        _ = await Task.WhenAll(calls).WaitAsync(Patience, Ct);
    }

    [Fact]
    public async Task ASettledCommandIsKeptForTheRetentionAndOnlyThenForgottenWithItsRetainedBytes()
    {
        var retention = TimeSpan.FromMinutes(10);
        var (receipts, time) = Table(new LocalRpcCommandReceiptOptions { Capacity = 1, Retention = retention });
        await using var disposer = receipts;
        var old = Guid.NewGuid();
        _ = await Run(receipts, old, _ => Task.FromResult("0123456789"));
        Assert.Equal(10, receipts.RetainedResponseBytes);

        time.Advance(retention - TimeSpan.FromTicks(1));
        var early = await FailureOf(Run(receipts, Guid.NewGuid(), _ => Task.FromResult("x")));
        Assert.True(LocalRpcRefusal.TryRead(early, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.ReceiptsFull, refusal!.Reason);
        Assert.NotNull(receipts.Get(old));
        Assert.Equal(10, receipts.RetainedResponseBytes);

        time.Advance(TimeSpan.FromTicks(1));
        var next = Guid.NewGuid();
        Assert.Equal("abc", await Run(receipts, next, _ => Task.FromResult("abc")));

        Assert.Null(receipts.Get(old));
        Assert.NotNull(receipts.Get(next));
        Assert.Equal(3, receipts.RetainedResponseBytes);
        Assert.Equal(1, receipts.RecordedCommands);
    }

    [Fact]
    public async Task ACommandStillRunningIsNeverForgotten()
    {
        var (receipts, time) = Table(new LocalRpcCommandReceiptOptions { Capacity = 1, Retention = TimeSpan.FromMinutes(1) });
        await using var disposer = receipts;
        var gate = Gate();
        var running = Guid.NewGuid();
        var call = Run(receipts, running, _ => gate.Task.ContinueWith(_ => "late", TaskScheduler.Default));
        time.Advance(TimeSpan.FromHours(3));

        var refused = await FailureOf(Run(receipts, Guid.NewGuid(), _ => Task.FromResult("x")));

        Assert.True(LocalRpcRefusal.TryRead(refused, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.ReceiptsFull, refusal!.Reason);
        Assert.Equal(LocalRpcReceiptState.InFlight, receipts.Get(running)!.Value.State);
        gate.SetResult();
        Assert.Equal("late", await call.WaitAsync(Patience, Ct));
    }

    [Fact]
    public async Task ADisconnectedCallDoesNotStopTheEffectAndALaterDuplicateIsAnsweredFromTheRecord()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        var runs = 0;
        var effectToken = default(CancellationToken);
        using var disconnect = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var call = RunWith(receipts, id, context =>
        {
            runs++;
            effectToken = context.CancellationToken;
            return gate.Task.ContinueWith(_ => "committed anyway", TaskScheduler.Default);
        }, disconnect.Token);

        await disconnect.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);

        Assert.False(effectToken.IsCancellationRequested);
        Assert.Equal(LocalRpcReceiptState.InFlight, receipts.Get(id)!.Value.State);
        gate.SetResult();
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id)!.Value.State == LocalRpcReceiptState.Succeeded, "the abandoned effect to finish", Ct);
        var again = await Run(receipts, id, _ => Task.FromResult("must not run"));
        Assert.Equal("committed anyway", again);
        Assert.Equal(1, runs);
    }

    [Fact]
    public async Task TheEffectsContextNamesTheCommandAndTracksItsCommitPoint()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        Guid seenId = default;
        bool before = true;
        bool after = false;

        _ = await Run(receipts, id, context =>
        {
            seenId = context.CommandId;
            before = context.IsCommitted;
            context.Commit();
            after = context.IsCommitted;
            return Task.FromResult("x");
        });

        Assert.Equal(id, seenId);
        Assert.False(before);
        Assert.True(after);
        Assert.True(receipts.Get(id)!.Value.Committed);
    }

    [Fact]
    public async Task ACancelBeforeTheCommitPointStopsTheEffectAndReportsDidNotHappenAndTheOutcomeIsStable()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var runs = 0;
        var call = Run(receipts, id, async context =>
        {
            runs++;
            await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken);
            return "never";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);

        var report = await receipts.CancelAsync(id, Ct);
        var failure = await FailureOf(call);

        Assert.Equal(LocalRpcCancelDisposition.Cancelled, report.Disposition);
        Assert.Equal(LocalRpcEffect.DidNotHappen, report.Effect);
        Assert.Equal(StatusCode.Cancelled, failure.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(failure));
        var snapshot = receipts.Get(id)!.Value;
        Assert.Equal(LocalRpcReceiptState.Cancelled, snapshot.State);
        Assert.Equal(LocalRpcEffect.DidNotHappen, snapshot.Effect);
        Assert.False(snapshot.Committed);
        Assert.False(snapshot.ResponseRetained);

        var again = await receipts.CancelAsync(id, Ct);
        Assert.Equal(LocalRpcCancelDisposition.Cancelled, again.Disposition);
        Assert.Equal(LocalRpcEffect.DidNotHappen, again.Effect);
        var duplicate = await FailureOf(Run(receipts, id, _ =>
        {
            runs++;
            return Task.FromResult("must not run");
        }));
        Assert.Equal(StatusCode.Cancelled, duplicate.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(duplicate));
        Assert.Equal(1, runs);
    }

    [Fact]
    public async Task ACancelAfterTheCommitPointIsTooLateAndTheEffectCompletesUntouched()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        CancellationToken effectToken = default;
        var call = Run(receipts, id, async context =>
        {
            effectToken = context.CancellationToken;
            context.Commit();
            await gate.Task;
            return "completed";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id)?.Committed == true, "the commit", Ct);
        Assert.Equal(LocalRpcEffect.Happened, receipts.Get(id)!.Value.Effect);
        Assert.Equal(LocalRpcReceiptState.InFlight, receipts.Get(id)!.Value.State);

        var report = await receipts.CancelAsync(id, Ct);

        Assert.Equal(LocalRpcCancelDisposition.TooLate, report.Disposition);
        Assert.Equal(LocalRpcEffect.Happened, report.Effect);
        Assert.False(effectToken.IsCancellationRequested);
        gate.SetResult();
        Assert.Equal("completed", await call.WaitAsync(Patience, Ct));
    }

    [Fact]
    public async Task ACancelOfAnUnknownCommandIsNotFound()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;

        var report = await receipts.CancelAsync(Guid.NewGuid(), Ct);

        Assert.Equal(LocalRpcCancelDisposition.NotFound, report.Disposition);
        Assert.Equal(LocalRpcEffect.Unknown, report.Effect);
    }

    [Fact]
    public async Task ACancelOfASettledCommandReportsWhatItAlreadyIs()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var succeeded = Guid.NewGuid();
        _ = await Run(receipts, succeeded, _ => Task.FromResult("ok"));
        var faulted = Guid.NewGuid();
        _ = await FailureOf(Run(receipts, faulted, _ => Task.FromException<string>(new InvalidOperationException("before commit"))));

        var a = await receipts.CancelAsync(succeeded, Ct);
        var b = await receipts.CancelAsync(faulted, Ct);

        Assert.Equal(LocalRpcCancelDisposition.TooLate, a.Disposition);
        Assert.Equal(LocalRpcEffect.Happened, a.Effect);
        Assert.Equal(LocalRpcCancelDisposition.TooLate, b.Disposition);
        Assert.Equal(LocalRpcEffect.DidNotHappen, b.Effect);
    }

    [Fact]
    public async Task AnEffectThatIgnoresTheCancelAndFinishesIsReportedAsHappenedNotAsCancelled()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        var call = Run(receipts, id, async _ =>
        {
            await gate.Task;
            return "ignored the cancel";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);

        var cancelling = receipts.CancelAsync(id, Ct);
        await Task.Delay(30, Ct);
        Assert.False(cancelling.IsCompleted);
        gate.SetResult();
        var report = await cancelling.WaitAsync(Patience, Ct);

        Assert.Equal(LocalRpcCancelDisposition.TooLate, report.Disposition);
        Assert.Equal(LocalRpcEffect.Happened, report.Effect);
        Assert.Equal("ignored the cancel", await call.WaitAsync(Patience, Ct));
        Assert.Equal(LocalRpcReceiptState.Succeeded, receipts.Get(id)!.Value.State);
    }

    [Fact]
    public async Task ACancelThatTheEffectDoesNotAnswerInTimeIsRequestedWithAnUnknownEffect()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        var call = Run(receipts, id, async _ =>
        {
            await gate.Task;
            return "late";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);
        using var controlDeadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        var report = await receipts.CancelAsync(id, controlDeadline.Token);

        Assert.Equal(LocalRpcCancelDisposition.Requested, report.Disposition);
        Assert.Equal(LocalRpcEffect.Unknown, report.Effect);
        Assert.Equal(LocalRpcReceiptState.InFlight, receipts.Get(id)!.Value.State);
        gate.SetResult();
        _ = await call.WaitAsync(Patience, Ct);
    }

    [Fact]
    public async Task AnEffectThatCommitsAfterACancelWasRequestedIsStoppedAtTheCommitPointAndNothingHappens()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        var committed = false;
        var call = Run(receipts, id, async context =>
        {
            await gate.Task;
            context.Commit();
            committed = true;
            return "must not commit";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);
        var cancelling = receipts.CancelAsync(id, Ct);

        gate.SetResult();
        var report = await cancelling.WaitAsync(Patience, Ct);
        var failure = await FailureOf(call);

        Assert.False(committed);
        Assert.Equal(LocalRpcCancelDisposition.Cancelled, report.Disposition);
        Assert.Equal(LocalRpcEffect.DidNotHappen, report.Effect);
        Assert.Equal(StatusCode.Cancelled, failure.StatusCode);
        Assert.False(receipts.Get(id)!.Value.Committed);
    }

    [Fact]
    public async Task TheEffectTimeoutCancelsTheTokenAndAnEffectThatEndsWithoutCommittingDidNotHappen()
    {
        var (receipts, time) = Table(new LocalRpcCommandReceiptOptions { EffectTimeout = TimeSpan.FromSeconds(7) });
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var call = Run(receipts, id, async context =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken);
            return "never";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);

        time.Advance(TimeSpan.FromSeconds(7) - TimeSpan.FromTicks(1));
        await Task.Delay(30, Ct);
        Assert.False(call.IsCompleted);
        time.Advance(TimeSpan.FromTicks(1));
        var failure = await FailureOf(call);

        Assert.Equal(StatusCode.DeadlineExceeded, failure.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(failure));
        Assert.Equal(LocalRpcReceiptState.Cancelled, receipts.Get(id)!.Value.State);
    }

    [Fact]
    public async Task AnEffectThatTriesToCommitAfterTheTimeoutIsStopped()
    {
        var (receipts, time) = Table(new LocalRpcCommandReceiptOptions { EffectTimeout = TimeSpan.FromSeconds(1) });
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var gate = Gate();
        var call = Run(receipts, id, async context =>
        {
            await gate.Task;
            context.Commit();
            return "must not commit";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);
        time.Advance(TimeSpan.FromSeconds(1));

        gate.SetResult();
        var failure = await FailureOf(call);

        Assert.Equal(StatusCode.DeadlineExceeded, failure.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(failure));
        Assert.False(receipts.Get(id)!.Value.Committed);
    }

    [Fact]
    public async Task AnEffectThatFailsBeforeItsCommitPointDidNotHappenAndOneThatFailsAfterItDid()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var before = Guid.NewGuid();
        var after = Guid.NewGuid();
        var cancelledAfter = Guid.NewGuid();

        var a = await FailureOf(Run(receipts, before, _ => Task.FromException<string>(new InvalidOperationException("secret detail"))));
        var b = await FailureOf(Run(receipts, after, context =>
        {
            context.Commit();
            return Task.FromException<string>(new InvalidOperationException("after commit"));
        }));
        var c = await FailureOf(Run(receipts, cancelledAfter, context =>
        {
            context.Commit();
            return Task.FromException<string>(new OperationCanceledException());
        }));

        Assert.Equal(StatusCode.Internal, a.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(a));
        Assert.DoesNotContain("secret", a.Status.Detail, StringComparison.Ordinal);
        Assert.Equal(StatusCode.Internal, b.StatusCode);
        Assert.Equal(LocalRpcEffect.Happened, EffectOn(b));
        Assert.Equal(LocalRpcEffect.Happened, EffectOn(c));
        Assert.Equal(LocalRpcReceiptState.Faulted, receipts.Get(before)!.Value.State);
        Assert.Equal(LocalRpcEffect.DidNotHappen, receipts.Get(before)!.Value.Effect);
        Assert.Equal(LocalRpcEffect.Happened, receipts.Get(after)!.Value.Effect);
        Assert.Equal(LocalRpcReceiptState.Faulted, receipts.Get(cancelledAfter)!.Value.State);
        Assert.True(receipts.Get(after)!.Value.Committed);
    }

    [Fact]
    public async Task AnEffectThatThrowsBeforeItReturnsATaskIsRecordedLikeOneThatThrowsLater()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;
        var id = Guid.NewGuid();
        var runs = 0;

        var failure = await FailureOf(Run(receipts, id, _ =>
        {
            runs++;
            throw new InvalidOperationException("sync");
        }));
        var duplicate = await FailureOf(Run(receipts, id, _ =>
        {
            runs++;
            return Task.FromResult("must not run");
        }));

        Assert.Equal(StatusCode.Internal, failure.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(failure));
        Assert.Equal(StatusCode.Internal, duplicate.StatusCode);
        Assert.Equal(1, runs);
    }

    [Fact]
    public async Task AnRpcExceptionFromTheEffectKeepsItsStatusCodeButNotItsMessageAndAnOkStatusBecomesInternal()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;

        var notFound = await FailureOf(Run(receipts, Guid.NewGuid(), _ => Task.FromException<string>(new RpcException(new Status(StatusCode.NotFound, "internal path C:\\secret")))));
        var ok = await FailureOf(Run(receipts, Guid.NewGuid(), _ => Task.FromException<string>(new RpcException(new Status(StatusCode.OK, "odd")))));

        Assert.Equal(StatusCode.NotFound, notFound.StatusCode);
        Assert.DoesNotContain("secret", notFound.Status.Detail, StringComparison.Ordinal);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(notFound));
        Assert.Equal(StatusCode.Internal, ok.StatusCode);
    }

    [Fact]
    public async Task AnEffectsResponseIsKeptWithinTheByteBudgetAndTheOldestIsDroppedFirst()
    {
        var (receipts, _) = Table(new LocalRpcCommandReceiptOptions { MaxRetainedResponseBytes = 100 });
        await using var disposer = receipts;
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var c = Guid.NewGuid();
        _ = await Run(receipts, a, _ => Task.FromResult(new string('a', 50)));
        _ = await Run(receipts, b, _ => Task.FromResult(new string('b', 50)));

        // Exactly the budget: both are kept.
        Assert.Equal(100, receipts.RetainedResponseBytes);
        Assert.True(receipts.Get(a)!.Value.ResponseRetained);
        Assert.True(receipts.Get(b)!.Value.ResponseRetained);

        _ = await Run(receipts, c, _ => Task.FromResult("c"));

        Assert.Equal(51, receipts.RetainedResponseBytes);
        Assert.False(receipts.Get(a)!.Value.ResponseRetained);
        Assert.True(receipts.Get(b)!.Value.ResponseRetained);
        Assert.True(receipts.Get(c)!.Value.ResponseRetained);
        Assert.Equal(LocalRpcReceiptState.Succeeded, receipts.Get(a)!.Value.State);

        // The dropped response is not run again; the effect is reported as happened and the response as not retained.
        var failure = await FailureOf(Run(receipts, a, _ => Task.FromResult("must not run")));
        Assert.Equal(StatusCode.FailedPrecondition, failure.StatusCode);
        Assert.Equal(LocalRpcEffect.Happened, EffectOn(failure));
        Assert.Equal(new string('b', 50), await Run(receipts, b, _ => Task.FromResult("must not run")));
    }

    [Fact]
    public async Task AResponseLargerThanTheWholeBudgetIsNotKeptAndTheOthersAreNotDroppedForIt()
    {
        var (receipts, _) = Table(new LocalRpcCommandReceiptOptions { MaxRetainedResponseBytes = 100 });
        await using var disposer = receipts;
        var small = Guid.NewGuid();
        var huge = Guid.NewGuid();
        _ = await Run(receipts, small, _ => Task.FromResult("small"));

        var response = await Run(receipts, huge, _ => Task.FromResult(new string('h', 101)));

        Assert.Equal(101, response.Length);
        Assert.False(receipts.Get(huge)!.Value.ResponseRetained);
        Assert.Equal(LocalRpcReceiptState.Succeeded, receipts.Get(huge)!.Value.State);
        Assert.True(receipts.Get(small)!.Value.ResponseRetained);
        Assert.Equal(5, receipts.RetainedResponseBytes);
    }

    [Fact]
    public async Task ASizeThatCannotBeComputedOrIsNegativeIsHandledWithoutBreakingTheCommand()
    {
        var (receipts, _) = Table(new LocalRpcCommandReceiptOptions { MaxRetainedResponseBytes = 10 });
        await using var disposer = receipts;
        var throwing = Guid.NewGuid();
        var negative = Guid.NewGuid();

        var a = await receipts.ExecuteAsync(throwing, Digest(), _ => Task.FromResult("x"), _ => throw new NotSupportedException(), Ct);
        var b = await receipts.ExecuteAsync(negative, Digest(), _ => Task.FromResult("y"), _ => -5, Ct);

        Assert.Equal("x", a);
        Assert.Equal("y", b);
        Assert.False(receipts.Get(throwing)!.Value.ResponseRetained);
        Assert.True(receipts.Get(negative)!.Value.ResponseRetained);
        Assert.Equal(0, receipts.RetainedResponseBytes);
    }

    [Fact]
    public async Task DisposingCancelsRunningEffectsWaitsForThemAndRefusesNewCommands()
    {
        var (receipts, _) = Table();
        var id = Guid.NewGuid();
        var call = Run(receipts, id, async context =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken);
            return "never";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);

        await receipts.DisposeAsync();
        await receipts.DisposeAsync();
        var failure = await FailureOf(call);

        Assert.Equal(StatusCode.Unavailable, failure.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(failure));
        Assert.Equal(LocalRpcReceiptState.Cancelled, receipts.Get(id)!.Value.State);
        var refused = await FailureOf(Run(receipts, Guid.NewGuid(), _ => Task.FromResult("must not run")));
        Assert.Equal(StatusCode.Unavailable, refused.StatusCode);
        Assert.Equal(LocalRpcEffect.DidNotHappen, EffectOn(refused));
    }

    [Fact]
    public async Task DisposingReturnsAfterTheShutdownBoundEvenIfAnEffectIgnoresItsToken()
    {
        var receipts = new LocalRpcCommandReceipts(new LocalRpcCommandReceiptOptions { ShutdownTimeout = TimeSpan.FromMilliseconds(200) });
        var gate = Gate();
        var id = Guid.NewGuid();
        var call = Run(receipts, id, async _ =>
        {
            await gate.Task;
            return "late";
        });
        await BoundsHarness.WaitUntilAsync(() => receipts.Get(id) is not null, "the effect to start", Ct);
        var started = System.Diagnostics.Stopwatch.GetTimestamp();

        await receipts.DisposeAsync();

        var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(started);
        Assert.InRange(elapsed, TimeSpan.FromMilliseconds(150), TimeSpan.FromSeconds(10));
        Assert.Equal(LocalRpcReceiptState.InFlight, receipts.Get(id)!.Value.State);
        gate.SetResult();
        _ = await call.WaitAsync(Patience, Ct);
    }

    [Fact]
    public async Task OptionsAreValidatedAndHaveTheDocumentedDefaults()
    {
        var defaults = new LocalRpcCommandReceiptOptions();
        Assert.Equal(1024, defaults.Capacity);
        Assert.Equal(TimeSpan.FromMinutes(10), defaults.Retention);
        Assert.Equal(TimeSpan.FromSeconds(30), defaults.EffectTimeout);
        Assert.Equal(32L * 1024 * 1024, defaults.MaxRetainedResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(5), defaults.ShutdownTimeout);
        Assert.True(new LocalRpcCommandExecutorOptions().ReplayWindow < defaults.Retention, "The parent replays within the time the helper keeps receipts.");
        await using var one = new LocalRpcCommandReceipts();
        await using var two = new LocalRpcCommandReceipts(new LocalRpcCommandReceiptOptions { Capacity = 65536, Retention = TimeSpan.FromHours(24), EffectTimeout = TimeSpan.FromMinutes(10), MaxRetainedResponseBytes = 1L << 32, ShutdownTimeout = TimeSpan.FromMinutes(1) });
        await using var three = new LocalRpcCommandReceipts(new LocalRpcCommandReceiptOptions { Capacity = 1, Retention = TimeSpan.FromTicks(1), EffectTimeout = TimeSpan.FromSeconds(1), MaxRetainedResponseBytes = 0, ShutdownTimeout = TimeSpan.Zero });

        foreach (var invalid in new LocalRpcCommandReceiptOptions[]
        {
            new() { Capacity = 0 },
            new() { Capacity = 65537 },
            new() { Retention = TimeSpan.Zero },
            new() { Retention = TimeSpan.FromHours(24) + TimeSpan.FromTicks(1) },
            new() { EffectTimeout = TimeSpan.FromSeconds(1) - TimeSpan.FromTicks(1) },
            new() { EffectTimeout = TimeSpan.FromMinutes(10) + TimeSpan.FromTicks(1) },
            new() { MaxRetainedResponseBytes = -1 },
            new() { MaxRetainedResponseBytes = (1L << 32) + 1 },
            new() { ShutdownTimeout = TimeSpan.FromTicks(-1) },
            new() { ShutdownTimeout = TimeSpan.FromMinutes(1) + TimeSpan.FromTicks(1) },
        })
        {
            _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcCommandReceipts(invalid));
        }
    }

    [Fact]
    public async Task ArgumentsAreValidated()
    {
        var (receipts, _) = Table();
        await using var disposer = receipts;

        _ = await Assert.ThrowsAsync<ArgumentException>(() => receipts.ExecuteAsync(Guid.Empty, Digest(), _ => Task.FromResult("x"), Size, Ct));
        foreach (var length in new[] { 0, 31, 33 })
        {
            _ = await Assert.ThrowsAsync<ArgumentException>(() => receipts.ExecuteAsync(Guid.NewGuid(), new byte[length], _ => Task.FromResult("x"), Size, Ct));
        }

        _ = await Assert.ThrowsAsync<ArgumentNullException>(() => receipts.ExecuteAsync<string>(Guid.NewGuid(), Digest(), null!, Size, Ct));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(() => receipts.ExecuteAsync(Guid.NewGuid(), Digest(), _ => Task.FromResult("x"), null!, Ct));
        Assert.Equal(0, receipts.RecordedCommands);
    }

    [Theory]
    [InlineData("did-not-happen", true, LocalRpcEffect.DidNotHappen)]
    [InlineData("happened", true, LocalRpcEffect.Happened)]
    [InlineData("unknown", true, LocalRpcEffect.Unknown)]
    [InlineData("Unknown", false, default(LocalRpcEffect))]
    [InlineData("", false, default(LocalRpcEffect))]
    public void TheEffectTrailerReadsOnlyItsThreeNames(string text, bool expected, LocalRpcEffect effect)
    {
        var exception = new RpcException(new Status(StatusCode.Internal, "x"), new Metadata { { LocalRpcCommandReceipts.EffectTrailer, text } });

        Assert.Equal(expected, LocalRpcCommandReceipts.TryReadEffect(exception, out var read));
        Assert.Equal(effect, read);
        Assert.False(LocalRpcCommandReceipts.TryReadEffect(new RpcException(new Status(StatusCode.Internal, "x")), out _));
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcCommandReceipts.TryReadEffect(null!, out _));
    }

    [Fact]
    public async Task ManyThreadsRunningTheSameCommandsAndCancellingThemRunEachEffectAtMostOnceAndAllSettle()
    {
        await using var receipts = new LocalRpcCommandReceipts(new LocalRpcCommandReceiptOptions { Capacity = 4096 });
        const int commands = 120;
        var ids = Enumerable.Range(0, commands).Select(_ => Guid.NewGuid()).ToArray();
        var runs = new ConcurrentDictionary<Guid, int>();
        var committed = new ConcurrentDictionary<Guid, int>();

        Task<string> Effect(Guid id, LocalRpcCommandContext context) => Task.Run(async () =>
        {
            _ = runs.AddOrUpdate(id, 1, (_, count) => count + 1);
            await Task.Delay(RandomNumberGenerator.GetInt32(5), context.CancellationToken);
            context.Commit();
            _ = committed.AddOrUpdate(id, 1, (_, count) => count + 1);
            return id.ToString();
        });

        var calls = new List<Task>();
        foreach (var id in ids)
        {
            for (var copy = 0; copy < 4; copy++)
            {
                calls.Add(Task.Run(async () =>
                {
                    try
                    {
                        _ = await receipts.ExecuteAsync(id, Digest(), context => Effect(id, context), Size, Ct);
                    }
                    catch (RpcException)
                    {
                        // A cancelled command is reported as a typed failure.
                    }
                }, Ct));
            }

            if (RandomNumberGenerator.GetInt32(3) == 0)
            {
                calls.Add(Task.Run(async () => _ = await receipts.CancelAsync(id, Ct), Ct));
            }
        }

        await Task.WhenAll(calls).WaitAsync(TimeSpan.FromSeconds(60), Ct);

        foreach (var id in ids)
        {
            var snapshot = receipts.Get(id)!.Value;
            Assert.NotEqual(LocalRpcReceiptState.InFlight, snapshot.State);
            Assert.True(runs.GetValueOrDefault(id) == 1, "An effect runs once however many times its command arrives.");
            Assert.True(committed.GetValueOrDefault(id) <= 1);
            Assert.Equal(snapshot.State == LocalRpcReceiptState.Succeeded, committed.GetValueOrDefault(id) == 1);
            if (snapshot.State == LocalRpcReceiptState.Cancelled)
            {
                Assert.Equal(LocalRpcEffect.DidNotHappen, snapshot.Effect);
                Assert.Equal(0, committed.GetValueOrDefault(id));
            }
        }
    }
}
