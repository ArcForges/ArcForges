// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Callbacks travel over a separately provisioned parent-created channel with its own lanes. A call made from inside a
/// handler never waits for a slot, and a callback handler cannot call again, so two saturated lanes cannot wait on each other.
/// </summary>
// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCallbackTests
{
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    [Fact]
    public async Task ACallbackHandlerThatCallsAgainIsRefusedLocallyAndNothingIsSent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var primary = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var callback = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var toPrimary = primary.NewChannel();
        await using var toCallback = callback.NewChannel();
        await using var callbackBackToPrimary = primary.NewChannel();
        primary.Probe.RelayAction = async cancellation => Describe(await Outcome(new ProbeClient(toCallback.CallInvoker).Callback()));
        callback.Probe.CallbackAction = async cancellation =>
            await Outcome(new ProbeClient(callbackBackToPrimary.CallInvoker).Work(77, deadline: DateTime.UtcNow + Patience));

        var answer = Encoding.ASCII.GetString(await new ProbeClient(toPrimary.CallInvoker).Relay().ResponseAsync.WaitAsync(Patience, ct));

        // The relay reached the callback server, whose handler tried a further call and was refused before any byte was sent.
        Assert.Equal("ok:FailedPrecondition|RecursiveCallback", answer);
        Assert.Equal(1, callback.Probe.CallbackRuns);
        Assert.Empty(primary.Probe.Started);
        // The callback handler's own channel to the primary never opened a stream: the call was refused before it was sent.
        Assert.Equal(1, primary.Connects);
        // Only the relay itself was admitted by the primary; the callback handler's call never reached it.
        Assert.Equal(1, primary.Server.GetBoundsSnapshot().DataAdmitted);
    }

    [Fact]
    public async Task ACallbackIsRefusedAtOnceWhenTheCallbackLaneIsFullInsteadOfWaiting()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 5 };
        await using var primary = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var callback = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        await using var toPrimary = primary.NewChannel();
        await using var toCallback = callback.NewChannel();
        primary.Probe.RelayAction = async cancellation => Describe(await Outcome(new ProbeClient(toCallback.CallInvoker).Callback()));
        callback.Probe.CallbackAction = _ => Task.FromResult("ran");
        // The holder and the ordinary call use the same connection the callback arrives on, so they fill its lane.
        var directClient = new ProbeClient(toCallback.CallInvoker);
        var holder = directClient.Work(1, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => callback.Probe.Running == 1, "the callback lane to fill", ct);
        var ordinary = directClient.Work(2, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => callback.Server.GetBoundsSnapshot().DataQueued == 1, "an ordinary call to queue", ct);

        var refused = Encoding.ASCII.GetString(await new ProbeClient(toPrimary.CallInvoker).Relay().ResponseAsync.WaitAsync(Patience, ct));

        // An ordinary call queued behind the holder; the callback was refused at once and did not join the queue.
        Assert.Equal("ok:ResourceExhausted|CallbackNotQueued", refused);
        var snapshot = callback.Server.GetBoundsSnapshot();
        Assert.Equal(1, snapshot.DataQueued);
        Assert.Equal(1, snapshot.Refused[LocalRpcRefusalReason.CallbackNotQueued]);
        Assert.Equal(0, callback.Probe.CallbackRuns);

        Assert.True(callback.Probe.Release(1));
        await BoundsHarness.WaitUntilAsync(() => callback.Probe.Started.Count == 2, "the ordinary call to start", ct);
        Assert.True(callback.Probe.Release(2));
        _ = await Task.WhenAll(holder.ResponseAsync, ordinary.ResponseAsync).WaitAsync(Patience, ct);

        // With a free slot the same callback is served.
        var served = Encoding.ASCII.GetString(await new ProbeClient(toPrimary.CallInvoker).Relay().ResponseAsync.WaitAsync(Patience, ct));
        Assert.Equal("ok:ran", served);
        Assert.Equal(1, callback.Probe.CallbackRuns);
    }

    [Fact]
    public async Task TheCallbackMarkNeverLeaksOutOfAHandlerIntoTheNextCall()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var primary = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var callback = await BoundsHarness.StartAsync(new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 5 }, cancellationToken: ct);
        await using var toPrimary = primary.NewChannel();
        await using var toCallback = callback.NewChannel();
        callback.Probe.CallbackAction = _ => Task.FromResult("ran");
        primary.Probe.RelayAction = async cancellation => Describe(await Outcome(new ProbeClient(toCallback.CallInvoker).Callback()));
        var client = new ProbeClient(toPrimary.CallInvoker);

        _ = await client.Relay().ResponseAsync.WaitAsync(Patience, ct);
        _ = await client.Relay().ResponseAsync.WaitAsync(Patience, ct);

        Assert.Null(LocalRpcCallbackGuard.CurrentDepth);
        Assert.Equal(2, callback.Probe.CallbackRuns);
    }

    private static string Describe(string outcome) => "ok:" + outcome;

    private static async Task<string> Outcome(AsyncUnaryCall<byte[]> call)
    {
        try
        {
            return Encoding.ASCII.GetString(await call.ResponseAsync.ConfigureAwait(false));
        }
        catch (RpcException failure)
        {
            _ = LocalRpcRefusal.TryRead(failure, out var refusal);
            return failure.StatusCode + "|" + refusal?.Reason;
        }
    }
}
