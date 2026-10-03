// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Http;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>Builds the failures a send delegate can see, with the exact trailers the peer's layers attach.</summary>
internal static class Failures
{
    internal static RpcException Refusal(LocalRpcRefusalReason reason, StatusCode status = StatusCode.ResourceExhausted, bool dispatchedZero = true)
    {
        var trailers = new Metadata { { LocalRpcRefusal.ReasonTrailer, LocalRpcRefusal.NameOf(reason) } };
        if (dispatchedZero)
        {
            trailers.Add(LocalRpcRefusal.DispatchedTrailer, "0");
        }

        return new RpcException(new Status(status, "refused"), trailers);
    }

    internal static RpcException Effect(StatusCode status, string effectText) =>
        new(new Status(status, "reported"), new Metadata { { LocalRpcCommandReceipts.EffectTrailer, effectText } });

    internal static RpcException Status(StatusCode status, Exception? debug = null) => new(new Status(status, "failed", debug));

    internal static RpcException Unavailable() => Status(StatusCode.Unavailable);

    internal static RpcException Connect(StatusCode status = StatusCode.Unavailable) =>
        Status(status, new HttpRequestException("connect", new LocalRpcConnectException("no stream", new IOException("closed"))));
}

[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcFailureClassifierTests
{
    private static LocalRpcAttemptFailure Classify(Exception exception, bool callerCancelled = false)
    {
        using var source = new CancellationTokenSource();
        if (callerCancelled)
        {
            source.Cancel();
        }

        return LocalRpcFailureClassifier.Classify(exception, source.Token) ?? throw new InvalidOperationException("Not classified.");
    }

    [Theory]
    [InlineData(LocalRpcRefusalReason.DataQueueFull)]
    [InlineData(LocalRpcRefusalReason.ControlBusy)]
    [InlineData(LocalRpcRefusalReason.DeadlineBeforeDispatch)]
    [InlineData(LocalRpcRefusalReason.CallbackNotQueued)]
    [InlineData(LocalRpcRefusalReason.RecursiveCallback)]
    [InlineData(LocalRpcRefusalReason.CommandConflict)]
    [InlineData(LocalRpcRefusalReason.ReceiptsFull)]
    public void ATypedRefusalMarkedNotDispatchedProvesTheEffectDidNotHappen(LocalRpcRefusalReason reason)
    {
        var failure = Classify(Failures.Refusal(reason, LocalRpcRefusal.StatusOf(reason)));

        Assert.Equal(LocalRpcEffect.DidNotHappen, failure.Effect);
        Assert.Equal(LocalRpcFailureReason.Refused, failure.Reason);
        Assert.Equal(reason, failure.Refusal!.Reason);
        Assert.Equal(LocalRpcRefusal.StatusOf(reason), failure.Status);
        Assert.False(failure.CancelledByCaller);
    }

    [Fact]
    public void ARefusalTrailerWithoutTheNotDispatchedMarkProvesNothing()
    {
        var failure = Classify(Failures.Refusal(LocalRpcRefusalReason.DataQueueFull, dispatchedZero: false));

        Assert.Equal(LocalRpcEffect.Unknown, failure.Effect);
        Assert.Equal(LocalRpcFailureReason.PeerError, failure.Reason);
        Assert.Null(failure.Refusal);
    }

    [Theory]
    [InlineData("did-not-happen", LocalRpcEffect.DidNotHappen)]
    [InlineData("happened", LocalRpcEffect.Happened)]
    [InlineData("unknown", LocalRpcEffect.Unknown)]
    public void AnEffectTrailerFromThePeersReceiptLayerIsTheEffectItNames(string text, LocalRpcEffect expected)
    {
        var failure = Classify(Failures.Effect(StatusCode.Cancelled, text));

        Assert.Equal(expected, failure.Effect);
        Assert.Equal(LocalRpcFailureReason.ReportedByPeer, failure.Reason);
        Assert.Equal(StatusCode.Cancelled, failure.Status);
        Assert.Null(failure.Refusal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Happened")]
    [InlineData("did_not_happen")]
    [InlineData("1")]
    public void AnEffectTrailerThatIsNotOneOfTheThreeNamesIsIgnored(string text)
    {
        var failure = Classify(Failures.Effect(StatusCode.Internal, text));

        Assert.Equal(LocalRpcEffect.Unknown, failure.Effect);
        Assert.Equal(LocalRpcFailureReason.PeerError, failure.Reason);
    }

    [Fact]
    public void ABinaryTrailerNamedLikeTheEffectTrailerIsIgnored()
    {
        var exception = new RpcException(new Status(StatusCode.Internal, "x"), new Metadata { { LocalRpcCommandReceipts.EffectTrailer + "-bin", [1, 2] } });

        Assert.False(LocalRpcCommandReceipts.TryReadEffect(exception, out _));
        Assert.Equal(LocalRpcEffect.Unknown, Classify(exception).Effect);
    }

    [Fact]
    public void ATypedRefusalOutranksAnEffectTrailerOnTheSameFailure()
    {
        var exception = new RpcException(
            new Status(StatusCode.ResourceExhausted, "both"),
            new Metadata
            {
                { LocalRpcCommandReceipts.EffectTrailer, "happened" },
                { LocalRpcRefusal.ReasonTrailer, LocalRpcRefusal.NameOf(LocalRpcRefusalReason.DataQueueFull) },
                { LocalRpcRefusal.DispatchedTrailer, "0" },
            });

        var failure = Classify(exception);

        Assert.Equal(LocalRpcFailureReason.Refused, failure.Reason);
        Assert.Equal(LocalRpcEffect.DidNotHappen, failure.Effect);
    }

    [Theory]
    [InlineData(StatusCode.Unavailable, LocalRpcFailureReason.TransportLost)]
    [InlineData(StatusCode.Cancelled, LocalRpcFailureReason.TransportLost)]
    [InlineData(StatusCode.Aborted, LocalRpcFailureReason.TransportLost)]
    [InlineData(StatusCode.DeadlineExceeded, LocalRpcFailureReason.DeadlineExceeded)]
    [InlineData(StatusCode.Internal, LocalRpcFailureReason.PeerError)]
    [InlineData(StatusCode.Unknown, LocalRpcFailureReason.PeerError)]
    [InlineData(StatusCode.InvalidArgument, LocalRpcFailureReason.PeerError)]
    [InlineData(StatusCode.Unimplemented, LocalRpcFailureReason.PeerError)]
    [InlineData(StatusCode.FailedPrecondition, LocalRpcFailureReason.PeerError)]
    public void AnyOtherStatusAfterARequestMayHaveBeenSentLeavesTheEffectUnknown(StatusCode status, LocalRpcFailureReason reason)
    {
        var failure = Classify(Failures.Status(status));

        Assert.Equal(LocalRpcEffect.Unknown, failure.Effect);
        Assert.Equal(reason, failure.Reason);
        Assert.Equal(status, failure.Status);
        Assert.False(failure.CancelledByCaller);
    }

    [Fact]
    public void ACancelledStatusWhileTheCallersTokenIsCancelledIsTheCallersCancellation()
    {
        var failure = Classify(Failures.Status(StatusCode.Cancelled), callerCancelled: true);

        Assert.Equal(LocalRpcEffect.Unknown, failure.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, failure.Reason);
        Assert.True(failure.CancelledByCaller);
    }

    [Fact]
    public void AnUnavailableStatusIsNotTheCallersCancellationEvenIfTheTokenIsCancelled()
    {
        var failure = Classify(Failures.Unavailable(), callerCancelled: true);

        Assert.Equal(LocalRpcFailureReason.TransportLost, failure.Reason);
        Assert.False(failure.CancelledByCaller);
    }

    [Theory]
    [InlineData(false, LocalRpcFailureReason.ConnectFailed, false)]
    [InlineData(true, LocalRpcFailureReason.CancelledByCaller, true)]
    public void AConnectFailureInTheStatusDebugChainProvesNothingWasSent(bool callerCancelled, LocalRpcFailureReason reason, bool cancelledByCaller)
    {
        var failure = Classify(Failures.Connect(), callerCancelled);

        Assert.Equal(LocalRpcEffect.DidNotHappen, failure.Effect);
        Assert.Equal(reason, failure.Reason);
        Assert.Equal(cancelledByCaller, failure.CancelledByCaller);
        Assert.Equal(StatusCode.Unavailable, failure.Status);
    }

    [Fact]
    public void AConnectFailureCarriedByTheExceptionItselfCountsToo()
    {
        var failure = Classify(new LocalRpcConnectException("none", new IOException()));

        Assert.Equal(LocalRpcEffect.DidNotHappen, failure.Effect);
        Assert.Equal(LocalRpcFailureReason.ConnectFailed, failure.Reason);
        Assert.Null(failure.Status);
    }

    [Fact]
    public void ACancellationWhoseChainHoldsAConnectFailureProvesNothingWasSentWhoeverCancelled()
    {
        var chain = new OperationCanceledException("connect", new LocalRpcConnectException("none", new IOException()));

        Assert.Equal(LocalRpcFailureReason.ConnectFailed, Classify(chain).Reason);
        Assert.Equal(LocalRpcEffect.DidNotHappen, Classify(chain).Effect);
        var cancelled = Classify(chain, callerCancelled: true);
        Assert.Equal(LocalRpcEffect.DidNotHappen, cancelled.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, cancelled.Reason);
        Assert.True(cancelled.CancelledByCaller);
    }

    [Fact]
    public void ACancellationWithoutAConnectFailureIsTheCallersOrATransportLoss()
    {
        var callers = Classify(new OperationCanceledException(), callerCancelled: true);
        Assert.Equal(LocalRpcEffect.Unknown, callers.Effect);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, callers.Reason);
        Assert.True(callers.CancelledByCaller);

        var other = Classify(new OperationCanceledException());
        Assert.Equal(LocalRpcEffect.Unknown, other.Effect);
        Assert.Equal(LocalRpcFailureReason.TransportLost, other.Reason);
        Assert.False(other.CancelledByCaller);
        Assert.Equal(LocalRpcFailureReason.CancelledByCaller, Classify(new TaskCanceledException(), callerCancelled: true).Reason);
    }

    [Fact]
    public void AnIoOrHttpFailureIsATransportLossUnlessItsChainHoldsAConnectFailure()
    {
        Assert.Equal(LocalRpcFailureReason.TransportLost, Classify(new IOException("reset")).Reason);
        Assert.Equal(LocalRpcEffect.Unknown, Classify(new IOException("reset")).Effect);
        Assert.Equal(LocalRpcFailureReason.TransportLost, Classify(new HttpRequestException("reset")).Reason);
        Assert.Equal(LocalRpcFailureReason.ConnectFailed, Classify(new IOException("x", new LocalRpcConnectException("none", new InvalidOperationException()))).Reason);
        Assert.Equal(LocalRpcEffect.DidNotHappen, Classify(new HttpRequestException("x", new LocalRpcConnectException("none", new InvalidOperationException()))).Effect);
    }

    [Fact]
    public void AnExceptionThatIsNotATransportFailureIsNotClassified()
    {
        using var source = new CancellationTokenSource();

        Assert.Null(LocalRpcFailureClassifier.Classify(new InvalidOperationException("bug"), source.Token));
        Assert.Null(LocalRpcFailureClassifier.Classify(new ArgumentException("bug"), source.Token));
        Assert.Null(LocalRpcFailureClassifier.Classify(new NotSupportedException(), source.Token));
        Assert.Null(LocalRpcFailureClassifier.Classify(new InvalidOperationException("bug", new LocalRpcConnectException("none", new IOException())), source.Token));
    }

    [Fact]
    public void ChainSearchFindsAConnectFailureAtAnyDepthUpToTheBoundAndInsideAggregates()
    {
        static Exception Chain(int depth, Exception bottom)
        {
            var exception = bottom;
            for (var level = 0; level < depth; level++)
            {
                exception = new InvalidOperationException("level " + level, exception);
            }

            return exception;
        }

        var marker = new LocalRpcConnectException("none", new IOException());

        Assert.True(LocalRpcFailureClassifier.ChainContainsConnectFailure(marker));
        Assert.True(LocalRpcFailureClassifier.ChainContainsConnectFailure(Chain(10, marker)));
        Assert.True(LocalRpcFailureClassifier.ChainContainsConnectFailure(Chain(15, marker)));
        Assert.False(LocalRpcFailureClassifier.ChainContainsConnectFailure(Chain(16, marker)));
        Assert.False(LocalRpcFailureClassifier.ChainContainsConnectFailure(Chain(40, marker)));
        Assert.False(LocalRpcFailureClassifier.ChainContainsConnectFailure(null));
        Assert.False(LocalRpcFailureClassifier.ChainContainsConnectFailure(Chain(5, new IOException())));
        Assert.True(LocalRpcFailureClassifier.ChainContainsConnectFailure(new AggregateException(new IOException(), Chain(3, marker))));
        Assert.False(LocalRpcFailureClassifier.ChainContainsConnectFailure(new AggregateException(new IOException(), new InvalidOperationException())));
        Assert.False(LocalRpcFailureClassifier.ChainContainsConnectFailure(new AggregateException()));
    }

    [Theory]
    [InlineData(LocalRpcRefusalReason.DataQueueFull, true)]
    [InlineData(LocalRpcRefusalReason.ControlBusy, true)]
    [InlineData(LocalRpcRefusalReason.DeadlineBeforeDispatch, true)]
    [InlineData(LocalRpcRefusalReason.CallbackNotQueued, true)]
    [InlineData(LocalRpcRefusalReason.ReceiptsFull, true)]
    [InlineData(LocalRpcRefusalReason.RecursiveCallback, false)]
    [InlineData(LocalRpcRefusalReason.CommandConflict, false)]
    public void OnlyARefusalThatMayClearIsTransient(LocalRpcRefusalReason reason, bool transient)
    {
        Assert.Equal(transient, LocalRpcFailureClassifier.IsTransient(new LocalRpcRefusal(reason)));
    }

    [Fact]
    public void TheConnectExceptionKeepsItsMessageAndCause()
    {
        var cause = new IOException("closed");

        var exception = new LocalRpcConnectException("none", cause);

        Assert.Equal("none", exception.Message);
        Assert.Same(cause, exception.InnerException);
        Assert.IsAssignableFrom<IOException>(exception);
        Assert.Equal("boom", new LocalRpcConnectException("boom").Message);
        Assert.False(string.IsNullOrEmpty(new LocalRpcConnectException().Message));
    }
}
