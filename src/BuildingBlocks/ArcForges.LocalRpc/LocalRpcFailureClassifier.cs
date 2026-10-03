// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Http;
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>
/// The connect callback of <see cref="LocalRpcClientChannel"/> failed: no private stream was opened for the call, so nothing
/// was sent. A command that fails with this has certainly not had its effect.
/// </summary>
public sealed class LocalRpcConnectException : IOException
{
    /// <summary>Creates the exception without a message.</summary>
    public LocalRpcConnectException()
        : base("The private stream could not be opened.")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public LocalRpcConnectException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception around the failure that stopped the stream from opening.</summary>
    public LocalRpcConnectException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>What one failed attempt proves about the effect, and why it failed.</summary>
internal readonly record struct LocalRpcAttemptFailure(
    LocalRpcEffect Effect,
    LocalRpcFailureReason Reason,
    StatusCode? Status,
    LocalRpcRefusal? Refusal,
    bool CancelledByCaller);

/// <summary>
/// Decides what a failed attempt proves. Only three things prove that an effect did not happen: a typed refusal the peer
/// attached before dispatch, a failure to open the stream, and an effect trailer the peer's receipt layer attached. Anything
/// else after a request may have been sent leaves the effect unknown.
/// </summary>
internal static class LocalRpcFailureClassifier
{
    private const int MaxChainDepth = 16;

    /// <summary>Classifies an exception from a send delegate, or null when it is not a transport failure and must propagate.</summary>
    internal static LocalRpcAttemptFailure? Classify(Exception exception, CancellationToken caller)
    {
        switch (exception)
        {
            case RpcException rpc:
                return ClassifyRpc(rpc, caller);
            case OperationCanceledException:
                if (ChainContainsConnectFailure(exception))
                {
                    return ConnectFailure(null, caller);
                }

                return caller.IsCancellationRequested
                    ? new LocalRpcAttemptFailure(LocalRpcEffect.Unknown, LocalRpcFailureReason.CancelledByCaller, null, null, true)
                    : new LocalRpcAttemptFailure(LocalRpcEffect.Unknown, LocalRpcFailureReason.TransportLost, null, null, false);
            case LocalRpcConnectException:
                return ConnectFailure(null, caller);
            case IOException or HttpRequestException:
                return ChainContainsConnectFailure(exception)
                    ? ConnectFailure(null, caller)
                    : new LocalRpcAttemptFailure(LocalRpcEffect.Unknown, LocalRpcFailureReason.TransportLost, null, null, false);
            default:
                return null;
        }
    }

    private static LocalRpcAttemptFailure ClassifyRpc(RpcException rpc, CancellationToken caller)
    {
        var status = rpc.StatusCode;
        if (LocalRpcRefusal.TryRead(rpc, out var refusal))
        {
            return new LocalRpcAttemptFailure(LocalRpcEffect.DidNotHappen, LocalRpcFailureReason.Refused, status, refusal, false);
        }

        if (LocalRpcCommandReceipts.TryReadEffect(rpc, out var reported))
        {
            return new LocalRpcAttemptFailure(reported, LocalRpcFailureReason.ReportedByPeer, status, null, false);
        }

        if (ChainContainsConnectFailure(rpc.Status.DebugException) || ChainContainsConnectFailure(rpc))
        {
            return ConnectFailure(status, caller);
        }

        if (status == StatusCode.Cancelled && caller.IsCancellationRequested)
        {
            return new LocalRpcAttemptFailure(LocalRpcEffect.Unknown, LocalRpcFailureReason.CancelledByCaller, status, null, true);
        }

        var reason = status switch
        {
            StatusCode.DeadlineExceeded => LocalRpcFailureReason.DeadlineExceeded,
            StatusCode.Unavailable or StatusCode.Cancelled or StatusCode.Aborted => LocalRpcFailureReason.TransportLost,
            _ => LocalRpcFailureReason.PeerError,
        };
        return new LocalRpcAttemptFailure(LocalRpcEffect.Unknown, reason, status, null, false);
    }

    /// <summary>No stream was opened, so nothing was sent: the effect did not happen, whether or not the caller also cancelled.</summary>
    private static LocalRpcAttemptFailure ConnectFailure(StatusCode? status, CancellationToken caller) =>
        new(
            LocalRpcEffect.DidNotHappen,
            caller.IsCancellationRequested ? LocalRpcFailureReason.CancelledByCaller : LocalRpcFailureReason.ConnectFailed,
            status,
            null,
            caller.IsCancellationRequested);

    /// <summary>Whether a <see cref="LocalRpcConnectException"/> is anywhere in the inner-exception chain.</summary>
    internal static bool ChainContainsConnectFailure(Exception? exception)
    {
        var depth = 0;
        while (exception is not null && depth++ < MaxChainDepth)
        {
            if (exception is LocalRpcConnectException)
            {
                return true;
            }

            if (exception is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions)
                {
                    if (ChainContainsConnectFailure(inner))
                    {
                        return true;
                    }
                }

                return false;
            }

            exception = exception.InnerException;
        }

        return false;
    }

    /// <summary>Whether a refusal may succeed if the same command is sent again after a wait. A callback that nests is refused the same way every time.</summary>
    internal static bool IsTransient(LocalRpcRefusal refusal) =>
        refusal.Reason is LocalRpcRefusalReason.DataQueueFull
            or LocalRpcRefusalReason.ControlBusy
            or LocalRpcRefusalReason.DeadlineBeforeDispatch
            or LocalRpcRefusalReason.CallbackNotQueued
            or LocalRpcRefusalReason.ReceiptsFull;
}
