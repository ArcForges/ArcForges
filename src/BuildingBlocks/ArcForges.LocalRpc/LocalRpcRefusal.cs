// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Frozen;
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>The four operations that use a peer's reserved control slots instead of the data budget.</summary>
public enum LocalRpcControlOperation
{
    /// <summary>Not a control operation; never registered.</summary>
    None = 0,

    /// <summary>Launch bootstrap (challenge and confirm).</summary>
    Bootstrap = 1,

    /// <summary>Lease renewal.</summary>
    LeaseRenewal = 2,

    /// <summary>Cancellation of a running call, session or transfer.</summary>
    Cancellation = 3,

    /// <summary>Health.</summary>
    Health = 4,
}

/// <summary>Why a call was refused before it reached a service. A refused call never dispatched.</summary>
public enum LocalRpcRefusalReason
{
    /// <summary>No refusal; never reported.</summary>
    None = 0,

    /// <summary>All active data slots are taken and the bounded queue is full (<c>RESOURCE_EXHAUSTED</c>).</summary>
    DataQueueFull = 1,

    /// <summary>Both reserved control slots are taken (<c>RESOURCE_EXHAUSTED</c>).</summary>
    ControlBusy = 2,

    /// <summary>The call's deadline passed while it waited for a slot, or before it could start (<c>DEADLINE_EXCEEDED</c>).</summary>
    DeadlineBeforeDispatch = 3,

    /// <summary>A callback made from inside a handler found no free slot; callbacks never wait (<c>RESOURCE_EXHAUSTED</c>).</summary>
    CallbackNotQueued = 4,

    /// <summary>A callback handler tried to call again; callbacks do not nest (<c>FAILED_PRECONDITION</c>, raised by the caller).</summary>
    RecursiveCallback = 5,

    /// <summary>A call named a service other than the one its resolved route is for; the route guard refused it before the wire (<c>UNIMPLEMENTED</c>, raised by the caller).</summary>
    UnroutedService = 6,

    /// <summary>The child behind a resolved route is no longer registered (lease over, launch superseded or revoked, process gone); the route guard refused the call before the wire (<c>FAILED_PRECONDITION</c>, raised by the caller).</summary>
    RouteNotLive = 7,
}

/// <summary>The typed refusal a peer attaches to a call that was refused before dispatch.</summary>
public sealed record LocalRpcRefusal(LocalRpcRefusalReason Reason)
{
    internal const string ReasonTrailer = "x-af-refusal";
    internal const string DispatchedTrailer = "x-af-dispatched";
    internal const string NestedHeader = "x-af-nested";

    private static readonly FrozenDictionary<LocalRpcRefusalReason, string> Names = new Dictionary<LocalRpcRefusalReason, string>
    {
        [LocalRpcRefusalReason.DataQueueFull] = "data-queue-full",
        [LocalRpcRefusalReason.ControlBusy] = "control-busy",
        [LocalRpcRefusalReason.DeadlineBeforeDispatch] = "deadline-before-dispatch",
        [LocalRpcRefusalReason.CallbackNotQueued] = "callback-not-queued",
        [LocalRpcRefusalReason.RecursiveCallback] = "recursive-callback",
        [LocalRpcRefusalReason.UnroutedService] = "unrouted-service",
        [LocalRpcRefusalReason.RouteNotLive] = "route-not-live",
    }.ToFrozenDictionary();

    /// <summary>
    /// Reads the refusal from a failed call. It is present only when the call was refused by the bounds layer and
    /// states that the service was not dispatched; any other failure may or may not have dispatched.
    /// </summary>
    public static bool TryRead(RpcException exception, out LocalRpcRefusal? refusal)
    {
        ArgumentNullException.ThrowIfNull(exception);
        refusal = null;
        string? name = null;
        string? dispatched = null;
        foreach (var entry in exception.Trailers)
        {
            if (entry.IsBinary)
            {
                continue;
            }

            if (string.Equals(entry.Key, ReasonTrailer, StringComparison.Ordinal))
            {
                name = entry.Value;
            }
            else if (string.Equals(entry.Key, DispatchedTrailer, StringComparison.Ordinal))
            {
                dispatched = entry.Value;
            }
        }

        if (name is null || dispatched != "0")
        {
            return false;
        }

        foreach (var (reason, text) in Names)
        {
            if (string.Equals(text, name, StringComparison.Ordinal))
            {
                refusal = new LocalRpcRefusal(reason);
                return true;
            }
        }

        return false;
    }

    internal static string NameOf(LocalRpcRefusalReason reason) => Names[reason];

    internal static StatusCode StatusOf(LocalRpcRefusalReason reason) => reason switch
    {
        LocalRpcRefusalReason.DeadlineBeforeDispatch => StatusCode.DeadlineExceeded,
        LocalRpcRefusalReason.RecursiveCallback or LocalRpcRefusalReason.RouteNotLive => StatusCode.FailedPrecondition,
        LocalRpcRefusalReason.UnroutedService => StatusCode.Unimplemented,
        _ => StatusCode.ResourceExhausted,
    };
}

/// <summary>A point-in-time view of the call bounds of every connected peer of one server, with totals since it started.</summary>
/// <param name="Peers">Connections currently served.</param>
/// <param name="DataActive">Data calls running now, summed over peers.</param>
/// <param name="DataQueued">Data calls waiting now, summed over peers.</param>
/// <param name="ControlActive">Control calls running now, summed over peers.</param>
/// <param name="DataAdmitted">Data calls admitted since the server started.</param>
/// <param name="ControlAdmitted">Control calls admitted since the server started, by operation.</param>
/// <param name="Refused">Calls refused before dispatch since the server started, by reason.</param>
public sealed record LocalRpcBoundsSnapshot(
    int Peers,
    int DataActive,
    int DataQueued,
    int ControlActive,
    long DataAdmitted,
    IReadOnlyDictionary<LocalRpcControlOperation, long> ControlAdmitted,
    IReadOnlyDictionary<LocalRpcRefusalReason, long> Refused);
