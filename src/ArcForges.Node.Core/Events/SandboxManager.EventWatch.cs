// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.CompilerServices;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Shape = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    internal async IAsyncEnumerable<NodeServiceWatchEventsFrame> WatchEventsAsync(NodeServiceWatchEventsRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var cursor = request.Clone();
        if (!Shape.IsValid(cursor) || !KnownRemoteFields(cursor, NodeServiceWatchEventsRequest.Parser))
        {
            yield return EventFailure(InvalidGrant(request.Meta, "event_watch_shape_invalid"));
            yield break;
        }

        while (true)
        {
            NodeServiceWatchEventsFrame? frame;
            lock (OwnershipGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    frame = PollEventsLocked(cursor, sandboxId: null);
                }
                catch (Exception failure) when (IsStorageFailure(failure))
                {
                    frame = EventFailure(StorageFailure(request.Meta));
                }
            }

            if (frame is null)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(125), _clock, cancellationToken).ConfigureAwait(false);
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();
            yield return frame;
            if (frame.Event is not { } item)
            {
                yield break;
            }

            cursor.Epoch = item.Epoch;
            cursor.AfterSequence = item.Sequence;
        }
    }

    internal NodeServiceWatchEventsFrame? PollEventsFromCenter(NodeServiceWatchEventsRequest request, VerifiedRemoteGrantCall verified,
        CancellationToken cancellationToken) =>
        ReadFromCenter<NodeServiceWatchEventsRequest, NodeServiceWatchEventsFrame?>(request, request.Meta, verified,
            RemoteGrantAction.WatchEvents, NodeServiceWatchEventsRequest.Parser, Shape.IsValid(request),
            (grant, _) =>
            {
                if (grant.Scope != StoredRemoteGrantScope.Sandbox || grant.SandboxId is not { } sandboxId)
                {
                    return EventFailure(GrantDenied(request.Meta));
                }

                var frame = PollEventsLocked(request, sandboxId);
                cancellationToken.ThrowIfCancellationRequested();
                return RemoteSandboxAdmissionCurrent(verified, grant, _clock.GetUtcNow()) ? frame : EventFailure(GrantDenied(request.Meta));
            }, EventFailure, cancellationToken);

    private NodeServiceWatchEventsFrame? PollEventsLocked(NodeServiceWatchEventsRequest request, string? sandboxId)
    {
        bool hasEpoch = request.Epoch.Length != 0;
        if (request.AfterSequence > long.MaxValue || !hasEpoch && request.AfterSequence != 0)
        {
            return InvalidCursor();
        }

        long after = (long)request.AfterSequence;
        var observed = _store.Read(reader => SandboxEventRecords.ReadNext(reader, OwnerId, sandboxId, _nodeEpoch, after));
        if (hasEpoch && request.Epoch != _nodeEpoch)
        {
            return Gap("epoch_changed");
        }

        if (hasEpoch && after < observed.EvictedThrough)
        {
            return Gap("retention");
        }

        if (after > Math.Max(observed.EvictedThrough, observed.LastRetained))
        {
            return InvalidCursor();
        }

        if (observed.Next is not { } next)
        {
            return null;
        }

        var item = new Event
        {
            Sequence = checked((ulong)next.Sequence),
            Epoch = _nodeEpoch,
            Kind = next.Kind switch
            {
                "sandbox" => EventKind.Sandbox,
                "run" => EventKind.Run,
                _ => throw new InvalidDataException("The stored Sandbox event kind is unavailable."),
            },
            SandboxId = FromHex(next.SandboxId),
            Revision = new() { Value = next.Revision },
            ObservedAt = ProtoTime.ToInstant(next.ObservedAt),
        };
        if (item.Kind == EventKind.Run)
        {
            item.RunId = FromHex(next.AggregateId);
        }

        return new() { Meta = Response(request.Meta, next.Revision), Event = item };

        NodeServiceWatchEventsFrame InvalidCursor() =>
            EventFailure(Error(request.Meta, ErrorCategory.Validation, "invalid_cursor", "event_cursor_invalid"));

        NodeServiceWatchEventsFrame Gap(string reason) => new()
        {
            Meta = Response(request.Meta),
            Gap = new()
            {
                Epoch = _nodeEpoch,
                RequestedSequence = request.AfterSequence,
                EarliestSequence = observed.FirstRetained > 0 ? (ulong)observed.FirstRetained : checked((ulong)observed.EvictedThrough + 1),
                Reason = reason,
            },
        };
    }

    private static NodeServiceWatchEventsFrame EventFailure(ArcError error) =>
        new() { Meta = new() { CorrelationId = error.CorrelationId?.Clone() }, Error = error };
}
