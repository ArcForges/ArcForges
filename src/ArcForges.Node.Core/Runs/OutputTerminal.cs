// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private readonly Dictionary<RunTerminalCaller, TerminalConnection> _terminalConnections = [];

    internal async Task<RunServiceAcquireTerminalResponse> AcquireTerminalAsync(RunServiceAcquireTerminalRequest request,
        RunTerminalCaller caller, CancellationToken closed, CancellationToken wait)
    {
        var command = new RunTerminalRequest(RunTerminalAction.Acquire, caller, ToHex(request.Meta.CommandId),
            Mode: (RunTerminalLeaseMode)request.Mode,
            ExistingLeaseId: request.ExistingLeaseId is { } existing ? ToHex(existing) : null, Takeover: request.Takeover);
        var (meta, reply, error) = await RunTerminalAsync(request.RunId, request.Meta, command, closed, wait).ConfigureAwait(false);
        if (error is not null)
        {
            return new() { Meta = meta, Error = error };
        }

        if (reply?.Lease is not { } lease || !IsSandboxId(lease.LeaseId))
        {
            return new() { Meta = meta, Error = TerminalAcknowledgmentLost(request.Meta) };
        }

        var view = new TerminalLease
        {
            LeaseId = FromHex(lease.LeaseId),
            RunEpoch = lease.RunEpoch,
            Generation = lease.Generation,
            Mode = (LeaseMode)lease.Mode,
            ExpiresAt = ProtoTime.ToInstant(lease.ExpiresAt),
            LastInputSequence = lease.LastInputSequence,
            LastResizeSequence = lease.LastResizeSequence,
        };
        return V2Shapes.IsValid(view)
            ? new() { Meta = meta, Value = new() { Lease = view } }
            : new() { Meta = meta, Error = TerminalAcknowledgmentLost(request.Meta) };
    }

    internal async Task<RunServiceWriteTerminalResponse> WriteTerminalAsync(RunServiceWriteTerminalRequest request,
        RunTerminalCaller caller, CancellationToken closed, CancellationToken wait)
    {
        var lease = PreflightTerminalLease(request.Lease);
        if (lease is null)
        {
            return new() { Meta = Response(request.Meta), Error = InvalidRun(request.Meta) };
        }

        var command = new RunTerminalRequest(RunTerminalAction.Write, caller, ToHex(request.Meta.CommandId), lease,
            Sequence: request.InputSequence, Input: request.HasInput ? request.Input.ToByteArray() : null,
            CloseStdin: request.CloseStdin);
        var (meta, reply, error) = await RunTerminalAsync(request.RunId, request.Meta, command, closed, wait).ConfigureAwait(false);
        if (error is not null)
        {
            return new() { Meta = meta, Error = error };
        }

        return reply?.AcceptedBytes is int accepted && accepted >= 0 && accepted <= request.Input.Length
            ? new() { Meta = meta, Value = new() { AcceptedBytes = (uint)accepted } }
            : new() { Meta = meta, Error = TerminalAcknowledgmentLost(request.Meta) };
    }

    internal async Task<RunServiceResizeTerminalResponse> ResizeTerminalAsync(RunServiceResizeTerminalRequest request,
        RunTerminalCaller caller, CancellationToken closed, CancellationToken wait)
    {
        var lease = PreflightTerminalLease(request.Lease);
        if (lease is null)
        {
            return new() { Meta = Response(request.Meta), Error = InvalidRun(request.Meta) };
        }

        var command = new RunTerminalRequest(RunTerminalAction.Resize, caller, ToHex(request.Meta.CommandId), lease,
            Sequence: request.ResizeSequence, Rows: request.Size.Rows, Columns: request.Size.Columns);
        var (meta, reply, error) = await RunTerminalAsync(request.RunId, request.Meta, command, closed, wait).ConfigureAwait(false);
        if (error is not null)
        {
            return new() { Meta = meta, Error = error };
        }

        return reply is { Rows: uint rows and >= 1 and <= 32767, Columns: uint columns and >= 1 and <= 32767 }
            ? new() { Meta = meta, Value = new() { AppliedSize = new() { Rows = rows, Columns = columns } } }
            : new() { Meta = meta, Error = TerminalAcknowledgmentLost(request.Meta) };
    }

    internal async Task<RunServiceDetachTerminalResponse> DetachTerminalAsync(RunServiceDetachTerminalRequest request,
        RunTerminalCaller caller, CancellationToken closed, CancellationToken wait)
    {
        var lease = PreflightTerminalLease(request.Lease);
        if (lease is null)
        {
            return new() { Meta = Response(request.Meta), Error = InvalidRun(request.Meta) };
        }

        var command = new RunTerminalRequest(RunTerminalAction.Detach, caller, ToHex(request.Meta.CommandId), lease);
        var (meta, _, error) = await RunTerminalAsync(request.RunId, request.Meta, command, closed, wait).ConfigureAwait(false);
        return error is null ? new() { Meta = meta, Value = new() } : new() { Meta = meta, Error = error };
    }

    private async Task<(ResponseMeta Meta, RunTerminalReply? Reply, ArcError? Error)> RunTerminalAsync(Id id,
        RequestMeta requestMeta, RunTerminalRequest request, CancellationToken closed, CancellationToken wait)
    {
        var handedOff = false;
        try
        {
            IRunOwnerLease owner;
            CancellationToken ownerLifetime;
            ResponseMeta meta;
            lock (OwnershipGate)
            {
                wait.ThrowIfCancellationRequested();
                if (request.Caller is not { ProcessId: > 0, ProcessStartTicks: > 0 }
                    || !closed.CanBeCanceled || closed.IsCancellationRequested)
                {
                    return (Response(requestMeta), null,
                        Error(requestMeta, ErrorCategory.Authorization, "permission_denied", "terminal_local_connection_required"));
                }

                string runId = ToHex(id);
                StoredRun? run;
                try
                {
                    run = _store.Read(reader => RunRecords.Get(reader, OwnerId, runId));
                }
                catch (Exception failure) when (IsStorageFailure(failure))
                {
                    return (Response(requestMeta), null, StorageFailure(requestMeta));
                }

                if (run is null)
                {
                    return (Response(requestMeta), null, Error(requestMeta, ErrorCategory.State, "not_found", "run_not_visible"));
                }

                meta = Response(requestMeta, run.Revision);
                if (request.Lease is { } lease && lease.RunEpoch != run.Epoch)
                {
                    return (meta, null, TerminalError(requestMeta, RunTerminalStatus.LeaseStale));
                }

                if (!_liveRuns.TryGetValue(runId, out var live) || live.Spec.Epoch != run.Epoch || live.OwnerLease is not { } active)
                {
                    var unavailable = request is { Action: RunTerminalAction.Acquire, ExistingLeaseId: null }
                        && run.State is StoredRunState.Starting or StoredRunState.Exited or StoredRunState.Failed;
                    return (meta, null, unavailable ? TerminalError(requestMeta, RunTerminalStatus.TerminalUnavailable)
                        : TerminalAcknowledgmentLost(requestMeta));
                }

                TrackTerminalConnection(request.Caller, runId, closed);
                owner = active;
                ownerLifetime = live.CancellationToken;
            }

            // The public deadline only stops waiting. Every accepted exchange runs under the
            // bounded private controller and the Run lifetime, independently of the RPC.
            handedOff = true;
            var exchange = InvokeTerminalOwnerAsync(owner, request, ownerLifetime);
            try
            {
                var reply = await exchange.WaitAsync(wait).ConfigureAwait(false);
                return (meta, reply, reply.Status == RunTerminalStatus.Ok ? null : TerminalError(requestMeta, reply.Status));
            }
            catch (OperationCanceledException) when (wait.IsCancellationRequested)
            {
                return (meta, null, TerminalAcknowledgmentLost(requestMeta));
            }
        }
        finally
        {
            if (!handedOff && request.Input is { } input)
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }
    }

    private static async Task<RunTerminalReply> InvokeTerminalOwnerAsync(IRunOwnerLease owner, RunTerminalRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            return await owner.TerminalAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsRunOwnerFailure(error) || error is ObjectDisposedException)
        {
            return new(RunTerminalStatus.AckUnavailable);
        }
        finally
        {
            if (request.Input is { } input)
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }
    }

    private void TrackTerminalConnection(RunTerminalCaller caller, string runId, CancellationToken closed)
    {
        if (!_terminalConnections.TryGetValue(caller, out var connection))
        {
            connection = new TerminalConnection(this, caller);
            _terminalConnections.Add(caller, connection);
            _ = closed.UnsafeRegister(static state =>
            {
                var ending = (TerminalConnection)state!;
                _ = Task.Run(() => ending.Manager.RevokeTerminalConnectionAsync(ending));
            }, connection);
        }

        // One registration per actual transport connection; retain only live Run identities.
        connection.Runs.RemoveWhere(id => !_liveRuns.ContainsKey(id));
        _ = connection.Runs.Add(runId);
    }

    private async Task RevokeTerminalConnectionAsync(TerminalConnection connection)
    {
        List<IRunOwnerLease> owners = [];
        lock (OwnershipGate)
        {
            if (!_terminalConnections.Remove(connection.Caller))
            {
                return;
            }

            foreach (var id in connection.Runs)
            {
                if (_liveRuns.TryGetValue(id, out var live) && live.OwnerLease is { } owner)
                {
                    owners.Add(owner);
                }
            }
        }

        var revoke = new RunTerminalRequest(RunTerminalAction.Revoke, connection.Caller, "");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        _ = await Task.WhenAll(owners.Select(owner => InvokeTerminalOwnerAsync(owner, revoke, deadline.Token))).ConfigureAwait(false);
    }

    private static RunTerminalLease? PreflightTerminalLease(TerminalLease? lease)
    {
        if (!V2Shapes.IsValid(lease))
        {
            return null;
        }

        try
        {
            return ProtoTime.ToDateTimeOffset(lease.ExpiresAt) is { } expiration
                ? new(ToHex(lease.LeaseId), lease.RunEpoch, lease.Generation, (RunTerminalLeaseMode)lease.Mode,
                    expiration, lease.LastInputSequence, lease.LastResizeSequence) : null;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static ArcError TerminalError(RequestMeta meta, RunTerminalStatus status) => status switch
    {
        RunTerminalStatus.InvalidArgument => InvalidRun(meta),
        RunTerminalStatus.LeaseStale => Error(meta, ErrorCategory.Conflict, "lease_stale", "terminal_lease_stale"),
        RunTerminalStatus.CommandIdReused => Error(meta, ErrorCategory.Conflict, "command_id_reused", "terminal_command_intent_changed"),
        RunTerminalStatus.Busy => Error(meta, ErrorCategory.State, "busy", "terminal_writer_busy"),
        RunTerminalStatus.TerminalUnavailable => Error(meta, ErrorCategory.State, "terminal_unavailable", "run_terminal_unavailable"),
        RunTerminalStatus.Unsupported => Error(meta, ErrorCategory.State, "terminal_unavailable", "terminal_mode_unsupported"),
        _ => TerminalAcknowledgmentLost(meta),
    };

    private static ArcError TerminalAcknowledgmentLost(RequestMeta meta)
    {
        var error = Error(meta, ErrorCategory.Execution, "terminal_ack_unavailable", "terminal_acknowledgment_unavailable", EffectCertainty.Unknown);
        error.Retry = new RetryAdvice { Mode = RetryMode.Never };
        return error;
    }

    private sealed record TerminalConnection(SandboxManager Manager, RunTerminalCaller Caller)
    {
        internal HashSet<string> Runs { get; } = new(StringComparer.Ordinal);
    }
}
