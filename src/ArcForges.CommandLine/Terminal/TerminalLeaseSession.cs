// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Google.Protobuf;
using Grpc.Core;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.CommandLine;

// The caller pins its local connection until every attachment task has finished.
internal sealed class TerminalLeaseSession : IDisposable
{
    private const int MaxInputBytes = 65536;
    private const int MaxDimension = 32767;
    private static readonly TimeSpan s_deadline = TimeSpan.FromSeconds(10);

    private readonly Cli _cli;
    private readonly V2CliSession _session;
    private readonly Id _runId;
    private readonly TerminalMode _terminalMode;
    private readonly SemaphoreSlim _lane = new(1, 1);
    private volatile TerminalLease _lease;
    private ArcError? _invalidated;
    private ArcError? _detachFailure;
    private bool _inputClosed;
    private bool _detached;

    private TerminalLeaseSession(Cli cli, V2CliSession session, Id runId, TerminalMode terminalMode, TerminalLease lease)
    {
        _cli = cli;
        _session = session;
        _runId = runId;
        _terminalMode = terminalMode;
        _lease = lease;
    }

    internal TerminalLease Lease => _lease.Clone();

    internal static async Task<TerminalLeaseSession> AcquireAsync(Cli cli, V2CliSession session, Run run,
        bool readOnly, bool takeover, CancellationToken cancellationToken)
    {
        if (readOnly && takeover)
        {
            throw new UsageException("A read-only attachment cannot take over the writer lease.");
        }

        var terminalMode = run.TerminalMode;
        var epoch = run.Epoch;
        if (run.RunId is not { Value.Length: 16 } runId || epoch.Length == 0
            || terminalMode is not (TerminalMode.Interactive or TerminalMode.Pipes))
        {
            throw Refusal(ErrorCategory.State, "terminal_unavailable", "run_terminal_identity_unavailable");
        }

        var request = new RunServiceAcquireTerminalRequest
        {
            Meta = TransientMeta(),
            RunId = runId.Clone(),
            Mode = readOnly ? LeaseMode.Observer : LeaseMode.Writer,
        };
        if (takeover)
        {
            request.Takeover = true;
        }

        var response = await DispatchAsync(request.Meta,
            () => session.Runs.AcquireTerminalAsync(request, deadline: cli.Deadline(s_deadline),
                cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
        var value = Confirm(request.Meta, response.Meta, response.Value, response.Error);
        var lease = value.Lease;
        if (!MatchesLease(lease, epoch, request.Mode)
            || lease.LastInputSequence != 0 || lease.LastResizeSequence != 0)
        {
            throw Unconfirmed(request.Meta);
        }

        return new(cli, session, request.RunId, terminalMode, lease);
    }

    internal Task RenewAsync(CancellationToken cancellationToken) => UseAsync(async lease =>
    {
        var request = new RunServiceAcquireTerminalRequest
        {
            Meta = TransientMeta(),
            RunId = _runId,
            Mode = lease.Mode,
            ExistingLeaseId = lease.LeaseId,
        };
        var response = await DispatchAsync(request.Meta,
            () => _session.Runs.AcquireTerminalAsync(request, deadline: _cli.Deadline(s_deadline),
                cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
        var value = Confirm(request.Meta, response.Meta, response.Value, response.Error);
        var renewed = value.Lease;
        if (!MatchesLease(renewed, lease.RunEpoch, lease.Mode)
            || !lease.LeaseId.Equals(renewed.LeaseId) || renewed.Generation != lease.Generation
            || renewed.LastInputSequence != lease.LastInputSequence || renewed.LastResizeSequence != lease.LastResizeSequence)
        {
            throw Unconfirmed(request.Meta);
        }

        _lease = renewed;
        return renewed;
    }, cancellationToken);

    internal Task<int> WriteAsync(ReadOnlyMemory<byte> input, CancellationToken cancellationToken)
    {
        if (input.Length is < 1 or > MaxInputBytes)
        {
            throw new UsageException("Terminal input frames require 1 to 65536 bytes.");
        }

        return WriteOrCloseAsync(input, close: false, cancellationToken);
    }

    internal Task CloseInputAsync(CancellationToken cancellationToken)
    {
        if (_terminalMode != TerminalMode.Pipes)
        {
            throw Refusal(ErrorCategory.State, "terminal_unavailable", "terminal_mode_unsupported");
        }

        return WriteOrCloseAsync(ReadOnlyMemory<byte>.Empty, close: true, cancellationToken);
    }

    private Task<int> WriteOrCloseAsync(ReadOnlyMemory<byte> input, bool close, CancellationToken cancellationToken) =>
        UseAsync(async lease =>
        {
            RequireWriter(lease);
            if (_inputClosed)
            {
                throw Refusal(ErrorCategory.State, "terminal_unavailable", "terminal_input_closed");
            }

            var request = new RunServiceWriteTerminalRequest
            {
                Meta = TransientMeta(),
                RunId = _runId,
                Lease = lease,
                InputSequence = NextSequence(lease.LastInputSequence),
            };
            if (close)
            {
                request.CloseStdin = true;
            }
            else
            {
                request.Input = ByteString.CopyFrom(input.Span);
            }

            var response = await DispatchAsync(request.Meta,
                () => _session.Runs.WriteTerminalAsync(request, deadline: _cli.Deadline(s_deadline),
                    cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            var value = Confirm(request.Meta, response.Meta, response.Value, response.Error);
            if (!value.HasAcceptedBytes || value.AcceptedBytes > (uint)input.Length)
            {
                throw Unconfirmed(request.Meta);
            }

            var confirmed = lease.Clone();
            confirmed.LastInputSequence = request.InputSequence;
            _lease = confirmed;
            _inputClosed = close;
            return (int)value.AcceptedBytes;
        }, cancellationToken);

    internal Task ResizeAsync(int rows, int columns, CancellationToken cancellationToken)
    {
        if (_terminalMode != TerminalMode.Interactive)
        {
            throw Refusal(ErrorCategory.State, "terminal_unavailable", "terminal_mode_unsupported");
        }

        if (rows is < 1 or > MaxDimension || columns is < 1 or > MaxDimension)
        {
            throw new UsageException("Terminal rows and columns require values between 1 and 32767.");
        }

        return UseAsync(async lease =>
        {
            RequireWriter(lease);
            var request = new RunServiceResizeTerminalRequest
            {
                Meta = TransientMeta(),
                RunId = _runId,
                Lease = lease,
                Size = new TerminalSize { Rows = (uint)rows, Columns = (uint)columns },
                ResizeSequence = NextSequence(lease.LastResizeSequence),
            };
            var response = await DispatchAsync(request.Meta,
                () => _session.Runs.ResizeTerminalAsync(request, deadline: _cli.Deadline(s_deadline),
                    cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            var value = Confirm(request.Meta, response.Meta, response.Value, response.Error);
            if (value.AppliedSize is not { HasRows: true, HasColumns: true } actual
                || actual.Rows != request.Size.Rows || actual.Columns != request.Size.Columns)
            {
                throw Unconfirmed(request.Meta);
            }

            var confirmed = lease.Clone();
            confirmed.LastResizeSequence = request.ResizeSequence;
            _lease = confirmed;
            return actual;
        }, cancellationToken);
    }

    internal async Task DetachAsync(CancellationToken cancellationToken)
    {
        await _lane.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_detached)
            {
                return;
            }

            if (_detachFailure is { } previous)
            {
                throw new V2CommandException(previous, identity: null);
            }

            var request = new RunServiceDetachTerminalRequest { Meta = TransientMeta(), RunId = _runId, Lease = _lease };
            var response = await DispatchAsync(request.Meta,
                () => _session.Runs.DetachTerminalAsync(request, deadline: _cli.Deadline(s_deadline),
                    cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            _ = Confirm(request.Meta, response.Meta, response.Value, response.Error);
            _detached = true;
        }
        catch (V2CommandException exception)
        {
            _detachFailure = exception.Error;
            throw;
        }
        finally
        {
            _lane.Release();
        }
    }

    public void Dispose() => _lane.Dispose();

    private async Task<TResult> UseAsync<TResult>(Func<TerminalLease, Task<TResult>> action, CancellationToken cancellationToken)
    {
        await _lane.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if ((_invalidated ?? _detachFailure) is { } failure)
            {
                throw new V2CommandException(failure, identity: null);
            }

            if (_detached)
            {
                throw Refusal(ErrorCategory.Conflict, "lease_stale", "terminal_lease_stale");
            }

            return await action(_lease).ConfigureAwait(false);
        }
        catch (V2CommandException exception) when (exception.Error.Effect == EffectCertainty.Unknown || exception.Error.Code == "lease_stale")
        {
            _invalidated = exception.Error;
            throw;
        }
        finally
        {
            _lane.Release();
        }
    }

    private static bool MatchesLease([NotNullWhen(true)] TerminalLease? lease, string epoch, LeaseMode mode) =>
        lease is { LeaseId.Value.Length: 16, Generation: > 0, HasLastInputSequence: true, HasLastResizeSequence: true }
        && lease.RunEpoch == epoch && lease.Mode == mode && V2Shapes.IsValid(lease);

    private static void RequireWriter(TerminalLease lease)
    {
        if (lease.Mode != LeaseMode.Writer)
        {
            throw Refusal(ErrorCategory.Conflict, "lease_stale", "terminal_writer_required");
        }
    }

    private static ulong NextSequence(ulong current) => current != ulong.MaxValue
        ? current + 1
        : throw Refusal(ErrorCategory.Conflict, "lease_stale", "terminal_sequence_exhausted");

    private static RequestMeta TransientMeta()
    {
        var meta = Cli.Meta();
        meta.CommandId = CommandIds.New();
        return meta;
    }

    private static async Task<T> DispatchAsync<T>(RequestMeta meta, Func<AsyncUnaryCall<T>> send, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var call = send();
            return await call.ResponseAsync.ConfigureAwait(false);
        }
        catch (RpcException exception) when (exception.StatusCode is StatusCode.PermissionDenied or StatusCode.Unauthenticated)
        {
            throw Refusal(ErrorCategory.Authorization, "permission_denied", "terminal_local_connection_required", meta.CorrelationId);
        }
        catch (RpcException exception) when (exception.StatusCode == StatusCode.Unimplemented)
        {
            throw Refusal(ErrorCategory.State, "terminal_unavailable", "terminal_method_unavailable", meta.CorrelationId);
        }
        catch (RpcException)
        {
            throw Unconfirmed(meta);
        }
        catch (OperationCanceledException)
        {
            throw Unconfirmed(meta);
        }
    }

    private static T Confirm<T>(RequestMeta request, ResponseMeta? response, T? value, ArcError? error) where T : class
    {
        if (!request.CorrelationId.Equals(response?.CorrelationId))
        {
            throw Unconfirmed(request);
        }

        return error is { } refusal ? throw new V2CommandException(refusal, identity: null)
            : value ?? throw Unconfirmed(request);
    }

    private static V2CommandException Refusal(ErrorCategory category, string code, string reason, Id? correlationId = null)
    {
        var error = V2Cli.Error(category, code, reason);
        error.CorrelationId = correlationId;
        return new V2CommandException(error, identity: null);
    }

    private static V2CommandException Unconfirmed(RequestMeta meta)
    {
        var error = V2Cli.Error(ErrorCategory.Execution, "terminal_ack_unavailable", "terminal_acknowledgment_unavailable");
        error.CorrelationId = meta.CorrelationId;
        error.Effect = EffectCertainty.Unknown;
        return new V2CommandException(error, identity: null);
    }
}
