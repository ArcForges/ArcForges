// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.RunSupervisor.Protocol;

/// <summary>An ordered authenticated channel to a platform-verified supervisor process.</summary>
public sealed class RunControlClient : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly RunLaunchSpec? _launch;
    private readonly byte[] _controlKey;
    private readonly byte[] _challenge;
    private readonly SemaphoreSlim _messages = new(1, 1);
    private long _sequence = 1;
    private int _activationAttempted;
    private bool _broken;

    private RunControlClient(Stream stream, byte[] controlKey, byte[] challenge, RunOwnerIdentity identity,
        RunLaunchSpec? launch = null, long? recoveryBoundaryHandle = null)
    {
        _stream = stream;
        _launch = launch;
        _controlKey = [.. controlKey];
        _challenge = challenge;
        Identity = identity;
        RecoveryBoundaryHandle = recoveryBoundaryHandle;
    }

    public RunOwnerIdentity Identity { get; }
    public long? RecoveryBoundaryHandle { get; }

    public static async ValueTask<RunControlClient> ConnectAsync(Stream stream, RunLaunchSpec spec, string launchBinding,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(spec);
        var challenge = new byte[RunWire.ChallengeLength];
        await stream.ReadExactlyAsync(challenge, cancellationToken).ConfigureAwait(false);
        await RunWire.WriteFrameAsync(stream, spec, challenge, false, new RunControlFrame(1, RunControlCommand.Hello,
            LaunchBinding: launchBinding), cancellationToken)
            .ConfigureAwait(false);
        var ready = await RunWire.ReadFrameAsync(stream, spec, challenge, true, cancellationToken).ConfigureAwait(false);
        if (ready is not { Sequence: 1, Command: RunControlCommand.Hello, Error: null, Identity: { } identity }
            || ready.LaunchBinding != launchBinding || ready.TerminalRequest is not null || ready.TerminalPoll is not null
            || ready.TerminalReply is not null || ready.Reconnect is not null || ready.RecoveryBoundaryHandle is not null
            || identity.Endpoint != spec.ControlEndpoint
            || identity.ControlEpoch != spec.Epoch || identity.ProcessId <= 0)
        {
            throw new InvalidDataException("run_owner_identity_mismatch");
        }

        return new RunControlClient(stream, spec.ControlKey, challenge, identity, spec);
    }

    /// <summary>Authenticates a new controller connection with no authority to release launch inputs.</summary>
    public static async ValueTask<RunControlClient> ReconnectAsync(Stream stream, RunRecoverySpec spec, string requesterCreationIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ControlKey.Length != RunWire.KeyLength || spec.Generation <= 0 || spec.Owner.ControlEpoch != spec.Epoch
            || string.IsNullOrEmpty(requesterCreationIdentity))
        {
            throw new InvalidDataException("run_recovery_identity_invalid");
        }

        var challenge = new byte[RunWire.ChallengeLength];
        await stream.ReadExactlyAsync(challenge, cancellationToken).ConfigureAwait(false);
        var reconnect = new RunReconnectRequest(spec.RunId, spec.Epoch, spec.LaunchSha256, spec.Owner, spec.Generation,
            Environment.ProcessId, requesterCreationIdentity);
        var hello = new RunControlFrame(1, RunControlCommand.Rebind, Reconnect: reconnect);
        await RunWire.WriteFrameAsync(stream, spec.ControlKey, challenge, false, hello, cancellationToken).ConfigureAwait(false);
        var ready = await RunWire.ReadFrameAsync(stream, spec.ControlKey, challenge, true, cancellationToken).ConfigureAwait(false);
        if ((ready with { RecoveryBoundaryHandle = null }) != (hello with { Identity = spec.Owner })
            || ready.RecoveryBoundaryHandle is <= 0)
        {
            throw new InvalidDataException("run_recovery_owner_identity_mismatch");
        }

        return new RunControlClient(stream, spec.ControlKey, challenge, spec.Owner, recoveryBoundaryHandle: ready.RecoveryBoundaryHandle);
    }

    public async ValueTask ActivateAsync(RunRelease release, CancellationToken cancellationToken)
    {
        if (_launch is not { } launch || Interlocked.Exchange(ref _activationAttempted, 1) != 0)
        {
            throw new RunNativeException("run_owner_refused", "activation_closed");
        }

        try
        {
            var activation = release with { Inputs = new RunLaunchInputs(launch.Argv, launch.Environment) };
            _ = await SendAsync(RunControlCommand.Activate, activation, 0, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            launch.ClearInputs();
        }
    }

    public async ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken)
    {
        if (grace < TimeSpan.Zero || grace > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(grace));
        }

        _ = await SendAsync(RunControlCommand.Stop, null, (int)grace.TotalMilliseconds, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken) =>
        (await SendAsync(RunControlCommand.Observe, null, 0, cancellationToken).ConfigureAwait(false)).Observation
        ?? throw new InvalidDataException("run_owner_observation_missing");

    public async ValueTask<RunTerminalReply> TerminalAsync(RunTerminalRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var started = Stopwatch.GetTimestamp();
        try
        {
            var frame = await SendAsync(RunControlCommand.TerminalBegin, null, 0, cancellationToken, request)
                .ConfigureAwait(false);
            var reply = frame.TerminalReply!;
            var poll = new RunTerminalPoll(request.Caller, request.CommandId);
            while (reply.Status == RunTerminalStatus.Pending)
            {
                if (Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(9))
                {
                    return new(RunTerminalStatus.AckUnavailable);
                }

                // Polls carry only owner-local comparison identity. No input is retried after admission.
                await Task.Delay(TimeSpan.FromMilliseconds(40), cancellationToken).ConfigureAwait(false);
                frame = await SendAsync(RunControlCommand.TerminalPoll, null, 0, cancellationToken, terminalPoll: poll)
                    .ConfigureAwait(false);
                reply = frame.TerminalReply!;
            }

            return reply;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or JsonException
            || error is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new(RunTerminalStatus.AckUnavailable);
        }
    }

    private async ValueTask<RunControlFrame> SendAsync(RunControlCommand command, RunRelease? release, int grace,
        CancellationToken cancellationToken, RunTerminalRequest? terminalRequest = null, RunTerminalPoll? terminalPoll = null)
    {
        await _messages.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_broken)
            {
                throw new IOException("run_control_closed");
            }

            var sequence = checked(++_sequence);
            var request = new RunControlFrame(sequence, command, release, grace, TerminalRequest: terminalRequest, TerminalPoll: terminalPoll);
            var terminal = command is RunControlCommand.TerminalBegin or RunControlCommand.TerminalPoll;
            // A caller may stop waiting, but cannot interrupt a partially sent request on the lifecycle channel.
            using var transportDeadline = terminal ? new CancellationTokenSource(TimeSpan.FromSeconds(3)) : null;
            var transportToken = transportDeadline?.Token ?? cancellationToken;
            try
            {
                await RunWire.WriteFrameAsync(_stream, _controlKey, _challenge, false, request, transportToken).ConfigureAwait(false);
                var reply = await RunWire.ReadFrameAsync(_stream, _controlKey, _challenge, true, transportToken).ConfigureAwait(false);
                if (reply.Sequence != sequence || reply.Command != command || reply.TerminalRequest is not null || reply.TerminalPoll is not null
                    || reply.Reconnect is not null || reply.RecoveryBoundaryHandle is not null
                    || terminal && (reply.TerminalReply is null || !Enum.IsDefined(reply.TerminalReply.Status))
                    || !terminal && reply.TerminalReply is not null)
                {
                    throw new InvalidDataException("run_control_response_mismatch");
                }

                if (reply.Error is { } error)
                {
                    throw new RunNativeException("run_owner_refused", error);
                }

                return reply;
            }
            catch (Exception error) when (error is IOException and not RunNativeException
                or InvalidDataException or JsonException or OperationCanceledException)
            {
                // Close on framing loss so the live owner immediately revokes the old Node's terminal authority.
                _broken = true;
                await _stream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            _messages.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _messages.WaitAsync().ConfigureAwait(false);
        try
        {
            _broken = true;
            _launch?.ClearInputs();
            CryptographicOperations.ZeroMemory(_controlKey);
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _messages.Release();
        }
    }
}
