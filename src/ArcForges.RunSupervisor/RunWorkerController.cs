// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

internal sealed record RunControlConnection(Stream Stream, Action<RunReconnectRequest?> RequirePeer);

/// <summary>Owns the lifecycle independently of the lifetime of the authenticating Node connection.</summary>
internal sealed class RunWorkerController(
    RunLaunchSpec launch,
    string launchBinding,
    RunOwnerIdentity identity,
    Func<CancellationToken, ValueTask<RunControlConnection>> listen,
    Func<RunLaunchSpec, RunRelease, CancellationToken, ValueTask<IRunWorkerSession>> start,
    Action consumeHandoff,
    Func<long?>? recoveryBoundaryHandle = null)
{
    private readonly object _gate = new();
    private readonly TaskCompletionSource<RunRelease?> _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<TimeSpan> _stop = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly RunTerminalBroker _terminal = new(launch.Epoch, launch.TerminalMode);
    private RunOwnerObservation _observation = new(RunOwnerState.Ready, RunPayloadStart.NotStarted, false);
    private long _controllerGeneration;
    private bool _authorized;
    private bool _stopPreventedActivation;
    private bool _reportedRecoveryFailure;

    internal async Task<int> RunAsync()
    {
        using var finish = new CancellationTokenSource();
        var connection = ServeAsync(finish.Token);
        try
        {
            RunRelease? release;
            try
            {
                release = await _release.Task.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                lock (_gate)
                {
                    _release.TrySetResult(null);
                }

                release = await _release.Task.ConfigureAwait(false);
            }

            // The owner consumes the manifest before handing the released input to the executor.
            try
            {
                consumeHandoff();
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException
                or System.ComponentModel.Win32Exception or InvalidDataException)
            {
                Publish(new RunOwnerObservation(RunOwnerState.RecoveryRequired, RunPayloadStart.NotStarted, false,
                    TerminationReason: "launch_handoff_cleanup_unverified", NativeError: FailureCode(error)));
                return 2;
            }
            if (release is null)
            {
                Publish(UnstartedOwner("activation_not_received"));
                return 0;
            }

            Publish(new RunOwnerObservation(RunOwnerState.Starting, RunPayloadStart.Unknown, false));
            try
            {
                using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var inputs = release.Inputs!;
                IRunWorkerSession session;
                try
                {
                    var spec = launch with { Argv = inputs.Argv, Environment = inputs.Environment };
                    var starting = Task.Run(async () =>
                        await start(spec, release with { Inputs = null }, startup.Token).ConfigureAwait(false));
                    if (await Task.WhenAny(starting, _stop.Task).ConfigureAwait(false) != starting)
                    {
                        await startup.CancelAsync().ConfigureAwait(false);
                    }

                    session = await starting.ConfigureAwait(false);
                }
                finally
                {
                    inputs.Clear();
                }

                await using var owned = session;
                _terminal.Bind(session);
                try
                {
                    return await OwnAsync(session).ConfigureAwait(false);
                }
                finally
                {
                    _terminal.RevokeAll();
                }
            }
            catch (RunNativeException error) when (error.BoundaryEmptyVerified && error.PayloadNotStarted)
            {
                Publish(UnstartedOwner("native_launch_refused") with { NativeError = FailureCode(error) });
                return 0;
            }
            catch (Exception error)
            {
                // A failed or interrupted native handoff cannot prove whether payload instructions ran.
                Publish(new RunOwnerObservation(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, false,
                    ExitSource: RunExitSources.Supervisor, TerminationReason: "native_owner_failed", NativeError: FailureCode(error)));
                return 2;
            }
        }
        finally
        {
            await finish.CancelAsync().ConfigureAwait(false);
            await connection.ConfigureAwait(false);
            if (_release.Task.IsCompletedSuccessfully)
            {
                _release.Task.Result?.Inputs?.Clear();
            }

            CryptographicOperations.ZeroMemory(launch.ControlKey);
        }
    }

    private async Task<int> OwnAsync(IRunWorkerSession session)
    {
        var stopApplied = false;
        while (true)
        {
            _terminal.Tick();
            try
            {
                if (!stopApplied && _stop.Task.IsCompletedSuccessfully)
                {
                    var grace = await _stop.Task.ConfigureAwait(false);
                    stopApplied = true;
                    using var stopping = new CancellationTokenSource(grace + TimeSpan.FromSeconds(15));
                    await session.StopAsync(grace, stopping.Token).ConfigureAwait(false);
                }

                using var readback = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var observation = await session.ObserveAsync(readback.Token).ConfigureAwait(false);
                if (observation.IsTerminal && !observation.GroupEmptyVerified)
                {
                    observation = observation with { State = RunOwnerState.Draining };
                }

                Publish(observation);
                if (observation.IsTerminal)
                {
                    return 0;
                }
            }
            catch (Exception error)
            {
                // Keep the owner and its handles alive while proof is unavailable.
                var uncertain = Volatile.Read(ref _observation) with
                {
                    State = RunOwnerState.RecoveryRequired,
                    GroupEmptyVerified = false,
                    NativeError = FailureCode(error),
                };
                try
                {
                    Publish(uncertain);
                }
                catch (Exception receiptError) when (receiptError is IOException or UnauthorizedAccessException)
                {
                    Console.Error.WriteLine("run_observation_write_failed " + receiptError.GetType().Name);
                    Volatile.Write(ref _observation, uncertain);
                }
            }

            await Task.Delay(TimeSpan.FromMilliseconds(150)).ConfigureAwait(false);
        }
    }

    private void Publish(RunOwnerObservation observation)
    {
        if (observation == Volatile.Read(ref _observation))
        {
            return;
        }

        RunWire.WriteObservation(launch, observation, identity, Volatile.Read(ref _controllerGeneration));
        Volatile.Write(ref _observation, observation);
    }

    private async Task ServeAsync(CancellationToken cancellationToken)
    {
        await ServeConnectionAsync(recovery: false, cancellationToken).ConfigureAwait(false);
        lock (_gate)
        {
            if (!_authorized)
            {
                _release.TrySetResult(null);
                return;
            }
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            await ServeConnectionAsync(recovery: true, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ServeConnectionAsync(bool recovery, CancellationToken cancellationToken)
    {
        bool authenticated = false;
        try
        {
            var connection = await listen(cancellationToken).ConfigureAwait(false);
            await using var stream = connection.Stream;
            var challenge = RandomNumberGenerator.GetBytes(RunWire.ChallengeLength);
            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshake.CancelAfter(TimeSpan.FromSeconds(5));
            var handshakeToken = handshake.Token;
            await stream.WriteAsync(challenge, handshakeToken).ConfigureAwait(false);
            await stream.FlushAsync(handshakeToken).ConfigureAwait(false);
            var hello = await RunWire.ReadFrameAsync(stream, launch.ControlKey, challenge, false, handshakeToken).ConfigureAwait(false);
            var ready = AuthenticateController(connection, hello, recovery);
            authenticated = true;
            _reportedRecoveryFailure = false;
            await RunWire.WriteFrameAsync(stream, launch, challenge, true, ready, handshakeToken).ConfigureAwait(false);
            await ServeRequestsAsync(stream, challenge, recovery, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or InvalidDataException or SocketException or UnauthorizedAccessException
            or OperationCanceledException or JsonException or RunNativeException or System.ComponentModel.Win32Exception)
        {
            if (recovery && !authenticated && !cancellationToken.IsCancellationRequested && !_reportedRecoveryFailure)
            {
                _reportedRecoveryFailure = true;
                Console.Error.WriteLine("run_control_rebind_failed " + FailureCode(error));
            }

            if (recovery && !authenticated && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), CancellationToken.None).ConfigureAwait(false);
            }
        }
        finally
        {
            if (authenticated)
            {
                _terminal.InvalidateController();
            }
        }
    }

    private RunControlFrame AuthenticateController(RunControlConnection connection, RunControlFrame hello, bool recovery)
    {
        if (!recovery)
        {
            if (hello != new RunControlFrame(1, RunControlCommand.Hello, LaunchBinding: launchBinding))
            {
                throw new InvalidDataException("run_owner_hello_invalid");
            }

            connection.RequirePeer(null);
            return hello with { Identity = identity };
        }

        if (hello.Reconnect is not { } reconnect || hello != new RunControlFrame(1, RunControlCommand.Rebind, Reconnect: reconnect)
            || reconnect.Owner != identity || reconnect.RunId != launch.RunId || reconnect.Epoch != launch.Epoch
            || reconnect.LaunchSha256 != launch.LaunchSha256 || reconnect.Generation <= Volatile.Read(ref _controllerGeneration)
            || reconnect.ProcessId <= 0 || string.IsNullOrEmpty(reconnect.CreationIdentity))
        {
            throw new InvalidDataException("run_recovery_identity_mismatch");
        }

        connection.RequirePeer(reconnect);
        var boundary = recoveryBoundaryHandle?.Invoke();
        if (recoveryBoundaryHandle is not null && boundary is null)
        {
            throw new InvalidDataException("run_recovery_boundary_unavailable");
        }

        Volatile.Write(ref _controllerGeneration, reconnect.Generation);
        return hello with { Identity = identity, RecoveryBoundaryHandle = boundary };
    }

    private async Task ServeRequestsAsync(Stream stream, byte[] challenge, bool recovery, CancellationToken cancellationToken)
    {
        long sequence = 1;
        while (!cancellationToken.IsCancellationRequested)
        {
            var request = recovery
                ? await RunWire.ReadFrameAsync(stream, launch.ControlKey, challenge, false, cancellationToken).ConfigureAwait(false)
                : await RunWire.ReadFrameAsync(stream, launch, challenge, false, cancellationToken).ConfigureAwait(false);
            RunControlFrame reply;
            var releaseAccepted = false;
            try
            {
                if (request.Sequence != checked(++sequence) || request.Identity is not null || request.Observation is not null
                    || request.Error is not null || request.LaunchBinding is not null || request.TerminalReply is not null
                    || request.Reconnect is not null || request.RecoveryBoundaryHandle is not null
                    || recovery && request.Command == RunControlCommand.Activate)
                {
                    throw new InvalidDataException("run_owner_request_invalid");
                }

                reply = Execute(request);
                releaseAccepted = request.Command == RunControlCommand.Activate && reply.Error is null;
            }
            finally
            {
                if (request.TerminalRequest?.Input is { } input)
                {
                    CryptographicOperations.ZeroMemory(input);
                }

                if (!releaseAccepted)
                {
                    request.Release?.Inputs?.Clear();
                }
            }

            await RunWire.WriteFrameAsync(stream, launch, challenge, true, reply, cancellationToken).ConfigureAwait(false);
        }
    }

    private RunControlFrame Execute(RunControlFrame request)
    {
        var reply = new RunControlFrame(request.Sequence, request.Command);
        switch (request.Command)
        {
            case RunControlCommand.Activate when request is
            { Release: { Inputs: not null } release, GraceMilliseconds: 0, TerminalRequest: null, TerminalPoll: null }:
                lock (_gate)
                {
                    if (_release.TrySetResult(release))
                    {
                        _authorized = true;
                        return reply;
                    }
                }

                return reply with { Error = "activation_closed" };
            case RunControlCommand.Stop when request is
            { Release: null, GraceMilliseconds: >= 0 and <= 60000, TerminalRequest: null, TerminalPoll: null }:
                lock (_gate)
                {
                    _stop.TrySetResult(TimeSpan.FromMilliseconds(request.GraceMilliseconds));
                    if (!_authorized && !_release.Task.IsCompleted)
                    {
                        Volatile.Write(ref _stopPreventedActivation, true);
                        _release.TrySetResult(null);
                    }
                }

                _terminal.RevokeAll();
                return reply;
            case RunControlCommand.Observe when request is
            { Release: null, GraceMilliseconds: 0, TerminalRequest: null, TerminalPoll: null }:
                return reply with { Observation = Volatile.Read(ref _observation) };
            case RunControlCommand.TerminalBegin when request is
            { Release: null, GraceMilliseconds: 0, TerminalRequest: { } terminal, TerminalPoll: null }:
                return reply with { TerminalReply = _terminal.Begin(terminal) };
            case RunControlCommand.TerminalPoll when request is
            { Release: null, GraceMilliseconds: 0, TerminalRequest: null, TerminalPoll: { } poll }:
                return reply with { TerminalReply = _terminal.Poll(poll) };
            default:
                return reply with { Error = "invalid_control_request" };
        }
    }

    private RunOwnerObservation UnstartedOwner(string failure) => Volatile.Read(ref _stopPreventedActivation)
        ? new(RunOwnerState.Exited, RunPayloadStart.NotStarted, true, ExitSource: RunExitSources.Supervisor, TerminationReason: "stopped_before_payload")
        : new(RunOwnerState.Failed, RunPayloadStart.NotStarted, true, ExitSource: RunExitSources.Supervisor, TerminationReason: failure);

    private static string FailureCode(Exception error) =>
        error is RunNativeException native ? $"{native.Phase}/{native.NativeCode}" : error.GetType().Name;
}
