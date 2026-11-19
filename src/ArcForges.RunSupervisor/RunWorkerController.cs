// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

/// <summary>Owns the lifecycle independently of the lifetime of the authenticating Node connection.</summary>
internal sealed class RunWorkerController(
    RunLaunchSpec launch,
    string launchBinding,
    RunOwnerIdentity identity,
    Func<CancellationToken, ValueTask<Stream>> listen,
    Func<RunLaunchSpec, RunRelease, CancellationToken, ValueTask<IRunWorkerSession>> start,
    Action consumeHandoff)
{
    private readonly object _gate = new();
    private readonly TaskCompletionSource<RunRelease?> _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<TimeSpan> _stop = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly RunTerminalBroker _terminal = new(launch.Epoch, launch.TerminalMode);
    private RunOwnerObservation _observation = new(RunOwnerState.Ready, RunPayloadStart.NotStarted, false);
    private bool _authorized;

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

            // The owner has consumed the handoff. The raw inputs are kept only in the private process memory.
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
                var starting = Task.Run(async () => await start(launch, release, startup.Token).ConfigureAwait(false));
                if (await Task.WhenAny(starting, _stop.Task).ConfigureAwait(false) != starting)
                {
                    await startup.CancelAsync().ConfigureAwait(false);
                }

                await using var session = await starting.ConfigureAwait(false);
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

        RunWire.WriteObservation(launch, observation);
        Volatile.Write(ref _observation, observation);
    }

    private async Task ServeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = await listen(cancellationToken).ConfigureAwait(false);
            var challenge = RandomNumberGenerator.GetBytes(RunWire.ChallengeLength);
            await stream.WriteAsync(challenge, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            var hello = await RunWire.ReadFrameAsync(stream, launch, challenge, false, cancellationToken).ConfigureAwait(false);
            if (hello != new RunControlFrame(1, RunControlCommand.Hello, LaunchBinding: launchBinding))
            {
                throw new InvalidDataException("run_owner_hello_invalid");
            }

            await RunWire.WriteFrameAsync(stream, launch, challenge, true, hello with { Identity = identity }, cancellationToken)
                .ConfigureAwait(false);
            long sequence = 1;
            while (!cancellationToken.IsCancellationRequested)
            {
                var request = await RunWire.ReadFrameAsync(stream, launch, challenge, false, cancellationToken).ConfigureAwait(false);
                RunControlFrame reply;
                try
                {
                    if (request.Sequence != checked(++sequence) || request.Identity is not null || request.Observation is not null
                        || request.Error is not null || request.LaunchBinding is not null || request.TerminalReply is not null)
                    {
                        throw new InvalidDataException("run_owner_request_invalid");
                    }

                    reply = Execute(request);
                }
                finally
                {
                    if (request.TerminalRequest?.Input is { } input)
                    {
                        CryptographicOperations.ZeroMemory(input);
                    }
                }

                await RunWire.WriteFrameAsync(stream, launch, challenge, true, reply, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception error) when (error is IOException or InvalidDataException or SocketException or UnauthorizedAccessException
            or OperationCanceledException or JsonException or RunNativeException)
        {
            // A disconnected authenticated controller must not terminate an already released owner.
            lock (_gate)
            {
                if (!_authorized)
                {
                    _release.TrySetResult(null);
                }
            }
        }
        finally
        {
            // Losing the Node control connection destroys terminal authority, not the Run or its native handles.
            _terminal.RevokeAll();
        }
    }

    private RunControlFrame Execute(RunControlFrame request)
    {
        var reply = new RunControlFrame(request.Sequence, request.Command);
        switch (request.Command)
        {
            case RunControlCommand.Activate when request is
            { Release: { } release, GraceMilliseconds: 0, TerminalRequest: null, TerminalPoll: null }:
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
                    if (!_authorized)
                    {
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

    private RunOwnerObservation UnstartedOwner(string failure) => _stop.Task.IsCompletedSuccessfully
        ? new(RunOwnerState.Exited, RunPayloadStart.NotStarted, true, ExitSource: RunExitSources.Supervisor, TerminationReason: "stopped_before_payload")
        : new(RunOwnerState.Failed, RunPayloadStart.NotStarted, true, ExitSource: RunExitSources.Supervisor, TerminationReason: failure);

    private static string FailureCode(Exception error) =>
        error is RunNativeException native ? $"{native.Phase}/{native.NativeCode}" : error.GetType().Name;
}
