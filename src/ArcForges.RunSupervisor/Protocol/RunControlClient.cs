// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.RunSupervisor.Protocol;

/// <summary>An ordered authenticated channel to a platform-verified supervisor process.</summary>
public sealed class RunControlClient : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly RunLaunchSpec _spec;
    private readonly byte[] _challenge;
    private readonly SemaphoreSlim _messages = new(1, 1);
    private long _sequence = 1;
    private bool _broken;

    private RunControlClient(Stream stream, RunLaunchSpec spec, byte[] challenge, RunOwnerIdentity identity)
    {
        _stream = stream;
        _spec = spec;
        _challenge = challenge;
        Identity = identity;
    }

    public RunOwnerIdentity Identity { get; }

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
            || ready.LaunchBinding != launchBinding || identity.Endpoint != spec.ControlEndpoint
            || identity.ControlEpoch != spec.Epoch || identity.ProcessId <= 0)
        {
            throw new InvalidDataException("run_owner_identity_mismatch");
        }

        return new RunControlClient(stream, spec, challenge, identity);
    }

    public async ValueTask ActivateAsync(RunRelease release, CancellationToken cancellationToken) =>
        _ = await SendAsync(RunControlCommand.Activate, release, 0, cancellationToken).ConfigureAwait(false);

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

    private async ValueTask<RunControlFrame> SendAsync(RunControlCommand command, RunRelease? release, int grace,
        CancellationToken cancellationToken)
    {
        await _messages.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_broken)
            {
                throw new IOException("run_control_closed");
            }

            var sequence = checked(++_sequence);
            var request = new RunControlFrame(sequence, command, release, grace);
            var sent = false;
            try
            {
                await RunWire.WriteFrameAsync(_stream, _spec, _challenge, false, request, cancellationToken).ConfigureAwait(false);
                sent = true;
                var reply = await RunWire.ReadFrameAsync(_stream, _spec, _challenge, true, cancellationToken).ConfigureAwait(false);
                if (reply.Sequence != sequence || reply.Command != command)
                {
                    throw new InvalidDataException("run_control_response_mismatch");
                }

                if (reply.Error is { } error)
                {
                    throw new RunNativeException("run_owner_refused", error);
                }

                return reply;
            }
            catch (Exception error) when (error is IOException and not RunNativeException or OperationCanceledException)
            {
                // A partially sent frame also invalidates the channel. Retrying a release on this connection is unsafe.
                _broken = true;
                if (!sent)
                {
                    await _stream.DisposeAsync().ConfigureAwait(false);
                }

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
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _messages.Release();
        }
    }
}
