// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.LocalRpc.Platform.Shapes;
using ArcForges.Contracts.LocalRpc.Platform.V1;

namespace ArcForges.LocalRpc;

/// <summary>
/// Owns the actual parent bootstrap server and registration. Registration expiry, disconnect, revoked launch or disposal
/// stops this server. The trusted launcher still owns the OS child process and its containment/termination.
/// </summary>
public sealed class LocalRpcParentBootstrapHost : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly LocalRpcServer _server;
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CancellationTokenRegistration _ended;
    private Task? _shutdown;

    private LocalRpcParentBootstrapHost(LocalRpcRegistration registration, LocalRpcServer server)
    {
        Registration = registration;
        _server = server;
        _ended = registration.Ended.Register(static owner => { _ = ((LocalRpcParentBootstrapHost)owner!).DisposeAsync(); }, this);
    }

    public LocalRpcRegistration Registration { get; }
    /// <summary>Completes after owned registration/server cleanup; faults if cleanup fails. The launcher observes this to terminate its child.</summary>
    public Task Completion => _completion.Task;

    /// <summary>
    /// Creates the registration from the parent's actual runtime manifest, adds the real generated service to the explicitly configured
    /// private builder and starts it. Failed startup revokes the launch. No supplied child process, stream or application identity is invented.
    /// </summary>
    public static async Task<LocalRpcParentBootstrapHost> StartAsync(LocalRpcLaunch launch, EndpointManifest server,
        LocalRpcServerBuilder builder, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(launch);
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(builder);
        LocalRpcRegistration? registration = null;
        LocalRpcServer? transport = null;
        LocalRpcParentBootstrapHost? host = null;
        try
        {
            var frozen = server.Clone();
            if (!ContractShapeValidation.IsValid(frozen)) throw new ArgumentException("The complete actual parent runtime manifest is required.", nameof(server));
            registration = LocalRpcRegistration.Create(launch, BootstrapWire.FromId(frozen.InstanceId));
            var service = new LocalRpcBootstrapService(registration, frozen);
            cancellationToken.ThrowIfCancellationRequested();
            if (registration.Ended.IsCancellationRequested) throw new InvalidOperationException("The registration has already ended; relaunch under a fresh identity.");
            transport = builder.RequireRegistration(registration).AddService(service).Build();
            await transport.StartAsync(cancellationToken).ConfigureAwait(false);
            host = new LocalRpcParentBootstrapHost(registration, transport);
            if (registration.Ended.IsCancellationRequested)
            {
                await host.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException("The registration ended during startup; relaunch under a fresh identity.");
            }
            return host;
        }
        catch
        {
            if (host is not null) await host.DisposeAsync().ConfigureAwait(false);
            else
            {
                try
                {
                    if (registration is not null) await registration.DisposeAsync().ConfigureAwait(false);
                    else launch.Revoke();
                }
                finally { if (transport is not null) await transport.DisposeAsync().ConfigureAwait(false); }
            }
            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _shutdown ??= ShutdownAsync();
            return new(_completion.Task);
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "The shared completion task reports cleanup failure to every caller, including registration-triggered shutdown.")]
    private async Task ShutdownAsync()
    {
        await Task.Yield();
        Exception? failure = null;
        try { await Registration.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error) { failure = error; }
        try { await _server.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error) { failure = failure is null ? error : new AggregateException(failure, error); }
        _ended.Dispose();
        if (failure is null) _completion.TrySetResult();
        else _completion.TrySetException(failure);
    }
}
