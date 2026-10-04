// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.LocalRpc;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// Runs the helper once its operating-system profile is in force: it serves the sandbox contract to the parent on the supplied service
/// stream, proves the one-use launch secret to the parent on the supplied control stream, keeps its registration lease, and leaves the
/// process the moment the parent is lost, the session lease passes or the session is closed. It never listens on a network endpoint and
/// opens nothing that was not inherited.
/// </summary>
internal static class ContentSandboxHost
{
    /// <summary>A seam for the tests only: builds the service the host serves. Production always builds the real one.</summary>
    internal delegate ContentSandboxServiceImpl ServiceFactory(
        ContentSandboxLaunchFrame frame,
        HelperResources resources,
        IContentParserProfile? profile,
        TimeProvider clock,
        Action<int> requestExit);

    private static readonly TimeSpan ExpiryPoll = TimeSpan.FromSeconds(1);

    /// <summary>Serves until the process should end and returns its exit code. Everything it was given is released before it returns.</summary>
    [SuppressMessage("Design", "CA1031", Justification = "Any failure of the host ends the process with a distinct exit code; nothing is reported to the parent.")]
    [SuppressMessage("Reliability", "CA2000", Justification = "The channel and the lease keeper are disposed in the finally block.")]
    [SuppressMessage("Reliability", "CA2025", Justification = "The tasks end with the exit decision, before the channel and the service are disposed.")]
    internal static async Task<int> RunAsync(
        ContentSandboxLaunchFrame frame,
        LocalRpcChildBootstrap bootstrap,
        HelperResources resources,
        ParserProfiles parsers,
        TimeProvider clock,
        CancellationToken stop,
        ServiceFactory? serviceFactory = null,
        Func<bool>? parentLost = null)
    {
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(bootstrap);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(parsers);
        ArgumentNullException.ThrowIfNull(clock);
        var exit = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var profile = parsers.Find(frame.ParserProfile);
        using var service = serviceFactory is null
            ? new ContentSandboxServiceImpl(frame, resources, profile, clock, code => exit.TrySetResult(code))
            : serviceFactory(frame, resources, profile, clock, code => exit.TrySetResult(code));
        LocalRpcServer? server = null;
        LocalRpcClientChannel? control = null;
        LocalRpcLeaseKeeper? keeper = null;
        try
        {
            var supplier = new LocalRpcStreamSupplier();
            if (!supplier.TrySupply(resources.Service))
            {
                return ContentSandboxContract.ExitInventoryInvalid;
            }

            var builder = LocalRpcServer.CreateBuilder(supplier);
            builder.Limits = new LocalRpcLimits { ShutdownTimeout = TimeSpan.FromMilliseconds(500) };
            server = builder
                .AddService(service)
                .RegisterControl(LocalRpcControlOperation.LeaseRenewal, ContentSandboxServiceImpl.ServiceName, ContentSandboxContract.RenewSessionMethod)
                .RegisterControl(LocalRpcControlOperation.Cancellation, ContentSandboxServiceImpl.ServiceName, ContentSandboxContract.CancelSessionMethod)
                .Build();
            await server.StartAsync(stop).ConfigureAwait(false);

            var controlStream = resources.Control;
            control = LocalRpcClientChannel.CreateFromStreams(_ => ValueTask.FromResult(controlStream));
            var registered = await RegisterAsync(control.CallInvoker, bootstrap, stop).ConfigureAwait(false);
            keeper = LocalRpcLeaseKeeper.Start((command, token) => RenewAsync(registered.Authenticated, command, token));

            var expiry = WatchExpiryAsync(service, exit, parentLost, stop);
            var lost = Task.Delay(Timeout.InfiniteTimeSpan, keeper.Lost).ContinueWith(
                _ => exit.TrySetResult(ContentSandboxContract.ExitParentLost),
                CancellationToken.None,
                TaskContinuationOptions.None,
                TaskScheduler.Default);
            using var stopRegistration = stop.Register(() => exit.TrySetResult(ContentSandboxContract.ExitClean));
            var code = await exit.Task.ConfigureAwait(false);
            _ = expiry;
            _ = lost;
            return code;
        }
        catch (Exception exception) when (exception is RpcException or IOException or LocalRpcRegistrationLostException or InvalidOperationException
            or OperationCanceledException or HttpRequestException)
        {
            return ContentSandboxContract.ExitParentLost;
        }
        finally
        {
            if (keeper is not null)
            {
                await keeper.DisposeAsync().ConfigureAwait(false);
            }

            if (control is not null)
            {
                await control.DisposeAsync().ConfigureAwait(false);
            }

            if (server is not null)
            {
                await server.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static async Task WatchExpiryAsync(ContentSandboxServiceImpl service, TaskCompletionSource<int> exit, Func<bool>? parentLost, CancellationToken stop)
    {
        using var timer = new PeriodicTimer(ExpiryPoll);
        try
        {
            while (await timer.WaitForNextTickAsync(stop).ConfigureAwait(false))
            {
                if (service.IsExpired)
                {
                    _ = exit.TrySetResult(ContentSandboxContract.ExitSessionExpired);
                    return;
                }

                if (parentLost?.Invoke() == true)
                {
                    _ = exit.TrySetResult(ContentSandboxContract.ExitParentLost);
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The process is stopping.
        }
    }

    /// <summary>The helper's generated client side of the bootstrap: challenge, proof, confirm.</summary>
    private static async Task<RegisteredParent> RegisterAsync(CallInvoker invoker, LocalRpcChildBootstrap bootstrap, CancellationToken stop)
    {
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(invoker);
        var identity = bootstrap.Identity;
        var manifest = new EndpointManifest
        {
            AppId = identity.BuildId,
            BuildHash = Convert.ToHexStringLower(identity.BuildDigest.Span),
            ContractSetHash = Convert.ToHexStringLower(identity.ContractSetDigest.Span),
        };
        manifest.ContractMajors.Add(identity.ProtocolVersion);
        var challenge = await client.ChallengeAsync(
            new LocalBootstrapServiceChallengeRequest
            {
                Meta = NewMeta(),
                InstanceId = SandboxRecords.ToWireId(bootstrap.InstanceId),
                Challenge = ByteString.CopyFrom(bootstrap.ClientChallenge.Span),
                Caller = manifest,
            },
            cancellationToken: stop).ConfigureAwait(false);
        var value = challenge.Value;
        if (!SandboxRecords.TryReadId(value.ChallengeId, out var challengeId) || !SandboxRecords.TryReadId(value.Server?.InstanceId, out var serverInstance))
        {
            throw new InvalidOperationException("The parent answered the challenge with a malformed identifier.");
        }

        var proof = bootstrap.ComputeProof(challengeId, value.ServerChallenge.Span, serverInstance);
        var confirm = await client.ConfirmAsync(
            new LocalBootstrapServiceConfirmRequest { Meta = NewMeta(), ChallengeId = value.ChallengeId, Proof = ByteString.CopyFrom(proof) },
            cancellationToken: stop).ConfigureAwait(false);
        var credentials = bootstrap.AcceptGrant(confirm.Value.PeerNonce.Span);
        return new RegisteredParent(invoker.Intercept(credentials), credentials);
    }

    private static async ValueTask<DateTimeOffset> RenewAsync(CallInvoker authenticated, ReadOnlyMemory<byte> commandId, CancellationToken token)
    {
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(authenticated);
        try
        {
            var response = await client.RenewAsync(
                new LocalBootstrapServiceRenewRequest
                {
                    Meta = new RequestMeta
                    {
                        CommandId = new Id { Value = ByteString.CopyFrom(commandId.Span) },
                        CorrelationId = SandboxRecords.ToWireId(Guid.NewGuid()),
                    },
                },
                cancellationToken: token).ConfigureAwait(false);
            return SandboxRecords.FromInstant(response.Value.ExpiresAt);
        }
        catch (RpcException exception) when (exception.StatusCode == StatusCode.Unauthenticated)
        {
            throw new LocalRpcRegistrationLostException("The parent ended the registration.", exception);
        }
    }

    private static RequestMeta NewMeta() => new()
    {
        CorrelationId = SandboxRecords.ToWireId(Guid.NewGuid()),
        CommandId = SandboxRecords.ToWireId(Guid.NewGuid()),
    };

    private sealed record RegisteredParent(CallInvoker Authenticated, LocalRpcCallCredentials Credentials);
}
