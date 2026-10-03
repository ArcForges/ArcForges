// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Explicit local opt-in checks of WP-08.02 over real operating-system streams and real processes (set ARCFORGES_LOCALRPC_OS_STREAMS=1;
/// skipped by default and never run in hosted CI): registration, calls, renewal, lease expiry, a lost connection, a killed child and a
/// relaunch over a real Named Pipe (Windows) or a real Unix-socket path, on the real clock. A pass names only the operating system it
/// ran on and says nothing about wrong-user denial, which needs a second account.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcRegistrationOsChecks
{
    private const string OptIn = "Explicit local OS-stream checks only (ARCFORGES_LOCALRPC_OS_STREAMS=1).";
    private static readonly Status Refused = new(StatusCode.Unauthenticated, "Registration is required.");
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(60);

    public static bool Enabled => LocalRpcOsStreamChecks.Enabled;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Rig : IAsyncDisposable
    {
        private Rig(LaunchWorld world, LocalRpcLaunchAuthority authority)
        {
            World = world;
            Authority = authority;
        }

        internal LaunchWorld World { get; }

        internal LocalRpcLaunchAuthority Authority { get; }

        internal static Rig Create(bool unixSocket)
        {
            var world = new LaunchWorld();
            return new Rig(world, LocalRpcLaunchAuthority.Create(world.Root, null, new LaunchEnvironment { ForceUnixSocket = unixSocket }));
        }

        internal async Task<Served> ServeAsync(TimeSpan lease)
        {
            var launch = Authority.Launch("slot-a", Launches.Identity());
#pragma warning disable CA2000 // Owned by the returned Served, which disposes it.
            var registration = LocalRpcRegistration.Create(launch, new RegistrationTimings { Lease = lease });
#pragma warning restore CA2000
            var resource = launch.HandoffBootstrapResource();
            var adapter = new BootstrapAdapter();
            var probe = new ProbeBrokerService();
            var server = LocalRpcServer.CreateBuilder(launch.Endpoint!).RequireRegistration(registration).AddService(adapter).AddService(probe).Build();
            await server.StartAsync(Ct);
            return new Served(launch, registration, resource, probe, server);
        }

        public async ValueTask DisposeAsync()
        {
            await Authority.DisposeAsync();
            World.Dispose();
        }
    }

    private sealed class Served(LocalRpcLaunch launch, LocalRpcRegistration registration, byte[] resource, ProbeBrokerService probe, LocalRpcServer server) : IAsyncDisposable
    {
        internal LocalRpcLaunch Launch { get; } = launch;

        internal LocalRpcRegistration Registration { get; } = registration;

        internal byte[] Resource { get; } = resource;

        internal ProbeBrokerService Probe { get; } = probe;

        internal LocalRpcServer Server { get; } = server;

        public async ValueTask DisposeAsync()
        {
            await Server.DisposeAsync();
            await Registration.DisposeAsync();
            await Launch.DisposeAsync();
        }
    }

    public static TheoryData<string> Transports() => OperatingSystem.IsWindows() ? new() { "named-pipe", "unix-socket" } : new() { "unix-socket" };

    [Theory(Skip = OptIn, SkipUnless = nameof(Enabled))]
    [MemberData(nameof(Transports))]
    public async Task AChildRegistersCallsRenewsAndLosesItsRegistrationOnARealEndpoint(string transport)
    {
        await using var rig = Rig.Create(unixSocket: transport == "unix-socket");
        await using var served = await rig.ServeAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(transport == "unix-socket" ? LocalRpcTransport.UnixDomainSocket : LocalRpcTransport.NamedPipe, served.Launch.Endpoint!.Transport);
        using var bootstrap = LocalRpcChildBootstrap.FromResource(served.Resource);
        await using var channel = LocalRpcClientChannel.Create(served.Launch.Endpoint!, new LocalRpcLimits { ConnectTimeout = TimeSpan.FromSeconds(10) });

        // Before the proof nothing but the two bootstrap steps is served.
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(channel.CallInvoker, Ct));
        var child = await ChildClient.RegisterAsync(channel.CallInvoker, bootstrap, Ct);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(channel.CallInvoker, Ct));

        // Renewals keep it alive for more than two leases; a second connection to the same endpoint is dropped unread.
        var keeper = LocalRpcLeaseKeeper.Start((command, token) => ChildClient.RenewAsync(child.Authenticated, command, token), TimeProvider.System, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(2));
        await Task.Delay(TimeSpan.FromSeconds(5), Ct);
        Assert.Equal(LocalRpcRegistrationState.Registered, served.Registration.State);
        await using var second = LocalRpcClientChannel.Create(served.Launch.Endpoint!, new LocalRpcLimits { ConnectTimeout = TimeSpan.FromSeconds(10) });
        var late = await ChildClient.ListStatusAsync(second.CallInvoker.Intercept(child.Credentials), Ct);
        Assert.NotEqual(Status.DefaultSuccess, late);

        // Without renewals the lease ends on its own.
        await keeper.DisposeAsync();
        await WaitForEndAsync(served.Registration);
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, served.Registration.EndReason);
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
    }

    [Theory(Skip = OptIn, SkipUnless = nameof(Enabled))]
    [MemberData(nameof(Transports))]
    public async Task ALostConnectionAndARelaunchOnARealEndpointNeedFreshGrants(string transport)
    {
        await using var rig = Rig.Create(unixSocket: transport == "unix-socket");
        await using var first = await rig.ServeAsync(TimeSpan.FromSeconds(30));
        using var bootstrap = LocalRpcChildBootstrap.FromResource(first.Resource);
#pragma warning disable CA2000 // Disposed explicitly below: the test closes the connection on purpose.
        var channel = LocalRpcClientChannel.Create(first.Launch.Endpoint!, new LocalRpcLimits { ConnectTimeout = TimeSpan.FromSeconds(10) });
#pragma warning restore CA2000
        var child = await ChildClient.RegisterAsync(channel.CallInvoker, bootstrap, Ct);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));

        // A closed connection ends the registration and the launch.
        await channel.DisposeAsync();
        await WaitForEndAsync(first.Registration);
        Assert.Equal(LocalRpcRegistrationEnd.ConnectionLost, first.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, first.Launch.Status());

        // The relaunch is the next epoch with a new endpoint, secret and nonce; the old child's grants mean nothing to it.
        await using var next = await rig.ServeAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(first.Launch.Descriptor.Epoch + 1, next.Launch.Descriptor.Epoch);
        using var nextBootstrap = LocalRpcChildBootstrap.FromResource(next.Resource);
        await using var nextChannel = LocalRpcClientChannel.Create(next.Launch.Endpoint!, new LocalRpcLimits { ConnectTimeout = TimeSpan.FromSeconds(10) });
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(nextChannel.CallInvoker.Intercept(child.Credentials), Ct));
        var fresh = await ChildClient.RegisterAsync(nextChannel.CallInvoker, nextBootstrap, Ct);
        Assert.False(child.Nonce.AsSpan().SequenceEqual(fresh.Nonce));
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(fresh.Authenticated, Ct));
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task ARealProcessRegistersOverARealEndpointAndItsDeathEndsTheRegistrationThenARelaunchRegistersFresh()
    {
        await using var rig = Rig.Create(unixSocket: !OperatingSystem.IsWindows());
        await using var first = await rig.ServeAsync(TimeSpan.FromSeconds(2));
        var staleResource = (byte[])first.Resource.Clone();
        using var process = StartHelper();
        first.Launch.BindChild(LocalRpcProcessIdentity.FromProcess(process));
        await process.StandardInput.WriteLineAsync(Convert.ToBase64String(first.Resource));
        await process.StandardInput.FlushAsync(Ct);
        Array.Clear(first.Resource);

        Assert.StartsWith("REGISTERED ", await ReadLineAsync(process), StringComparison.Ordinal);
        Assert.Equal("CALL OK", await ReadLineAsync(process));
        Assert.Equal("ALIVE", await ReadLineAsync(process));
        // Three leases pass with the child renewing from another process.
        await Task.Delay(TimeSpan.FromSeconds(6), Ct);
        Assert.Equal(LocalRpcRegistrationState.Registered, first.Registration.State);
        Assert.Equal(1, first.Probe.Dispatched);

        process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync(Ct);
        await WaitForEndAsync(first.Registration);
        Assert.Equal(LocalRpcRegistrationEnd.ConnectionLost, first.Registration.EndReason);
        Assert.NotEqual(LocalRpcLaunchRefusal.None, first.Launch.Status());

        // The relaunch (next epoch) registers a new process from scratch; a process holding the first launch's spent resource cannot.
        await using var next = await rig.ServeAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(first.Launch.Descriptor.Epoch + 1, next.Launch.Descriptor.Epoch);
        using var stale = StartHelper();
        await stale.StandardInput.WriteLineAsync(Convert.ToBase64String(staleResource));
        await stale.StandardInput.FlushAsync(Ct);
        Assert.StartsWith("REFUSED ", await ReadLineAsync(stale), StringComparison.Ordinal);
        await stale.WaitForExitAsync(Ct);
        Assert.Equal(3, stale.ExitCode);
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, next.Registration.State);

        using var fresh = StartHelper();
        next.Launch.BindChild(LocalRpcProcessIdentity.FromProcess(fresh));
        await fresh.StandardInput.WriteLineAsync(Convert.ToBase64String(next.Resource));
        await fresh.StandardInput.FlushAsync(Ct);
        Assert.StartsWith("REGISTERED ", await ReadLineAsync(fresh), StringComparison.Ordinal);
        Assert.Equal("CALL OK", await ReadLineAsync(fresh));
        fresh.Kill(entireProcessTree: true);
        await fresh.WaitForExitAsync(Ct);
    }

    private static Process StartHelper()
    {
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("The test executable path is unknown.");
        var start = new ProcessStartInfo(host)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.Environment["DOTNET_STARTUP_HOOKS"] = Path.Combine(AppContext.BaseDirectory, "ArcForges.LocalRpc.Tests.dll");
        if (string.Equals(Path.GetFileNameWithoutExtension(host), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "ArcForges.LocalRpc.Tests.dll"));
        }

        start.Environment[LaunchHelperProcess.Variable] = "register";
        return Process.Start(start) ?? throw new InvalidOperationException("The helper process did not start.");
    }

    private static async Task<string> ReadLineAsync(Process process)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        bounded.CancelAfter(Patience);
        try
        {
            return await process.StandardOutput.ReadLineAsync(bounded.Token)
                ?? throw new InvalidOperationException("The helper closed its output: " + await process.StandardError.ReadToEndAsync(Ct));
        }
        catch (OperationCanceledException) when (!Ct.IsCancellationRequested)
        {
            throw new TimeoutException("The helper printed no line in time.");
        }
    }

    private static async Task WaitForEndAsync(LocalRpcRegistration registration)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        bounded.CancelAfter(Patience);
        using var either = CancellationTokenSource.CreateLinkedTokenSource(registration.Ended, bounded.Token);
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, either.Token);
        }
        catch (OperationCanceledException)
        {
            // Either the registration ended or the wait timed out; the assertion below says which.
        }

        Assert.True(registration.Ended.IsCancellationRequested, "The registration did not end in time.");
    }
}
