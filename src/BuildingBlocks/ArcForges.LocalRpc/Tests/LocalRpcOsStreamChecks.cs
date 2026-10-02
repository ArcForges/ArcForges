// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Explicit local opt-in checks against real OS streams (set ARCFORGES_LOCALRPC_OS_STREAMS=1). They are skipped
/// by default and never run in hosted CI. A pass names only the operating system it ran on: the Unix domain
/// socket code path can be exercised on Windows (AF_UNIX) but that is not Linux or macOS evidence, and
/// cross-user denial needs a second account that these checks do not have.
/// </summary>
// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcOsStreamChecks
{
    private const string OptIn = "Explicit local OS-stream checks only (ARCFORGES_LOCALRPC_OS_STREAMS=1).";
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    public static bool Enabled => Environment.GetEnvironmentVariable("ARCFORGES_LOCALRPC_OS_STREAMS") == "1"
        && Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true";

    public static bool PipeEnabled => Enabled && OperatingSystem.IsWindows();

    [Fact(Skip = OptIn, SkipUnless = nameof(PipeEnabled))]
    public async Task NamedPipeCarriesGeneratedCallsAndSurvivesMalformedFramesOnTheRealOsStream()
    {
        var endpoint = LocalRpcEndpoint.NamedPipe("af-os-pipe-" + Guid.NewGuid().ToString("N"));

        await RunTransportScenarioAsync(endpoint, TestContext.Current.CancellationToken);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task UnixSocketPathCarriesGeneratedCallsAndSurvivesMalformedFramesOnTheRealOsStream()
    {
        var directory = Directory.CreateTempSubdirectory("afrpc-");
        try
        {
            var path = Path.Combine(directory.FullName, "c.sock");
            var endpoint = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, path);
            await RunTransportScenarioAsync(endpoint, TestContext.Current.CancellationToken);

            // The listener removed the socket it created and a second server can reuse the name.
            Assert.False(File.Exists(path));
            await RunTransportScenarioAsync(endpoint, TestContext.Current.CancellationToken);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AUnixSocketIsNeverBoundOverAnExistingFileAndIsOwnerOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        var directory = Directory.CreateTempSubdirectory("afrpc-");
        try
        {
            var path = Path.Combine(directory.FullName, "c.sock");
            await File.WriteAllTextAsync(path, "not a socket", ct);
            Assert.Throws<IOException>(() => UnixSocketAcceptSource.Bind(path, 4));
            Assert.Equal("not a socket", await File.ReadAllTextAsync(path, ct));
            File.Delete(path);

            await using var source = UnixSocketAcceptSource.Bind(path, 4);
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            }

            await source.UnbindAsync();
            Assert.False(File.Exists(path));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(PipeEnabled))]
    [SupportedOSPlatform("windows")]
    public async Task EveryNamedPipeInstanceGrantsOnlyTheCurrentUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var name = "af-os-acl-" + Guid.NewGuid().ToString("N");
        await using var source = NamedPipeAcceptSource.Bind(name);
        var accepted = source.AcceptAsync(ct).AsTask();
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Anonymous);
        await client.ConnectAsync(ct);
        await using var stream = await accepted.WaitAsync(Patience, ct);

        var server = Assert.IsType<NamedPipeServerStream>(stream);
        var security = server.GetAccessControl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>().ToArray();
        var user = WindowsIdentity.GetCurrent().User;

        Assert.NotNull(user);
        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
        {
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(user, rule.IdentityReference);
        });
        Assert.Equal(user, security.GetOwner(typeof(SecurityIdentifier)));
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task QuickReconnectsAreAllServedOnTheRealOsStream()
    {
        var ct = TestContext.Current.CancellationToken;
        var directory = Directory.CreateTempSubdirectory("afrpc-");
        try
        {
            var endpoint = OperatingSystem.IsWindows()
                ? LocalRpcEndpoint.NamedPipe("af-os-reconnect-" + Guid.NewGuid().ToString("N"))
                : LocalRpcEndpoint.UnixDomainSocket(Path.Combine(directory.FullName, "c.sock"));
            await ReconnectAsync(endpoint, ct);
            await ReconnectAsync(LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, Path.Combine(directory.FullName, "u.sock")), ct);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task TheCallBoundsAndTheControlSlotsHoldOnTheRealOsStream()
    {
        var ct = TestContext.Current.CancellationToken;
        var directory = Directory.CreateTempSubdirectory("afrpc-");
        try
        {
            await RunBoundsScenarioAsync(OperatingSystem.IsWindows()
                ? LocalRpcEndpoint.NamedPipe("af-os-bounds-" + Guid.NewGuid().ToString("N"))
                : LocalRpcEndpoint.UnixDomainSocket(Path.Combine(directory.FullName, "c.sock")), ct);
            await RunBoundsScenarioAsync(LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, Path.Combine(directory.FullName, "u.sock")), ct);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static async Task RunBoundsScenarioAsync(LocalRpcEndpoint endpoint, CancellationToken ct)
    {
        var probe = new ProbeService();
        await using var server = LocalRpcServer.CreateBuilder(endpoint)
            .AddService(probe)
            .RegisterControl(LocalRpcControlOperation.Health, BoundsProbe.Health)
            .RegisterControl(LocalRpcControlOperation.Cancellation, BoundsProbe.Cancel)
            .Build();
        await server.StartAsync(ct);
        await using var channel = LocalRpcClientChannel.Create(endpoint);
        var client = new ProbeClient(channel.CallInvoker);
        var calls = new List<AsyncUnaryCall<byte[]>>();
        var total = LocalRpcLimits.DefaultMaxActiveCalls + LocalRpcLimits.DefaultMaxQueuedCalls;
        for (var id = 0; id < total; id++)
        {
            calls.Add(client.Work(id, deadline: DateTime.UtcNow + Patience));
            if (id < LocalRpcLimits.DefaultMaxActiveCalls)
            {
                await BoundsHarness.WaitUntilAsync(() => probe.Running == id + 1, "an active call", ct);
            }
            else
            {
                var queued = id - LocalRpcLimits.DefaultMaxActiveCalls + 1;
                await BoundsHarness.WaitUntilAsync(() => server.GetBoundsSnapshot().DataQueued == queued, "a queued call", ct);
            }
        }

        var refused = await ProbeClient.FailureAsync(client.Work(total, deadline: DateTime.UtcNow + Patience));
        var health = await client.Health().ResponseAsync.WaitAsync(Patience, ct);
        var cancelled = await client.Cancel(0).ResponseAsync.WaitAsync(Patience, ct);

        Assert.Equal(StatusCode.ResourceExhausted, refused.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(refused, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, refusal!.Reason);
        Assert.Equal(LocalRpcLimits.DefaultMaxActiveCalls, health[0]);
        Assert.Equal(new byte[] { 1 }, cancelled);
        await BoundsHarness.WaitUntilAsync(() => probe.Started.Count == LocalRpcLimits.DefaultMaxActiveCalls + 1, "the oldest queued call to start", ct);
        Assert.Equal(LocalRpcLimits.DefaultMaxActiveCalls, probe.Started[LocalRpcLimits.DefaultMaxActiveCalls]);
        for (var id = 0; id < total + 8; id++)
        {
            _ = probe.Release(id);
        }

        using var drained = CancellationTokenSource.CreateLinkedTokenSource(ct);
        drained.CancelAfter(Patience);
        while (calls.Any(call => !call.ResponseAsync.IsCompleted))
        {
            for (var id = 0; id < total + 8; id++)
            {
                _ = probe.Release(id);
            }

            await Task.Delay(10, drained.Token);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(PipeEnabled))]
    public async Task ABoundPipeNameCannotBeBoundAgainWhileItIsAlive()
    {
        var name = "af-os-first-" + Guid.NewGuid().ToString("N");
        await using var first = NamedPipeAcceptSource.Bind(name);

        var refused = Assert.ThrowsAny<Exception>(() => NamedPipeAcceptSource.Bind(name));
        Assert.True(refused is IOException or UnauthorizedAccessException, refused.GetType().Name);
        await first.UnbindAsync();
        await using var reused = NamedPipeAcceptSource.Bind(name);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task TheServingProcessOwnsNoTcpListener()
    {
        var ct = TestContext.Current.CancellationToken;
        var before = await ProcessTcpListeners.SnapshotAsync(ct);
        var directory = Directory.CreateTempSubdirectory("afrpc-");
        try
        {
            var endpoint = OperatingSystem.IsWindows()
                ? LocalRpcEndpoint.NamedPipe("af-os-tcp-" + Guid.NewGuid().ToString("N"))
                : LocalRpcEndpoint.UnixDomainSocket(Path.Combine(directory.FullName, "c.sock"));
            var service = new RecordingBootstrapService();
            await using var server = LocalRpcServer.CreateBuilder(endpoint).AddService(service).Build();
            await server.StartAsync(ct);
            await using var channel = LocalRpcClientChannel.Create(endpoint);
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            _ = await client.ChallengeAsync(Requests.Challenge(32), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

            var during = await ProcessTcpListeners.SnapshotAsync(ct);

            Assert.Equal(1, service.Dispatched);
            Assert.Equal(before, during);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(PipeEnabled))]
    public async Task AStoppedPipeServerReleasesItsNameAndRefusesNewClients()
    {
        var ct = TestContext.Current.CancellationToken;
        var endpoint = LocalRpcEndpoint.NamedPipe("af-os-stop-" + Guid.NewGuid().ToString("N"));
        var server = LocalRpcServer.CreateBuilder(endpoint).AddService(new RecordingBootstrapService()).Build();
        await server.StartAsync(ct);
        await server.StopAsync(ct);
        await server.DisposeAsync();

        await using var channel = LocalRpcClientChannel.Create(endpoint, new LocalRpcLimits { ConnectTimeout = TimeSpan.FromMilliseconds(500) });
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
        var refused = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + TimeSpan.FromSeconds(5), cancellationToken: ct));

        Assert.NotEqual(StatusCode.OK, refused.StatusCode);
    }

    private static async Task ReconnectAsync(LocalRpcEndpoint endpoint, CancellationToken ct)
    {
        var service = new RecordingBootstrapService();
        await using var server = LocalRpcServer.CreateBuilder(endpoint).AddService(service).Build();
        await server.StartAsync(ct);
        const int rounds = 100;
        for (var index = 0; index < rounds; index++)
        {
            await using var channel = LocalRpcClientChannel.Create(endpoint);
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        }

        Assert.Equal(rounds, service.Dispatched);
    }

    private static async Task RunTransportScenarioAsync(LocalRpcEndpoint endpoint, CancellationToken ct)
    {
        var service = new RecordingBootstrapService();
        await using var server = LocalRpcServer.CreateBuilder(endpoint).AddService(service).Build();
        await server.StartAsync(ct);
        await using var channel = LocalRpcClientChannel.Create(endpoint);
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var echoed = await client.ChallengeAsync(Requests.Challenge(3 * 1024 * 1024), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        Assert.Equal(3 * 1024 * 1024, echoed.Value.ServerChallenge.Length);
        Assert.Equal(1, service.Dispatched);

        var oversized = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.ChallengeAsync(Requests.Challenge(LocalRpcLimits.DefaultMaxMessageBytes + 1), deadline: DateTime.UtcNow + Patience, cancellationToken: ct));
        Assert.Equal(StatusCode.ResourceExhausted, oversized.StatusCode);

        foreach (var (fixture, goAway) in new (byte[] Bytes, int? Code)[]
        {
            ("GET / HTTP/1.1\r\nHost: arcforges.invalid\r\n\r\n"u8.ToArray(), null),
            (RawFrames.Concat(RawFrames.Preface, RawFrames.Frame(0, 0x4, 0, 1)), 1),
            (RawFrames.Concat(RawFrames.Preface, RawFrames.Frame(65535, 0x0, 0, 1)), 6),
            (RawFrames.Concat(RawFrames.Preface, RawFrames.Frame(4, 0x1, 0x4, 1, [0xFF, 0xFF, 0xFF, 0xFF])), 9),
        })
        {
            await using var raw = await OpenRawAsync(endpoint, ct);
            await raw.WriteAsync(fixture, ct);
            var frames = await RawFrames.ReadUntilClosedAsync(raw, Patience, ct);
            if (goAway is { } expected)
            {
                Assert.Equal(expected, RawFrames.GoAwayCode(frames));
            }
        }

        foreach (var (flag, declared, actual, encoding, status) in new (byte, uint, int, string?, StatusCode)[]
        {
            (0, 100u, 10, null, StatusCode.Internal),
            (2, 8u, 8, null, StatusCode.Unknown),
            (1, 8u, 8, "gzip", StatusCode.Unimplemented),
            (0, (uint)LocalRpcLimits.DefaultMaxMessageBytes + 1, 16, null, StatusCode.ResourceExhausted),
        })
        {
            var observed = await RawGrpc.PostAsync(
                token => new ValueTask<Stream>(OpenRawAsync(endpoint, token)),
                Requests.ChallengePath,
                RawFrames.GrpcMessage(flag, declared, actual),
                encoding,
                ct);
            Assert.Equal(status, observed);
        }

        Assert.Equal(1, service.Dispatched);
        var after = await client.ChallengeAsync(Requests.Challenge(64), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        Assert.Equal(64, after.Value.ServerChallenge.Length);
        Assert.Equal(2, service.Dispatched);
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the connected socket passes to the returned stream.")]
    private static async Task<Stream> OpenRawAsync(LocalRpcEndpoint endpoint, CancellationToken ct)
    {
        if (endpoint.Transport == LocalRpcTransport.NamedPipe)
        {
            var pipe = new NamedPipeClientStream(".", endpoint.Address, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Anonymous);
            await pipe.ConnectAsync(ct);
            return pipe;
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(endpoint.Address), ct);
        return new NetworkStream(socket, ownsSocket: true);
    }
}

/// <summary>The TCP sockets in the LISTEN state that the current process owns, read from the OS.</summary>
internal static class ProcessTcpListeners
{
    internal static async Task<string[]> SnapshotAsync(CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
        {
            var output = await RunAsync("netstat", "-ano", ct).ConfigureAwait(false);
            var pid = Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return [.. output.Split('\n')
                .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Where(parts => parts.Length >= 5 && parts[0].StartsWith("TCP", StringComparison.Ordinal)
                    && parts[3] == "LISTENING" && parts[4] == pid)
                .Select(parts => parts[0] + " " + parts[1])
                .Order(StringComparer.Ordinal)];
        }

        if (OperatingSystem.IsLinux())
        {
            var inodes = new HashSet<string>(StringComparer.Ordinal);
            foreach (var descriptor in Directory.EnumerateFiles("/proc/self/fd"))
            {
                var target = new FileInfo(descriptor).LinkTarget;
                if (target is not null && target.StartsWith("socket:[", StringComparison.Ordinal))
                {
                    inodes.Add(target["socket:[".Length..^1]);
                }
            }

            var listeners = new List<string>();
            foreach (var table in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
            {
                foreach (var line in (await File.ReadAllLinesAsync(table, ct).ConfigureAwait(false)).Skip(1))
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 9 && parts[3] == "0A" && inodes.Contains(parts[9]))
                    {
                        listeners.Add(table + " " + parts[1]);
                    }
                }
            }

            return [.. listeners.Order(StringComparer.Ordinal)];
        }

        var lsof = await RunAsync("lsof", $"-nP -a -p {Environment.ProcessId} -iTCP -sTCP:LISTEN", ct).ConfigureAwait(false);
        return [.. lsof.Split('\n').Skip(1).Where(line => line.Length > 0).Order(StringComparer.Ordinal)];
    }

    private static async Task<string> RunAsync(string file, string arguments, CancellationToken ct)
    {
        using var process = Process.Start(new ProcessStartInfo(file, arguments)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException("Could not start " + file);
        var output = await process.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
        await process.WaitForExitAsync(ct).ConfigureAwait(false);
        return output;
    }
}
