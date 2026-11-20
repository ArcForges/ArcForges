// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Tests;
using Google.Protobuf;
using Grpc.Core;
using static ArcForges.ClosedLoop.Tests.CloudLinkCenterControlTests;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "cloud")]
public sealed class RemoteStreamCenterTests
{
    private const string DataServiceName = "/arcforges.sandbox.v2.DataService/";
    private static readonly string[] TransferObservations = ["import.json", "export.json", "revoked-import.json", "expired-import.json"];
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 290_000, DisableParallelization = true)]
    public async Task InstalledNodePreservesRemoteStreamCursorsAndTheOriginalTransfer()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var (origin, directory) = RequireNativeFixture();
        await using var fixture = TestNode.Create();
        ConfigureNativeFixture(fixture, origin);
        var process = await fixture.StartNodeAsync();
        await using var local = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(local.CallInvoker);
        var control = new CenterControlService.CenterControlServiceClient(local.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(local.CallInvoker);
        var runs = new RunService.RunServiceClient(local.CallInvoker);
        var data = new DataService.DataServiceClient(local.CallInvoker);
        var hello = await node.HandshakeAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: Ct);
        var identity = Value(hello.Value, hello.Error);
        var epoch = identity.OwnerEpoch;
        Assert.NotNull(epoch);
        await using var cleanup = new OwnedNodeCleanup(fixture, process, control, epoch);

        var begin = new CenterControlServiceBeginConnectRequest
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            CenterOrigin = origin,
            ServiceMode = "self_hosted",
            FlowKind = "browser",
        };
        var enrollment = await ConnectAsync(control, begin, directory);
        await WriteObservationAsync(directory, "connected.json", new { ownerEpoch = Hex(epoch), nodeEpoch = identity.NodeEpoch });
        await WaitForFixtureAsync(directory, "connected-confirmed", NativeBound, "the exact authenticated Center peer");

        var logs = await CreateSandboxAsync(sandboxes, epoch, "Remote stream fixture");
        var files = await CreateSandboxAsync(sandboxes, epoch, "Remote transfer fixture");
        var fileRoot = Path.Combine(files.DataLocation, "data");
        var sentinel = Path.Combine(fileRoot, "owned-sentinel.txt");
        await File.WriteAllTextAsync(sentinel, "preserve owned data", Ct);
        var watch = await SetGrantAsync(node, epoch, enrollment, logs.SandboxId,
            ["/arcforges.sandbox.v2.RunService/WatchOutput", "/arcforges.sandbox.v2.NodeService/WatchEvents",
                "/arcforges.sandbox.v2.ResourceService/WatchUsage"], allowData: false);
        var transfer = await SetGrantAsync(node, epoch, enrollment, files.SandboxId,
            [DataServiceName + "BeginImport", DataServiceName + "WriteImport", DataServiceName + "CommitImport",
                DataServiceName + "BeginExport", DataServiceName + "ReadExport", DataServiceName + "InspectTransfer",
                DataServiceName + "CloseTransfer"], allowData: true);
        await using var transfers = new OwnedTransferCleanup(data, epoch, files.SandboxId, directory);
        await ObserveOutputAsync(runs, epoch, logs, watch, directory);

        await WriteObservationAsync(directory, "file-scope.json", new
        {
            grant = Hex(transfer.GrantId),
            revision = transfer.Revision.Value,
            sandbox = Hex(files.SandboxId),
            sandboxRevision = files.Revision.Value,
        });
        await WaitForFixtureAsync(directory, "usage-reconnect", TimeSpan.FromSeconds(65), "the first resource sample and the withheld export range");
        var disconnected = await control.DisconnectAsync(new() { Meta = Meta(mutation: true), OwnerEpoch = epoch },
            deadline: Deadline, cancellationToken: Ct);
        Assert.False(Value(disconnected.Value, disconnected.Error).Connection.ConnectionEnabled);
        begin.Meta = Meta(mutation: true);
        var resumed = await control.BeginConnectAsync(begin, deadline: Deadline, cancellationToken: Ct);
        Assert.Null(Value(resumed.Value, resumed.Error).FlowId);
        var online = await WaitForStatusAsync(control, value => value.ChannelState == "online");
        Assert.Equal(enrollment, online.EnrollmentId);
        var again = await node.HandshakeAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: Ct);
        var same = Value(again.Value, again.Error);
        Assert.Equal(epoch, same.OwnerEpoch);
        Assert.Equal(identity.NodeEpoch, same.NodeEpoch);
        await WriteObservationAsync(directory, "reconnected.json", new { ownerEpoch = Hex(epoch), nodeEpoch = same.NodeEpoch });

        var completed = await ReadObservationAsync(directory, "round-trip.json");
        var exportId = IdFrom(completed, "export");
        var exported = await InspectAsync(data, exportId, Ct);
        Assert.Equal(exportId, exported.Transfer.TransferId);
        Assert.Equal(files.SandboxId, exported.Transfer.SandboxId);
        Assert.Equal(TransferState.Complete, exported.Transfer.State);
        Assert.NotNull(exported.Transfer.ClosedAt);
        Assert.Equal(completed.GetProperty("digest").GetString(), exported.Transfer.Sha256);
        var file = await File.ReadAllBytesAsync(Path.Combine(fileRoot, "round-trip.bin"), Ct);
        Assert.Equal((1 << 20) + 17, file.Length);
        Assert.Equal(exported.Transfer.Sha256, Convert.ToHexStringLower(SHA256.HashData(file)));

        var oversizedCommand = IdFrom(await ReadObservationAsync(directory, "oversize.json"), "command");
        var missing = await node.GetOperationAsync(new()
        {
            Meta = Meta(),
            OwnerEpoch = epoch,
            CommandId = oversizedCommand,
        }, deadline: Deadline, cancellationToken: Ct);
        Assert.Null(missing.Value);
        Assert.Equal("not_found", missing.Error?.Code);
        Assert.False(File.Exists(Path.Combine(fileRoot, "oversize-import.bin")));

        var revoked = IdFrom(await ReadObservationAsync(directory, "revoke-transfer.json"), "transfer");
        await RevokeAsync(node, epoch, transfer);
        var beforeRevoke = await InspectAsync(data, revoked, Ct);
        await WriteObservationAsync(directory, "grant-revoked", new { });
        await WaitForFixtureAsync(directory, "revoke-refused", NativeBound, "typed refusal after grant revocation");
        await RequireUnchangedAsync(data, revoked, beforeRevoke, Path.Combine(fileRoot, "revoked.bin"));
        await CloseKnownAsync(data, epoch, beforeRevoke, Ct);

        var expiry = DateTimeOffset.UtcNow.AddSeconds(12);
        var shortGrant = await SetGrantAsync(node, epoch, enrollment, files.SandboxId,
            [DataServiceName + "BeginImport", DataServiceName + "WriteImport", DataServiceName + "InspectTransfer"],
            allowData: true, expiresAt: ProtoTime.ToInstant(expiry));
        await WriteObservationAsync(directory, "short-grant.json", new { grant = Hex(shortGrant.GrantId), revision = shortGrant.Revision.Value });
        var expiring = IdFrom(await ReadObservationAsync(directory, "expire-transfer.json"), "transfer");
        await TestNode.WaitAsync(() => DateTimeOffset.UtcNow >= expiry, NativeBound, "the original grant expires on the installed Node's wall clock");
        var beforeExpiry = await InspectAsync(data, expiring, Ct);
        await WriteObservationAsync(directory, "grant-expired", new { });
        await WaitForFixtureAsync(directory, "expire-refused", NativeBound, "typed refusal after expiry of the same grant");
        await RequireUnchangedAsync(data, expiring, beforeExpiry, Path.Combine(fileRoot, "expired.bin"));
        await CloseKnownAsync(data, epoch, beforeExpiry, Ct);
        Assert.Equal("preserve owned data", await File.ReadAllTextAsync(sentinel, Ct));
    }

    private static async Task<Id> ConnectAsync(CenterControlService.CenterControlServiceClient control,
        CenterControlServiceBeginConnectRequest begin, string directory)
    {
        var connected = await control.BeginConnectAsync(begin, deadline: Deadline, cancellationToken: Ct);
        var flow = Value(connected.Value, connected.Error).FlowId;
        Assert.NotNull(flow);
        var approval = await WaitForFlowAsync(control, flow, observed => observed.State == "pending" && observed.HasVerificationUri);
        await WriteObservationAsync(directory, "approval.json", new { verificationUri = approval.VerificationUri });
        await WaitForFlowAsync(control, flow, observed => observed.State == "succeeded");
        var online = await WaitForStatusAsync(control, status => status.ChannelState == "online");
        return Assert.IsType<Id>(online.EnrollmentId);
    }

    private static async Task<Sandbox> CreateSandboxAsync(SandboxService.SandboxServiceClient sandboxes, Id epoch, string name)
    {
        var windows = OperatingSystem.IsWindows();
        var reply = await sandboxes.CreateAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            DisplayName = name,
            Config = new()
            {
                ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
                ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
                Network = new() { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
                Resources = new() { CpuMaxMillicores = 500, MemoryMaxBytes = 256UL << 20, PressureAction = PressureAction.Throttle },
                OutputRetentionBytes = 4096,
            },
        }, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error).Sandbox;
    }

    private static async Task<RemoteGrant> SetGrantAsync(NodeService.NodeServiceClient node, Id epoch, Id enrollment, Id sandbox,
        string[] methods, bool allowData, Instant? expiresAt = null)
    {
        var reply = await node.SetRemoteGrantAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            Grant = new()
            {
                GrantId = CommandIds.New(),
                EnrollmentId = enrollment,
                ScopeKind = "sandbox",
                SandboxId = sandbox,
                AllowData = allowData,
                ExpiresAt = expiresAt,
                Methods = { methods },
            },
        }, deadline: Deadline, cancellationToken: Ct);
        var grant = Value(reply.Value, reply.Error).Grant;
        Assert.Equal(GrantState.Active, grant.State);
        return grant;
    }

    private static async Task RevokeAsync(NodeService.NodeServiceClient node, Id epoch, RemoteGrant grant)
    {
        var reply = await node.RevokeRemoteGrantAsync(new()
        {
            Meta = Meta(mutation: true, revision: grant.Revision),
            OwnerEpoch = epoch,
            GrantId = grant.GrantId,
        }, deadline: Deadline, cancellationToken: Ct);
        Assert.Equal(GrantState.Revoked, Value(reply.Value, reply.Error).Grant.State);
    }

    private static async Task ObserveOutputAsync(RunService.RunServiceClient runs, Id epoch, Sandbox sandbox, RemoteGrant watch, string directory)
    {
        var working = Path.Combine(sandbox.DataLocation, "work");
        var load = Path.Combine(working, OperatingSystem.IsWindows() ? "arcforges-testload.exe" : "arcforges-testload");
        File.Copy(TestNode.TestLoad, load);
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(load, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var marker = Path.Combine(working, "observed.txt");
        var prefix = Path.Combine(working, "prefix-ready");
        var tail = Path.Combine(working, "tail-ready");
        var reply = await runs.StartAsync(new()
        {
            Meta = Meta(mutation: true, revision: sandbox.Revision),
            OwnerEpoch = epoch,
            SandboxId = sandbox.SandboxId,
            Argv = { load, "terminal", "slow-output", marker, prefix, tail },
            WorkingDirectory = "work",
            TerminalMode = TerminalMode.Pipes,
        }, deadline: Deadline, cancellationToken: Ct);
        var run = Value(reply.Value, reply.Error).Run;
        try
        {
            await TestNode.WaitAsync(async () => File.Exists(marker) && (await InspectRunAsync(runs, run.RunId, Ct)).State == RunState.Running,
                NativeBound, "the same native Run reached Running and wrote its initial output");
            var running = await InspectRunAsync(runs, run.RunId, Ct);
            await WriteObservationAsync(directory, "stream-scope.json", new
            {
                grant = Hex(watch.GrantId),
                revision = watch.Revision.Value,
                sandbox = Hex(sandbox.SandboxId),
                run = Hex(run.RunId),
                runEpoch = running.Epoch,
            });
            await WaitForFixtureAsync(directory, "view-paused", TimeSpan.FromSeconds(10), "the owner consumed one remote frame and paused reading");
            await File.WriteAllTextAsync(prefix, string.Empty, Ct);
            await TestNode.WaitAsync(() =>
            {
                using var input = new FileStream(marker, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var observed = new StreamReader(input);
                return observed.ReadToEnd().Contains("prefix-complete", StringComparison.Ordinal);
            }, TimeSpan.FromSeconds(10), "the native producer advanced while the remote reader was paused");
            await WriteObservationAsync(directory, "view-backlog", new { });
            await WaitForFixtureAsync(directory, "view-cancelled", TimeSpan.FromSeconds(14), "the owner cancelled the bounded remote view");
            Assert.Equal(RunState.Running, (await InspectRunAsync(runs, run.RunId, Ct)).State);
        }
        finally
        {
            await File.WriteAllTextAsync(prefix, string.Empty, CancellationToken.None);
            await File.WriteAllTextAsync(tail, string.Empty, CancellationToken.None);
            await TestNode.WaitAsync(async () => (await InspectRunAsync(runs, run.RunId, CancellationToken.None)).State is
                RunState.Exited or RunState.Failed or RunState.RecoveryRequired, NativeBound, "the fixture released the bounded native producer");
        }

        var finished = await InspectRunAsync(runs, run.RunId, Ct);
        Assert.Equal(RunState.Exited, finished.State);
        Assert.Equal(0, finished.Exit.RawCode);
        await WriteObservationAsync(directory, "output-finished", new { });
    }

    private static async Task<Run> InspectRunAsync(RunService.RunServiceClient runs, Id run, CancellationToken token)
    {
        var reply = await runs.InspectAsync(new() { Meta = Meta(), RunId = run }, deadline: Deadline, cancellationToken: token);
        return Value(reply.Value, reply.Error).Run;
    }

    private static async Task<(Transfer Transfer, Revision Revision)> InspectAsync(DataService.DataServiceClient data, Id transfer, CancellationToken token)
    {
        var reply = await data.InspectTransferAsync(new() { Meta = Meta(), TransferId = transfer }, deadline: Deadline, cancellationToken: token);
        return (Value(reply.Value, reply.Error).Transfer, Assert.IsType<Revision>(reply.Meta.ResultRev));
    }

    private static async Task RequireUnchangedAsync(DataService.DataServiceClient data, Id id, (Transfer Transfer, Revision Revision) before, string path)
    {
        var current = await InspectAsync(data, id, Ct);
        Assert.Equal(before.Transfer, current.Transfer);
        Assert.Equal(before.Revision, current.Revision);
        Assert.Equal(0UL, current.Transfer.VerifiedOffset);
        Assert.False(File.Exists(path));
    }

    private static async Task CloseKnownAsync(DataService.DataServiceClient data, Id epoch, (Transfer Transfer, Revision Revision) current,
        CancellationToken token)
    {
        if (current.Transfer.ClosedAt is not null)
            return;
        Assert.NotEqual(TransferState.RecoveryRequired, current.Transfer.State);
        var reply = await data.CloseTransferAsync(new()
        {
            Meta = Meta(mutation: true, revision: current.Revision),
            OwnerEpoch = epoch,
            TransferId = current.Transfer.TransferId,
        }, deadline: Deadline, cancellationToken: token);
        var closed = Value(reply.Value, reply.Error).Transfer;
        Assert.Equal(current.Transfer.TransferId, closed.TransferId);
        Assert.NotNull(closed.ClosedAt);
    }

    private static async Task<JsonElement> ReadObservationAsync(string directory, string name)
    {
        await WaitForFixtureAsync(directory, name, NativeBound, "the Center's " + name);
        using var json = JsonDocument.Parse(await File.ReadAllBytesAsync(Path.Combine(directory, name), Ct));
        return json.RootElement.Clone();
    }

    private static Id IdFrom(JsonElement observation, string property)
    {
        var bytes = Convert.FromHexString(observation.GetProperty(property).GetString()!);
        Assert.Equal(16, bytes.Length);
        return new() { Value = ByteString.CopyFrom(bytes) };
    }

    private static string Hex(Id id) => Convert.ToHexStringLower(id.Value.Span);

    private sealed class OwnedTransferCleanup(DataService.DataServiceClient data, Id epoch, Id sandbox, string directory) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            using var stopped = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            foreach (string name in TransferObservations)
            {
                string path = Path.Combine(directory, name);
                if (!File.Exists(path))
                    continue;
                try
                {
                    using var recorded = JsonDocument.Parse(await File.ReadAllBytesAsync(path, stopped.Token));
                    var id = IdFrom(recorded.RootElement, "transfer");
                    var current = await InspectAsync(data, id, stopped.Token);
                    Assert.Equal(sandbox, current.Transfer.SandboxId);
                    await CloseKnownAsync(data, epoch, current, stopped.Token);
                }
                catch (Exception failure) when (failure is RpcException or OperationCanceledException or IOException or JsonException or Xunit.Sdk.XunitException)
                {
                    TestContext.Current.SendDiagnosticMessage("The owned transfer cleanup could not be confirmed: " + failure.GetType().Name);
                }
            }
        }
    }
}
