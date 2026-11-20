// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using static ArcForges.ClosedLoop.Tests.CloudLinkCenterControlTests;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "cloud")]
public sealed class RemoteStreamCenterTests
{
    private const string DataServiceName = "/arcforges.sandbox.v2.DataService/";
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
        var exported = ReadFixtureTransfer(fixture, files.SandboxId, epoch, exportId, transfer, enrollment);
        Assert.Equal(StoredTransferDirection.Export, exported.Direction);
        Assert.Equal(StoredTransferState.Complete, exported.State);
        Assert.Equal(StoredTransferCloseReason.ExplicitClose, exported.CloseReason);
        Assert.NotNull(exported.ClosedAt);
        Assert.Equal(completed.GetProperty("digest").GetString(), exported.ExpectedSha256);
        Assert.False(File.Exists(FixtureStage(fixture, exportId)));
        var file = await File.ReadAllBytesAsync(Path.Combine(fileRoot, "round-trip.bin"), Ct);
        Assert.Equal((1 << 20) + 17, file.Length);
        Assert.Equal(exported.ExpectedSha256, Convert.ToHexStringLower(SHA256.HashData(file)));

        var oversizedCommand = IdFrom(await ReadObservationAsync(directory, "oversize.json"), "command");
        RequireNoFixtureReceipt(fixture, files.SandboxId, epoch, oversizedCommand);
        Assert.False(File.Exists(Path.Combine(fileRoot, "oversize-import.bin")));

        var revoked = IdFrom(await ReadObservationAsync(directory, "revoke-transfer.json"), "transfer");
        var beforeRevoke = ReadFixtureTransfer(fixture, files.SandboxId, epoch, revoked, transfer, enrollment);
        await RevokeAsync(node, epoch, transfer);
        await WriteObservationAsync(directory, "grant-revoked", new { });
        await WaitForFixtureAsync(directory, "revoke-refused", NativeBound, "typed refusal after grant revocation");
        RequireUnchangedImport(fixture, files.SandboxId, epoch, revoked, transfer, enrollment, beforeRevoke, Path.Combine(fileRoot, "revoked.bin"));

        var shortFiles = await CreateSandboxAsync(sandboxes, epoch, "Expiring transfer fixture");
        var expiry = DateTimeOffset.UtcNow.AddSeconds(12);
        var shortGrant = await SetGrantAsync(node, epoch, enrollment, shortFiles.SandboxId,
            [DataServiceName + "BeginImport", DataServiceName + "WriteImport", DataServiceName + "InspectTransfer"],
            allowData: true, expiresAt: ProtoTime.ToInstant(expiry));
        await WriteObservationAsync(directory, "short-grant.json", new
        {
            grant = Hex(shortGrant.GrantId),
            revision = shortGrant.Revision.Value,
            sandbox = Hex(shortFiles.SandboxId),
            sandboxRevision = shortFiles.Revision.Value,
        });
        var expiring = IdFrom(await ReadObservationAsync(directory, "expire-transfer.json"), "transfer");
        var beforeExpiry = ReadFixtureTransfer(fixture, shortFiles.SandboxId, epoch, expiring, shortGrant, enrollment);
        await TestNode.WaitAsync(() => DateTimeOffset.UtcNow >= expiry, NativeBound, "the original grant expires on the installed Node's wall clock");
        await WriteObservationAsync(directory, "grant-expired", new { });
        await WaitForFixtureAsync(directory, "expire-refused", NativeBound, "typed refusal after expiry of the same grant");
        RequireUnchangedImport(fixture, shortFiles.SandboxId, epoch, expiring, shortGrant, enrollment, beforeExpiry,
            Path.Combine(shortFiles.DataLocation, "data", "expired.bin"));
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

    private static StoredTransfer ReadFixtureTransfer(TestNode fixture, Id sandbox, Id epoch, Id transfer, RemoteGrant grant, Id enrollment)
    {
        using var database = OpenFixtureDatabase(fixture);
        var reader = new StoreReader(database, transaction: null, clock: TimeProvider.System);
        string owner = FixtureSandboxOwner(reader, sandbox);
        var row = Assert.IsType<StoredTransfer>(TransferRecords.Get(reader, owner, Hex(transfer)));
        Assert.Equal(Hex(sandbox), row.SandboxId);
        Assert.True(epoch.Value.Span.SequenceEqual(row.OwnerEpoch));
        Assert.Equal(Hex(grant.GrantId), row.Manifest.GrantId);
        Assert.Equal(grant.Revision.Value, row.Manifest.GrantRevision);
        Assert.Equal(Hex(enrollment), row.Manifest.EnrollmentId);
        Assert.NotEqual(owner, row.Manifest.ActorId);
        return row;
    }

    private static void RequireUnchangedImport(TestNode fixture, Id sandbox, Id epoch, Id id, RemoteGrant grant, Id enrollment,
        StoredTransfer before, string path)
    {
        var current = ReadFixtureTransfer(fixture, sandbox, epoch, id, grant, enrollment);
        Assert.Equal(before with { OwnerEpoch = current.OwnerEpoch }, current);
        Assert.Equal(StoredTransferDirection.Import, current.Direction);
        Assert.Equal(StoredTransferState.Open, current.State);
        Assert.Equal("data/" + Path.GetFileName(path), current.Manifest.RelativePath);
        Assert.Null(current.Manifest.Pending);
        Assert.Null(current.ClosedAt);
        Assert.Equal(0L, current.VerifiedOffset);
        Assert.Equal(0L, new FileInfo(FixtureStage(fixture, id)).Length);
        Assert.False(File.Exists(path));
    }

    private static void RequireNoFixtureReceipt(TestNode fixture, Id sandbox, Id epoch, Id command)
    {
        using var database = OpenFixtureDatabase(fixture);
        var reader = new StoreReader(database, transaction: null, clock: TimeProvider.System);
        Assert.Null(DurableOperationReads.Find(reader, FixtureSandboxOwner(reader, sandbox), epoch.Value.Span, command.Value.Span));
    }

    private static SqliteConnection OpenFixtureDatabase(TestNode fixture)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(fixture.DataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static string FixtureSandboxOwner(StoreReader reader, Id sandbox) => Assert.IsType<string>(
        reader.Scalar("SELECT owner_id FROM sandbox WHERE sandbox_id=$id;", ("$id", Hex(sandbox))));

    private static string FixtureStage(TestNode fixture, Id id) => Path.Combine(fixture.DataRoot, "control", "sandbox-transfers", Hex(id));

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
}
