// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using static ArcForges.ClosedLoop.Tests.CloudLinkCenterControlTests;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "cloud")]
public sealed class RemoteStreamCenterExpiryTests
{
    private const string DataServiceName = "/arcforges.sandbox.v2.DataService/";
    private const string SourceName = "natural-expiry.bin";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 3_900_000, DisableParallelization = true)]
    public async Task InstalledRemoteExportNaturallyExpiresAndReleasesItsSnapshot()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(Environment.GetEnvironmentVariable("ARCFORGES_CENTER04_EXPIRY_REQUIRED") == "1",
            "Run the separate actual one-hour expiry scenario with the installed Node and real Go Center.");
        var (origin, directory) = RequireNativeFixture();
        await using var fixture = TestNode.Create();
        ConfigureNativeFixture(fixture, origin);
        var process = await fixture.StartNodeAsync();
        await using var local = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(local.CallInvoker);
        var control = new CenterControlService.CenterControlServiceClient(local.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(local.CallInvoker);
        var hello = await node.HandshakeAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: Ct);
        var identity = Value(hello.Value, hello.Error);
        var epoch = Assert.IsType<Id>(identity.OwnerEpoch);
        await using var cleanup = new OwnedNodeCleanup(fixture, process, control, epoch);

        var connected = await control.BeginConnectAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            CenterOrigin = origin,
            ServiceMode = "self_hosted",
            FlowKind = "browser",
        }, deadline: Deadline, cancellationToken: Ct);
        var flow = Assert.IsType<Id>(Value(connected.Value, connected.Error).FlowId);
        var approval = await WaitForFlowAsync(control, flow, observed => observed.State == "pending" && observed.HasVerificationUri);
        await WriteObservationAsync(directory, "approval.json", new { verificationUri = approval.VerificationUri });
        await WaitForFlowAsync(control, flow, observed => observed.State == "succeeded");
        var online = await WaitForStatusAsync(control, status => status.ChannelState == "online");
        var enrollment = Assert.IsType<Id>(online.EnrollmentId);
        await WriteObservationAsync(directory, "connected.json", new { ownerEpoch = Hex(epoch), nodeEpoch = identity.NodeEpoch });
        await WaitForFixtureAsync(directory, "connected-confirmed", NativeBound, "the exact authenticated Center peer");

        var sandbox = await CreateExpirySandboxAsync(sandboxes, epoch);
        var source = Path.Combine(sandbox.DataLocation, "data", SourceName);
        var originalBytes = "ArcForges natural export expiry fixture\n"u8.ToArray();
        var originalDigest = Convert.ToHexStringLower(SHA256.HashData(originalBytes));
        await File.WriteAllBytesAsync(source, originalBytes, Ct);
        var originalWriteTime = File.GetLastWriteTimeUtc(source);
        var granted = await node.SetRemoteGrantAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            Grant = new()
            {
                GrantId = CommandIds.New(),
                EnrollmentId = enrollment,
                ScopeKind = "sandbox",
                SandboxId = sandbox.SandboxId,
                AllowData = true,
                Methods = { DataServiceName + "BeginExport", DataServiceName + "ReadExport", DataServiceName + "InspectTransfer" },
            },
        }, deadline: Deadline, cancellationToken: Ct);
        var grant = Value(granted.Value, granted.Error).Grant;
        Assert.Equal(GrantState.Active, grant.State);
        Assert.Null(grant.ExpiresAt);
        await WriteObservationAsync(directory, "file-scope.json", new
        {
            grant = Hex(grant.GrantId),
            revision = grant.Revision.Value,
            sandbox = Hex(sandbox.SandboxId),
            sandboxRevision = sandbox.Revision.Value,
            digest = originalDigest,
            bytes = originalBytes.Length,
        });

        await WaitForFixtureAsync(directory, "expiry-export.json", NativeBound, "the original verified remote export");
        using var marker = JsonDocument.Parse(await File.ReadAllBytesAsync(Path.Combine(directory, "expiry-export.json"), Ct));
        var observation = marker.RootElement;
        var transfer = Convert.FromHexString(observation.GetProperty("transfer").GetString()!);
        Assert.Equal(16, transfer.Length);
        Assert.Equal(originalDigest, observation.GetProperty("digest").GetString());
        Assert.Equal(originalBytes.Length, observation.GetProperty("bytes").GetInt32());

        string id = Convert.ToHexStringLower(transfer);
        var (ready, admittedAt) = ReadFixtureExport(fixture, sandbox.SandboxId, epoch, id, grant, enrollment);
        Assert.Equal(StoredTransferState.Complete, ready.State);
        Assert.Null(ready.ClosedAt);
        Assert.Null(ready.Manifest.Pending);
        Assert.Equal("data/" + SourceName, ready.Manifest.RelativePath);
        Assert.Equal(originalDigest, ready.ExpectedSha256);
        Assert.Equal((long)originalBytes.Length, ready.ByteLength);
        Assert.Equal(ready.ByteLength, ready.VerifiedOffset);
        Assert.InRange(ready.ExpiresAt - admittedAt, TimeSpan.FromHours(1) - TimeSpan.FromSeconds(2), TimeSpan.FromHours(1) + TimeSpan.FromSeconds(2));
        var stage = Path.Combine(fixture.DataRoot, "control", "sandbox-transfers", id);
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(stage, Ct));

        var remaining = ready.ExpiresAt - DateTimeOffset.UtcNow;
        Assert.InRange(remaining, TimeSpan.FromMinutes(58), TimeSpan.FromHours(1));
        var elapsed = Stopwatch.StartNew();
        await WaitForNaturalExpiryAsync(directory);
        Assert.True(elapsed.Elapsed >= remaining - TimeSpan.FromSeconds(2), "the native snapshot must survive its original wall-clock lease");

        var (closed, originalAdmission) = ReadFixtureExport(fixture, sandbox.SandboxId, epoch, id, grant, enrollment);
        Assert.Equal(admittedAt, originalAdmission);
        Assert.Equal(StoredTransferState.Complete, closed.State);
        Assert.Equal(StoredTransferCloseReason.Expiry, closed.CloseReason);
        Assert.InRange(Assert.IsType<DateTimeOffset>(closed.ClosedAt), ready.ExpiresAt, DateTimeOffset.UtcNow);
        Assert.True(closed.Manifest.Revision > ready.Manifest.Revision);
        Assert.Equal(ready with
        {
            OwnerEpoch = closed.OwnerEpoch,
            Manifest = ready.Manifest with { Revision = closed.Manifest.Revision },
            ClosedAt = closed.ClosedAt,
            CloseReason = closed.CloseReason,
        }, closed);
        Assert.False(File.Exists(stage));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(source, Ct));
        Assert.Equal(originalWriteTime, File.GetLastWriteTimeUtc(source));
    }

    private static async Task<Sandbox> CreateExpirySandboxAsync(SandboxService.SandboxServiceClient sandboxes, Id epoch)
    {
        bool windows = OperatingSystem.IsWindows();
        var opened = await sandboxes.CreateAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            DisplayName = "Natural remote export expiry fixture",
            Config = new()
            {
                ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
                ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
                Network = new() { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
                Resources = new() { CpuMaxMillicores = 500, MemoryMaxBytes = 256UL << 20, PressureAction = PressureAction.Throttle },
                OutputRetentionBytes = 4096,
            },
        }, deadline: Deadline, cancellationToken: Ct);
        return Value(opened.Value, opened.Error).Sandbox;
    }

    private static (StoredTransfer Transfer, DateTimeOffset AdmittedAt) ReadFixtureExport(TestNode fixture, Id sandbox,
        Id epoch, string id, RemoteGrant grant, Id enrollment)
    {
        using var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(fixture.DataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        database.Open();
        var reader = new StoreReader(database, transaction: null, clock: TimeProvider.System);
        string sandboxId = Hex(sandbox);
        string owner = Assert.IsType<string>(reader.Scalar("SELECT owner_id FROM sandbox WHERE sandbox_id=$id;", ("$id", sandboxId)));
        var row = Assert.IsType<StoredTransfer>(TransferRecords.Get(reader, owner, id));
        Assert.Equal(sandboxId, row.SandboxId);
        Assert.True(epoch.Value.Span.SequenceEqual(row.OwnerEpoch));
        Assert.Equal(StoredTransferDirection.Export, row.Direction);
        var current = Assert.IsType<StoredRemoteGrant>(RemoteGrantRecords.Get(reader, owner, Hex(grant.GrantId)));
        Assert.Equal(StoredRemoteGrantState.Active, current.State);
        Assert.Null(current.ExpiresAt);
        Assert.Equal(grant.Revision.Value, current.Revision);
        Assert.Equal(sandboxId, current.SandboxId);
        Assert.Equal(current.GrantId, row.Manifest.GrantId);
        Assert.Equal(current.Revision, row.Manifest.GrantRevision);
        Assert.Equal(Hex(enrollment), row.Manifest.EnrollmentId);
        Assert.NotEqual(owner, row.Manifest.ActorId);
        var created = Assert.IsType<string>(reader.Scalar("""
            SELECT created_utc FROM command_receipt
            WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$command AND aggregate_kind='transfer'
              AND aggregate_id=$transfer AND method=$method AND state='SUCCEEDED' AND effect_certainty=2;
            """, ("$owner", owner), ("$epoch", row.OwnerEpoch), ("$command", row.BeginCommandId), ("$transfer", id),
            ("$method", TransferRecords.BeginExportMethod)));
        return (row, DateTimeOffset.Parse(created, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind));
    }

    private static async Task WaitForNaturalExpiryAsync(string directory)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(62));
        string complete = Path.Combine(directory, "expiry-confirmed");
        string abort = Path.Combine(directory, "fixture-abort");
        while (!File.Exists(complete))
        {
            Assert.False(File.Exists(abort), "the real Go Center fixture requested teardown before observing natural expiry");
            await Task.Delay(TimeSpan.FromSeconds(1), timeout.Token);
        }
    }

    private static string Hex(Id id) => Convert.ToHexStringLower(id.Value.Span);
}
