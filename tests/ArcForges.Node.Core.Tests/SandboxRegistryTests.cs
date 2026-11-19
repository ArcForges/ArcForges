// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed partial class SandboxRegistryTests
{
    private const string StageVariable = "ARCFORGES_SANDBOX_TEST_MXC_STAGE";

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void CreateRenameAndReplaySurviveAStoreAndManagerRestart()
    {
        var stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        Id id;
        Id ownerEpoch;
        string nodeEpoch;
        string root;
        string identity;
        var config = DefaultConfig();
        config.Environment.Add(new EnvironmentEntry { Name = "SANDBOX_TEST_INPUT", Value = "fixture-only-value" });
        var create = new SandboxServiceCreateRequest { Meta = Command(), DisplayName = "original", Config = config };

        using (var store = fixture.Open())
        using (var manager = fixture.Manager(store, stage))
        {
            var hello = Handshake(manager, ct);
            ownerEpoch = hello.OwnerEpoch;
            nodeEpoch = hello.NodeEpoch;
            create.OwnerEpoch = ownerEpoch;
            var created = Created(manager, create, ct);
            id = created.SandboxId;
            root = created.DataLocation;
            Assert.Equal(SandboxState.Ready, created.State);
            Assert.Equal(1, created.Revision.Value);
            Assert.Equal(config, created.Config);
            Assert.Equal(Path.Combine(fixture.DataRoot, SandboxPrivateRoots.RelativePath(Hex(id))), root);
            identity = RootIdentity(store, id);

            var data = Path.Combine(root, "data", "sentinel.txt");
            File.WriteAllText(data, "persistent owner data");
            var renamed = manager.Configure(new SandboxServiceConfigureRequest
            {
                Meta = Command(1),
                OwnerEpoch = ownerEpoch,
                SandboxId = id,
                Config = config,
                DisplayName = "renamed",
            }, ct);
            Assert.Null(renamed.Error);
            Assert.Equal(2, renamed.Value.Sandbox.Revision.Value);
            Assert.Equal(root, renamed.Value.Sandbox.DataLocation);
            Assert.Equal(identity, RootIdentity(store, id));
            Assert.Equal("persistent owner data", File.ReadAllText(data));
            Assert.Equal(2L, Count(store, "SELECT count(*) FROM sandbox_config;"));

            var retained = ReceiptBody(store, create.Meta.CommandId);
            Assert.DoesNotContain("SANDBOX_TEST_INPUT", retained, StringComparison.Ordinal);
            Assert.DoesNotContain("fixture-only-value", retained, StringComparison.Ordinal);
            Assert.DoesNotContain("dataLocation", retained, StringComparison.Ordinal);
        }

        using (var store = fixture.Open())
        using (var manager = fixture.Manager(store, stage))
        {
            var hello = Handshake(manager, ct);
            Assert.Equal(ownerEpoch, hello.OwnerEpoch);
            Assert.NotEqual(nodeEpoch, hello.NodeEpoch);

            create.Meta.CorrelationId = NewId();
            var replay = manager.Create(create, ct);
            Assert.Null(replay.Error);
            Assert.Equal(create.Meta.CorrelationId, replay.Meta.CorrelationId);
            Assert.Equal(id, replay.Value.Sandbox.SandboxId);
            Assert.Equal("original", replay.Value.Sandbox.DisplayName);
            Assert.Equal(1, replay.Value.Sandbox.Revision.Value);
            Assert.Equal(config, replay.Value.Sandbox.Config);

            var current = manager.Inspect(new SandboxServiceInspectRequest { Meta = Query(), SandboxId = id }, ct);
            Assert.Null(current.Error);
            Assert.Equal("renamed", current.Value.Sandbox.DisplayName);
            Assert.Equal(2, current.Value.Sandbox.Revision.Value);
            Assert.Equal(root, current.Value.Sandbox.DataLocation);
            Assert.Equal(identity, RootIdentity(store, id));
            Assert.Equal("persistent owner data", File.ReadAllText(Path.Combine(root, "data", "sentinel.txt")));

            var receipt = manager.GetOperation(new NodeServiceGetOperationRequest
            {
                Meta = Query(),
                CommandId = create.Meta.CommandId,
                OwnerEpoch = ownerEpoch,
            }, ct);
            Assert.Null(receipt.Error);
            Assert.Equal(OperationState.Succeeded, receipt.Value.Operation.State);
            Assert.Equal(EffectCertainty.Happened, receipt.Value.Operation.Effect);
            Assert.Equal(id, receipt.Value.Operation.AggregateId);
            Assert.Equal(1, receipt.Value.Operation.Revision.Value);
            Assert.Equal(1L, Count(store, "SELECT count(*) FROM sandbox;"));
        }
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void OwnerNamesReceiptsAndCursorsAreScopedToTheCurrentAuthority()
    {
        var stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        using var owner = fixture.Manager(store, stage);
        using var other = fixture.Manager(store, stage, owner.OwnerId + ":separate-test-owner");
        var epoch = Handshake(owner, ct).OwnerEpoch;
        var foreignEpoch = Handshake(other, ct).OwnerEpoch;
        var request = CreateRequest(epoch, "Café");
        var first = Created(owner, request, ct);
        var second = Created(owner, CreateRequest(epoch, "another"), ct);

        // NFC-equivalent, case-insensitive names are unique only within the owning authority.
        var duplicate = owner.Create(CreateRequest(epoch, "CAFE\u0301"), ct);
        Assert.Equal(ErrorCategory.Conflict, duplicate.Error.Category);
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM sandbox;"));

        var sameCommand = request.Clone();
        sameCommand.DisplayName = "changed intent";
        Assert.Equal("command_id_reused", owner.Create(sameCommand, ct).Error.Code);
        var wrongEpoch = CreateRequest(foreignEpoch, "stale authority");
        Assert.Equal("owner_epoch_retired", owner.Create(wrongEpoch, ct).Error.Code);

        var page = owner.List(new SandboxServiceListRequest { Meta = Query(), Limit = 1 }, ct);
        Assert.Null(page.Error);
        var listed = Assert.Single(page.Value.Sandboxes);
        Assert.NotEmpty(page.Value.Page.NextCursor);
        var next = new SandboxServiceListRequest { Meta = Query(), Limit = 1, Cursor = page.Value.Page.NextCursor };
        var remaining = owner.List(next, ct);
        Assert.Null(remaining.Error);
        var otherOnPage = Assert.Single(remaining.Value.Sandboxes);
        Assert.NotEqual(listed.SandboxId, otherOnPage.SandboxId);
        Assert.Contains(listed.SandboxId, new[] { first.SandboxId, second.SandboxId });
        Assert.Contains(otherOnPage.SandboxId, new[] { first.SandboxId, second.SandboxId });
        Assert.Empty(remaining.Value.Page.NextCursor);

        Assert.Equal("invalid_cursor", other.List(next, ct).Error.Code);
        Assert.Equal("not_found", other.Inspect(new SandboxServiceInspectRequest
        {
            Meta = Query(),
            SandboxId = first.SandboxId,
        }, ct).Error.Code);
        Assert.Equal("not_found", other.GetOperation(new NodeServiceGetOperationRequest
        {
            Meta = Query(),
            CommandId = request.Meta.CommandId,
            OwnerEpoch = epoch,
        }, ct).Error.Code);
        Assert.Empty(other.List(new SandboxServiceListRequest { Meta = Query() }, ct).Value.Sandboxes);
        var separate = Created(other, CreateRequest(foreignEpoch, "Café"), ct);
        Assert.NotEqual(first.SandboxId, separate.SandboxId);

        _ = Created(owner, CreateRequest(epoch, "third"), ct);
        Assert.Equal("invalid_cursor", owner.List(next, ct).Error.Code);
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task ConcurrentConfigureUsesCasAndManagedUseBlocksPolicyChanges()
    {
        var stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        using var manager = fixture.Manager(store, stage);
        var epoch = Handshake(manager, ct).OwnerEpoch;
        var created = Created(manager, CreateRequest(epoch, "build"), ct);
        var proposalA = ConfigureRequest(created, epoch, "alpha");
        var proposalB = ConfigureRequest(created, epoch, "beta");

        // Both independently generated commands present the same previously read revision.
        var results = await Task.WhenAll(
            Task.Run(() => manager.Configure(proposalA, ct), ct),
            Task.Run(() => manager.Configure(proposalB, ct), ct));
        var won = Assert.Single(results, result => result.Value is not null).Value.Sandbox;
        var lost = Assert.Single(results, result => result.Error is not null).Error;
        Assert.Equal(2, won.Revision.Value);
        Assert.Equal("revision_mismatch", lost.Code);
        Assert.Equal(2, lost.Details.Revision.Actual.Value);
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM sandbox_config;"));
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM command_receipt;"));

        var run = NewId();
        SeedRecoveryRequiredRun(store, won, run);
        var changed = ConfigureRequest(won, epoch, "policy edit");
        changed.Config.Environment.Add(new EnvironmentEntry { Name = "BUILD_VARIANT", Value = "alternate" });
        var denied = manager.Configure(changed, ct);
        Assert.Equal("managed_use", denied.Error.Code);
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM sandbox_config;"));
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM command_receipt;"));

        var renamed = manager.Configure(ConfigureRequest(won, epoch, "same policy"), ct);
        Assert.Null(renamed.Error);
        Assert.Equal(3, renamed.Value.Sandbox.Revision.Value);
        Assert.Equal(won.DataLocation, renamed.Value.Sandbox.DataLocation);
        Assert.Equal(won.Config, renamed.Value.Sandbox.Config);
        var inspect = manager.Inspect(new SandboxServiceInspectRequest { Meta = Query(), SandboxId = won.SandboxId }, ct);
        Assert.Null(inspect.Error);
        Assert.Equal(run, Assert.Single(inspect.Value.Sandbox.ActiveRunIds));
        Assert.Equal(3L, Count(store, "SELECT count(*) FROM sandbox_config;"));
        Assert.Equal(3L, Count(store, "SELECT count(*) FROM command_receipt WHERE state='SUCCEEDED';"));
    }

    [Theory(Timeout = 60_000)]
    [InlineData(false, "managed_use")]
    [InlineData(true, "busy")]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task ConfigureCannotPassACompetingOwnershipTransition(bool deleting, string expectedError)
    {
        var stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        using var manager = fixture.Manager(store, stage);
        var epoch = Handshake(manager, ct).OwnerEpoch;
        var created = Created(manager, CreateRequest(epoch, "owned transition"), ct);
        var proposal = ConfigureRequest(created, epoch, "would be renamed");
        proposal.Config.Environment.Add(new EnvironmentEntry { Name = "BUILD_VARIANT", Value = "next" });

        using var requestArrived = new ManualResetEventSlim();
        Task<SandboxServiceConfigureResponse> configure;
        lock (manager.OwnershipGate)
        {
            configure = Task.Run(() =>
            {
                requestArrived.Set();
                return manager.Configure(proposal, ct);
            }, ct);
            Assert.True(requestArrived.Wait(TimeSpan.FromSeconds(10), ct));
            Assert.False(configure.IsCompleted);

            // The subsequent Start/Delete tasks own the native effects. Exercise their shared
            // serialization point with the real corresponding store transitions.
            if (deleting)
            {
                store.Write(tx => tx.Execute("UPDATE sandbox SET state=3 WHERE sandbox_id=$id AND revision=1;",
                    ("$id", Hex(created.SandboxId))), CommitDurability.Full);
            }
            else
            {
                SeedRecoveryRequiredRun(store, created, NewId());
            }
        }

        var result = await configure;
        Assert.Equal(expectedError, result.Error.Code);
        Assert.Null(result.Value);
        Assert.Equal(1L, Count(store, "SELECT count(*) FROM sandbox_config;"));
        Assert.Equal(1L, Count(store, "SELECT count(*) FROM command_receipt;"));
        Assert.Equal(1L, Count(store, "SELECT revision FROM sandbox;"));
        var current = manager.Inspect(new SandboxServiceInspectRequest
        {
            Meta = Query(),
            SandboxId = created.SandboxId,
        }, ct);
        Assert.Null(current.Error);
        Assert.Equal("owned transition", current.Value.Sandbox.DisplayName);
        Assert.Equal(created.Config, current.Value.Sandbox.Config);
        Assert.Equal(deleting ? SandboxState.Deleting : SandboxState.Ready, current.Value.Sandbox.State);
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void RealProfilesRetainExactSelectedEgressAndRejectAnUnknownPolicyBeforeReservation()
    {
        var stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        using var manager = fixture.Manager(store, stage);
        var epoch = Handshake(manager, ct).OwnerEpoch;

        var request = CreateRequest(epoch, "selected egress");
        request.Config.Network.AllowedDestinations.Add("tcp://192.0.2.1:443");
        var created = Created(manager, request, ct);
        Assert.Equal(request.Config, created.Config);
        var observation = Assert.Single(created.Capabilities, capability => capability.Key == "mxc.network.observation");
        Assert.Equal(OperatingSystem.IsWindows() ? CapabilityState.Unverified : CapabilityState.Available, observation.State);
        Assert.Equal(!OperatingSystem.IsWindows(), observation.HasEvidenceId);

        var unknown = CreateRequest(epoch, "unknown effect");
        unknown.Config = AddUnknownField(unknown.Config);
        var refused = manager.Create(unknown, ct);
        Assert.NotNull(refused.Error);
        Assert.Null(refused.Value);
        Assert.Equal(1L, Count(store, "SELECT count(*) FROM sandbox;"));
        Assert.Equal(1L, Count(store, "SELECT count(*) FROM command_receipt;"));
        Assert.Single(Directory.EnumerateDirectories(Path.Combine(fixture.DataRoot, "sandboxes")));
    }

    [Fact]
    public void NativeControlAndDurableAuthorityCanOpenOnTheSameDataRoot()
    {
        AssertNativePlatform();
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        new SandboxPrivateRoots(fixture.DataRoot).PrepareControlPaths();
        var owner = SandboxLocalOwner.Current() ?? throw new InvalidOperationException("The test principal is unavailable.");
        using var durable = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(fixture.DataRoot));
        Assert.False(durable.MaintenanceRequired);
        Assert.Equal(16, durable.OwnerEpoch.Length);
        var capabilities = SandboxPolicyAdmission.HandshakeCapabilities(fixture.DataRoot,
            Path.Combine(fixture.Root, "absent-mxc-installation"));
        Assert.Contains(capabilities, capability => capability.Key == "mxc.profile");
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void MissingInstallationRefusesAValidRequestBeforeReservation()
    {
        AssertNativePlatform();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        using var manager = fixture.Manager(store, Path.Combine(fixture.Root, "absent-mxc-installation"));
        var epoch = Handshake(manager, ct).OwnerEpoch;

        var refused = manager.Create(CreateRequest(epoch, "missing qualification"), ct);

        Assert.Equal("unsupported_combination", refused.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, refused.Error.Effect);
        Assert.Equal(0L, Count(store, "SELECT count(*) FROM sandbox;"));
        Assert.Equal(0L, Count(store, "SELECT count(*) FROM command_receipt;"));
        var sandboxes = Path.Combine(fixture.DataRoot, "sandboxes");
        Assert.Empty(Directory.Exists(sandboxes) ? Directory.EnumerateDirectories(sandboxes) : []);
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void CompactedReplyKeepsOriginalEffectAndAggregateAndNeverCreatesAnotherRoot()
    {
        var stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        var clock = new RegistryClock();
        using var fixture = new RegistryFixture();
        using var store = fixture.Open(clock);
        SandboxServiceCreateRequest command;
        Sandbox created;
        string owner;
        using (var manager = fixture.Manager(store, stage, clock: clock))
        {
            owner = manager.OwnerId;
            command = CreateRequest(Handshake(manager, ct).OwnerEpoch, "compact me");
            created = Created(manager, command, ct);
        }

        clock.Advance(TimeSpan.FromHours(25));
        using (var durable = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(fixture.DataRoot)))
        {
            Assert.Equal(1, durable.CompactKnownResponses());
        }

        using var resumed = fixture.Manager(store, stage, owner, clock);
        command.Meta.CorrelationId = NewId();
        var replay = resumed.Create(command, ct);
        Assert.Equal("receipt_compacted", replay.Error.Code);
        Assert.Equal(EffectCertainty.Happened, replay.Error.Effect);
        Assert.Equal(RetryMode.Never, replay.Error.Retry.Mode);
        Assert.EndsWith("GetOperation", replay.Error.Retry.ReconciliationOperation, StringComparison.Ordinal);
        Assert.Equal("SUCCEEDED", replay.Error.Details.State.State);
        Assert.Equal(created.SandboxId, replay.Error.Details.State.Resource.Id);
        var operation = resumed.GetOperation(new NodeServiceGetOperationRequest
        {
            Meta = Query(),
            CommandId = command.Meta.CommandId,
            OwnerEpoch = command.OwnerEpoch,
        }, ct);
        Assert.Null(operation.Error);
        Assert.True(operation.Value.Operation.ResponseCompacted);
        Assert.Equal(created.SandboxId, operation.Value.Operation.AggregateId);
        Assert.Equal(EffectCertainty.Happened, operation.Value.Operation.Effect);
        Assert.Equal(1L, Count(store, "SELECT count(*) FROM command_receipt;"));
        Assert.Single(Directory.EnumerateDirectories(Path.Combine(fixture.DataRoot, "sandboxes")));
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void GetOperationReturnsTheAcceptedReservationAfterAnInterruptedCreate()
    {
        AssertNativePlatform();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        var absentStage = Path.Combine(fixture.Root, "absent-mxc-installation");
        var id = NewId();
        string owner;
        SandboxServiceCreateRequest create;
        using (var store = fixture.Open())
        {
            using (var manager = fixture.Manager(store, absentStage))
            {
                owner = manager.OwnerId;
                create = CreateRequest(Handshake(manager, ct).OwnerEpoch, "interrupted create");
            }

            // Persist only the initial atomic transaction. No filesystem effect or outcome commit occurred.
            using var durable = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(fixture.DataRoot));
            string json = JsonFormatter.Default.Format(create.Config);
            string hash = Convert.ToHexStringLower(
                System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(json)));
            var now = DateTimeOffset.UtcNow;
            var row = new StoredSandbox(Hex(id), owner, create.DisplayName, create.DisplayName.ToUpperInvariant(), 1,
                StoredSandboxState.Creating, SandboxPrivateRoots.RelativePath(Hex(id)), SandboxRecords.PendingRootIdentity,
                1, now, now, new StoredSandboxConfig(create.Config.ProfileId, create.Config.ProfileVersion, json, hash));
            var canonical = create.Clone();
            canonical.Meta = null;
            canonical.OwnerEpoch = null;
            var admitted = durable.Admit(new DurableIntent(create.Meta.CommandId.Value.ToByteArray(),
                    create.OwnerEpoch.Value.ToByteArray(), "SandboxService.Create", "sandbox", Hex(id),
                    canonical.ToByteArray()),
                transaction => SandboxRecords.Reserve(transaction, row));
            Assert.Equal(DurableDecision.Execute, admitted.Decision);
        }

        using var reopened = fixture.Open();
        using var resumed = fixture.Manager(reopened, absentStage, owner);
        var operation = resumed.GetOperation(new NodeServiceGetOperationRequest
        {
            Meta = Query(),
            CommandId = create.Meta.CommandId,
            OwnerEpoch = create.OwnerEpoch,
        }, ct);
        Assert.Null(operation.Error);
        Assert.Equal(OperationState.Accepted, operation.Value.Operation.State);
        Assert.Equal(EffectCertainty.Unknown, operation.Value.Operation.Effect);
        Assert.Equal(id, operation.Value.Operation.AggregateId);
        Assert.NotNull(operation.Value.Operation.UpdatedAt);
        Assert.False(Directory.Exists(Path.Combine(fixture.DataRoot, SandboxPrivateRoots.RelativePath(Hex(id)))));
        Assert.Equal(1L, Count(reopened, "SELECT count(*) FROM command_receipt WHERE state='ACCEPTED';"));
        Assert.Equal(1L, Count(reopened, "SELECT count(*) FROM sandbox WHERE state=1 AND root_identity='pending';"));
    }

    [Fact(Timeout = 60_000)]
    public async Task LocalV2CreateWithoutARemoteTemplateReachesTheSandboxAdmissionPath()
    {
        AssertNativePlatform();
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        CreateOwnerOnlyDataRoot(fixture.DataRoot);
        await fixture.StartAsync();
        await using var channel = NodeChannel.Create(fixture.Endpoint);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        var reply = await node.HandshakeAsync(new NodeServiceHandshakeRequest { Meta = Query() }, cancellationToken: ct);
        Assert.Null(reply.Error);
        var epoch = reply.Value.OwnerEpoch;
        try
        {
            var request = CreateRequest(epoch, "local contract shape");
            // This sentinel profile cannot match either official profile. Still use the normal authenticated endpoint.
            request.Config.ProfileId = "unsupported-fixture-profile";
            Assert.Null(request.TemplateRevision);
            Assert.Null(request.ProvisionGrantId);
            var refused = await sandboxes.CreateAsync(request, cancellationToken: ct);
            Assert.Equal("unsupported_combination", refused.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, refused.Error.Effect);
            var list = await sandboxes.ListAsync(new SandboxServiceListRequest { Meta = Query() }, cancellationToken: ct);
            Assert.Null(list.Error);
            Assert.Empty(list.Value.Sandboxes);
        }
        finally
        {
            RemoveLocalOwnerKey(fixture, epoch);
        }
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task LocalV2CreatesAndInspectsAnOwnedSandboxWithTheRealQualifiedStage()
    {
        var stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        fixture.SandboxMxcInstallationRoot = stage;
        CreateOwnerOnlyDataRoot(fixture.DataRoot);
        await fixture.StartAsync();
        await using var channel = NodeChannel.Create(fixture.Endpoint);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        var hello = await node.HandshakeAsync(new NodeServiceHandshakeRequest { Meta = Query() }, cancellationToken: ct);
        Assert.Null(hello.Error);
        var epoch = hello.Value.OwnerEpoch;
        try
        {
            var request = CreateRequest(epoch, "local owned Sandbox");
            var created = await sandboxes.CreateAsync(request, cancellationToken: ct);
            Assert.True(created.Value is not null, created.Error?.ToString());
            Assert.Equal(request.Meta.CorrelationId, created.Meta.CorrelationId);
            Assert.Equal(1, created.Meta.ResultRev.Value);
            var owned = created.Value!.Sandbox;
            Assert.Equal(SandboxState.Ready, owned.State);
            Assert.Equal(request.Config, owned.Config);
            var data = Path.Combine(owned.DataLocation, "data", "owned.bin");
            File.WriteAllText(data, "local RPC fixture");

            var inspected = await sandboxes.InspectAsync(new SandboxServiceInspectRequest
            {
                SandboxId = owned.SandboxId,
                Meta = Query(),
            }, cancellationToken: ct);
            Assert.Null(inspected.Error);
            Assert.Equal(owned.SandboxId, inspected.Value.Sandbox.SandboxId);
            Assert.Equal(owned.DataLocation, inspected.Value.Sandbox.DataLocation);
            Assert.Equal("local RPC fixture", File.ReadAllText(data));
        }
        finally
        {
            RemoveLocalOwnerKey(fixture, epoch);
        }
    }

    private static void RemoveLocalOwnerKey(InProcessNode fixture, Id epoch)
    {
        string testKey = NodeDataKeyRing.TargetName(fixture.Runtime.Store.Metadata.NodeId.Span, "v2-owner-" + Hex(epoch));
        Assert.True(fixture.Secrets.Delete(testKey));
    }

    private static SandboxConfig DefaultConfig()
    {
        bool windows = OperatingSystem.IsWindows();
        return new()
        {
            ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
            ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
            Network = new NetworkPolicy { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
            Resources = new ResourcePolicy { PressureAction = PressureAction.Throttle },
        };
    }

    private static SandboxServiceCreateRequest CreateRequest(Id epoch, string name) =>
        new() { Meta = Command(), OwnerEpoch = epoch, DisplayName = name, Config = DefaultConfig() };

    private static SandboxServiceConfigureRequest ConfigureRequest(Sandbox sandbox, Id epoch, string name) =>
        new()
        {
            Meta = Command(sandbox.Revision.Value),
            OwnerEpoch = epoch,
            SandboxId = sandbox.SandboxId,
            Config = sandbox.Config.Clone(),
            DisplayName = name,
        };

    private static Sandbox Created(SandboxManager manager, SandboxServiceCreateRequest request, CancellationToken ct)
    {
        var response = manager.Create(request, ct);
        Assert.True(response.Value is not null, response.Error?.ToString());
        return response.Value!.Sandbox;
    }

    private static NodeServiceHandshakeValue Handshake(SandboxManager manager, CancellationToken ct)
    {
        var response = manager.Handshake(new NodeServiceHandshakeRequest { Meta = Query() }, ct);
        Assert.True(response.Value is not null, response.Error?.ToString());
        return response.Value!;
    }

    private static RequestMeta Query() => new() { CorrelationId = NewId() };

    private static RequestMeta Command(long? expected = null)
    {
        var meta = Query();
        meta.CommandId = NewId();
        if (expected.HasValue)
        {
            meta.ExpectedRev = new Revision { Value = expected.Value };
        }
        return meta;
    }

    private static Id NewId() => new() { Value = ByteString.CopyFrom(Guid.NewGuid().ToByteArray()) };

    private static string Hex(Id id) => Convert.ToHexStringLower(id.Value.Span);

    private static long Count(NodeStore store, string sql) => store.Read(reader => (long)reader.Scalar(sql)!);

    private static string RootIdentity(NodeStore store, Id id) => store.Read(reader =>
        (string)reader.Scalar("SELECT root_identity FROM sandbox WHERE sandbox_id=$id;", ("$id", Hex(id)))!);

    private static string ReceiptBody(NodeStore store, Id command) => store.Read(reader =>
        (string)reader.Scalar("SELECT response_json FROM command_receipt WHERE command_id=$id;", ("$id", Hex(command)))!);

    private static void SeedRecoveryRequiredRun(NodeStore store, Sandbox sandbox, Id run)
    {
        // CORE-02 owns starting processes. Seed a durable unresolved Run to exercise CORE-01's real managed-use query.
        store.Write(tx => tx.Execute("""
            INSERT INTO run(run_id,sandbox_id,sandbox_revision,revision,state,epoch,launch_sha256,snapshot_json,
                payload_started,created_utc,effect_certainty)
            VALUES($run,$sandbox,$revision,1,7,'sandbox-registry-test',$digest,'{}',1,$now,3);
            """, ("$run", Hex(run)), ("$sandbox", Hex(sandbox.SandboxId)), ("$revision", sandbox.Revision.Value),
            ("$digest", new string('0', 64)), ("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture))),
            CommitDurability.Full);
    }

    private static SandboxConfig AddUnknownField(SandboxConfig source)
    {
        using var buffer = new MemoryStream();
        source.WriteTo(buffer);
        using (var output = new CodedOutputStream(buffer, leaveOpen: true))
        {
            output.WriteTag(123, WireFormat.WireType.Varint);
            output.WriteUInt32(1);
        }
        return SandboxConfig.Parser.ParseFrom(buffer.ToArray());
    }

    private static void AssertNativePlatform() =>
        Assert.SkipUnless(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), "Sandbox profiles require native Windows or Linux.");

    private static string QualifiedStage()
    {
        AssertNativePlatform();
        string? path = Environment.GetEnvironmentVariable(StageVariable);
        Assert.SkipWhen(string.IsNullOrWhiteSpace(path), "Provide an exact authorized MXC-04 installation using " + StageVariable + ".");
        Assert.True(Path.IsPathFullyQualified(path!), StageVariable + " must name an absolute stage directory.");
        Assert.True(File.Exists(Path.Combine(path!, "mxc-manifest.json")), StageVariable + " must name a real MXC-04 stage.");
        return path!;
    }

    private static void CreateOwnerOnlyDataRoot(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            using var principal = WindowsIdentity.GetCurrent();
            var owner = principal.User ?? throw new InvalidOperationException("The test principal has no user SID.");
            var access = new DirectorySecurity();
            access.SetOwner(owner);
            access.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            access.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(path).Create(access);
        }
        else if (OperatingSystem.IsLinux())
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private sealed class RegistryClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan duration) => _now += duration;
    }

    private sealed class RegistryFixture : IDisposable
    {
        public RegistryFixture()
        {
            Root = Directory.CreateTempSubdirectory("arcforges-sandbox-registry-").FullName;
            DataRoot = Path.Combine(Root, "node-data");
            CreateOwnerOnlyDataRoot(DataRoot);
        }

        public string Root { get; }
        public string DataRoot { get; }

        public NodeStore Open(TimeProvider? clock = null) => NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = DataRoot,
            BootIdentity = "sandbox-registry-native-fixture",
            Clock = clock ?? TimeProvider.System,
        });

        public SandboxManager Manager(NodeStore store, string stage, string? owner = null, TimeProvider? clock = null) =>
            new(store, DataRoot, owner ?? SandboxLocalOwner.Current()
                ?? throw new InvalidOperationException("The test principal is unavailable."),
                NodeSecretStores.ForTestDataRoot(DataRoot), clock ?? TimeProvider.System, mxcInstallationRoot: stage);

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
