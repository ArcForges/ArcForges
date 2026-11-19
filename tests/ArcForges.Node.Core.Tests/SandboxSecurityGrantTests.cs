// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class SandboxSecurityGrantTests
{
    private const string StageVariable = "ARCFORGES_SANDBOX_TEST_MXC_STAGE";
    private const string SecretReference = "v1:00000000000000000000000000000001:1";
    private const string SecretVariable = "AFV2_GRANT_FIXTURE_REFERENCE";

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task ProvisionDerivesBoundSandboxAndOwnerRevocationFencesNewAdmission()
    {
        string stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        await StartAsync(fixture, stage);
        await using var channel = NodeChannel.Create(fixture.Endpoint);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        var epoch = await OwnerEpochAsync(node, ct);
        try
        {
            var manager = fixture.Runtime.Sandboxes ?? throw new InvalidOperationException("Sandbox Core was not loaded.");
            var store = fixture.Runtime.Store;
            var enrollment = Enrollment(manager.OwnerId);
            var actor = Hex(NewId());
            var template = DefaultConfig();
            string mountPath = Directory.CreateDirectory(Path.Combine(fixture.Root, "template-mounted")).FullName;
            template.HostGrants.Add(new HostGrant { HostPath = mountPath, SandboxPath = mountPath, Writable = false });
            template.Environment.Add(new EnvironmentEntry { Name = SecretVariable, SecretRef = SecretReference });
            var set = ProvisionRequest(epoch, enrollment, template);
            var create = CreateRequest(epoch, set.Grant.GrantId, 1, template, "protected provision");
            var createCall = Verified(enrollment, actor, set.Grant.GrantId, 1, RemoteGrantAction.SandboxCreate, create);

            // A valid local owner connection without a logged-in Center can query grants, but no
            // enrollment alone can authorize a remote command or enable a grant.
            Assert.Empty((await node.ListRemoteGrantsAsync(new() { Meta = Query() }, cancellationToken: ct)).Value.Grants);
            Denied((await node.SetRemoteGrantAsync(set, cancellationToken: ct)).Error);
            manager.UpdateRemoteEnrollment(enrollment);
            Denied(manager.CreateFromCenter(create, createCall, ct).Error);
            var localRefusal = await sandboxes.CreateAsync(create, cancellationToken: ct);
            Assert.NotNull(localRefusal.Error);
            Assert.Equal(ErrorCategory.Validation, localRefusal.Error.Category);
            Assert.Equal("invalid_argument", localRefusal.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, localRefusal.Error.Effect);
            AssertNoReceipt(store, create.Meta.CommandId);
            Assert.Equal(0L, Count(store, "SELECT count(*) FROM sandbox;"));

            var setReply = await node.SetRemoteGrantAsync(set, cancellationToken: ct);
            Assert.True(setReply.Value is not null, setReply.Error?.ToString());
            var provision = setReply.Value!.Grant;
            Assert.Equal(set.Grant.GrantId, provision.GrantId);
            Assert.Equal(1, provision.TemplateRevision.Value);
            var setReplay = await node.SetRemoteGrantAsync(set, cancellationToken: ct);
            Assert.Null(setReplay.Error);
            Assert.Equal(provision, setReplay.Value.Grant);

            manager.UpdateRemoteEnrollment(null);
            var disconnectedReplay = await node.SetRemoteGrantAsync(set, cancellationToken: ct);
            Assert.Null(disconnectedReplay.Error);
            Assert.Equal(provision, disconnectedReplay.Value.Grant);
            var freshWhileDisconnected = set.Clone();
            freshWhileDisconnected.Meta.CommandId = NewId();
            Denied((await node.SetRemoteGrantAsync(freshWhileDisconnected, cancellationToken: ct)).Error);
            AssertNoReceipt(store, freshWhileDisconnected.Meta.CommandId);
            Assert.Equal(1L, Count(store, "SELECT count(*) FROM remote_grant;"));
            manager.UpdateRemoteEnrollment(enrollment);

            using (var saved = JsonDocument.Parse(Receipt(store, set.Meta.CommandId)))
            {
                var receiptGrant = RemoteGrant.Parser.ParseFrom(saved.RootElement.GetProperty("grant").GetBytesFromBase64());
                AssertPrivateTemplateRedacted(receiptGrant.CreationTemplate);
            }

            var list = new NodeServiceListRemoteGrantsRequest { Meta = Query() };
            var localList = await node.ListRemoteGrantsAsync(list, cancellationToken: ct);
            Assert.Null(localList.Error);
            var localTemplate = Assert.Single(localList.Value.Grants).CreationTemplate;
            Assert.Equal(mountPath, Assert.Single(localTemplate.HostGrants).HostPath);
            Assert.True(localTemplate.HostGrants[0].HasNativeIdentity);
            Assert.Equal(SecretReference, Assert.Single(localTemplate.Environment).SecretRef);

            var remoteList = manager.ListRemoteGrantsFromCenter(list,
                Verified(enrollment, actor, provision.GrantId, 1, RemoteGrantAction.ListRemoteGrants, list), ct);
            Assert.Null(remoteList.Error);
            AssertPrivateTemplateRedacted(Assert.Single(remoteList.Value.Grants).CreationTemplate);

            var created = manager.CreateFromCenter(create, createCall, ct);
            Assert.True(created.Value is not null, created.Error?.ToString());
            var sandbox = created.Value!.Sandbox;
            Assert.Equal(SandboxState.Ready, sandbox.State);
            Assert.False(sandbox.HasDataLocation);
            AssertPrivateTemplateRedacted(sandbox.Config);
            var replay = manager.CreateFromCenter(create, createCall, ct);
            Assert.Null(replay.Error);
            Assert.Equal(sandbox.SandboxId, replay.Value.Sandbox.SandboxId);
            Assert.False(replay.Value.Sandbox.HasDataLocation);
            Assert.Equal(1L, Count(store, "SELECT count(*) FROM sandbox;"));

            var inspect = new SandboxServiceInspectRequest { Meta = Query(), SandboxId = sandbox.SandboxId };
            var owned = (await sandboxes.InspectAsync(inspect, cancellationToken: ct)).Value.Sandbox;
            Assert.True(Directory.Exists(owned.DataLocation));
            Assert.Equal(mountPath, Assert.Single(owned.Config.HostGrants).HostPath);
            Assert.Equal(SecretReference, Assert.Single(owned.Config.Environment).SecretRef);

            var childList = await node.ListRemoteGrantsAsync(
                new() { Meta = Query(), SandboxId = sandbox.SandboxId }, cancellationToken: ct);
            Assert.Null(childList.Error);
            var child = Assert.Single(childList.Value.Grants);
            Assert.Equal(provision.GrantId, child.ParentGrantId);
            Assert.Equal(sandbox.SandboxId, child.SandboxId);
            Assert.Equal("sandbox", child.ScopeKind);
            Assert.False(RemoteGrantPolicy.IsAllowed(child, RemoteGrantAction.SandboxCreate));
            Assert.True(RemoteGrantPolicy.IsAllowed(child, RemoteGrantAction.SandboxConfigure));
            var storedChild = store.Read(reader => RemoteGrantRecords.Get(reader, manager.OwnerId, Hex(child.GrantId)));
            Assert.NotNull(storedChild);
            Assert.Equal(Hex(provision.GrantId), storedChild.ParentGrantId);
            Assert.Equal(1, storedChild.ParentGrantRevision);

            var config = owned.Config.Clone();
            config.HostGrants.Clear();
            config.Environment.Clear();
            config.Resources.MemoryMaxBytes /= 2;
            var configure = ConfigureRequest(epoch, sandbox.SandboxId, 1, config);
            var configured = manager.ConfigureFromCenter(configure,
                Verified(enrollment, actor, child.GrantId, 1, RemoteGrantAction.SandboxConfigure, configure), ct);
            Assert.True(configured.Value is not null, configured.Error?.ToString());
            Assert.Equal(2, configured.Value!.Sandbox.Revision.Value);
            Assert.False(configured.Value.Sandbox.HasDataLocation);

            var expand = ConfigureRequest(epoch, sandbox.SandboxId, 2, owned.Config);
            Denied(manager.ConfigureFromCenter(expand,
                Verified(enrollment, actor, child.GrantId, 1, RemoteGrantAction.SandboxConfigure, expand), ct).Error);
            AssertNoReceipt(store, expand.Meta.CommandId);
            var repair = ConfigureRequest(epoch, sandbox.SandboxId, 2, config);
            repair.RepairError = true;
            Denied(manager.ConfigureFromCenter(repair,
                Verified(enrollment, actor, child.GrantId, 1, RemoteGrantAction.SandboxConfigure, repair), ct).Error);
            AssertNoReceipt(store, repair.Meta.CommandId);

            var revoke = RevokeRequest(epoch, provision.GrantId, 1);
            var revoked = await node.RevokeRemoteGrantAsync(revoke, cancellationToken: ct);
            Assert.True(revoked.Value is not null, revoked.Error?.ToString());
            Assert.Equal(GrantState.Revoked, revoked.Value!.Grant.State);
            Assert.Equal(2, revoked.Value.Grant.Revision.Value);
            Assert.Equal(revoked.Value.Grant, (await node.RevokeRemoteGrantAsync(revoke, cancellationToken: ct)).Value.Grant);

            Denied(manager.CreateFromCenter(create, createCall, ct).Error);
            var afterRevoke = ConfigureRequest(epoch, sandbox.SandboxId, 2, config);
            Denied(manager.ConfigureFromCenter(afterRevoke,
                Verified(enrollment, actor, child.GrantId, 1, RemoteGrantAction.SandboxConfigure, afterRevoke), ct).Error);
            AssertNoReceipt(store, afterRevoke.Meta.CommandId);
            var settled = (await sandboxes.InspectAsync(inspect, cancellationToken: ct)).Value.Sandbox;
            Assert.Equal(owned.DataLocation, settled.DataLocation);
            Assert.Equal(2, settled.Revision.Value);
            Assert.Equal(config, settled.Config);
            Assert.Equal(2L, Count(store, "SELECT count(*) FROM remote_grant;"));

            var operation = await node.GetOperationAsync(new()
            {
                Meta = Query(),
                OwnerEpoch = epoch,
                CommandId = create.Meta.CommandId,
            }, cancellationToken: ct);
            Assert.Null(operation.Error);
            Assert.Equal(sandbox.SandboxId, operation.Value.Operation.AggregateId);
            Assert.Equal(EffectCertainty.Happened, operation.Value.Operation.Effect);
        }
        finally
        {
            RemoveOwnerKey(fixture, epoch);
        }
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task InvalidEnrollmentActionAndRevisionNeverCommitAndExactRemoteRevocationDoes()
    {
        string stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        await StartAsync(fixture, stage);
        await using var channel = NodeChannel.Create(fixture.Endpoint);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var epoch = await OwnerEpochAsync(node, ct);
        try
        {
            var manager = fixture.Runtime.Sandboxes ?? throw new InvalidOperationException("Sandbox Core was not loaded.");
            var store = fixture.Runtime.Store;
            var enrollment = Enrollment(manager.OwnerId);
            manager.UpdateRemoteEnrollment(enrollment);
            var actor = Hex(NewId());
            var template = DefaultConfig();
            var set = ProvisionRequest(epoch, enrollment, template);
            var localOnly = set.Clone();
            localOnly.Meta = Command();
            localOnly.Grant.Methods.Add("/arcforges.sandbox.v2.NodeService/SetRemoteGrant");
            Assert.Equal("invalid_argument", (await node.SetRemoteGrantAsync(localOnly, cancellationToken: ct)).Error.Code);
            AssertNoReceipt(store, localOnly.Meta.CommandId);
            var setReply = await node.SetRemoteGrantAsync(set, cancellationToken: ct);
            Assert.True(setReply.Value is not null, setReply.Error?.ToString());
            var provision = setReply.Value!.Grant;
            Assert.Equal(1, provision.Revision.Value);

            var create = CreateRequest(epoch, provision.GrantId, 1, template, "denied provision");
            var call = Verified(enrollment, actor, provision.GrantId, 1, RemoteGrantAction.SandboxCreate, create);
            var foreign = enrollment with { EnrollmentId = Hex(NewId()) };
            Denied(manager.CreateFromCenter(create, call with { Enrollment = foreign }, ct).Error);
            Denied(manager.CreateFromCenter(create, call with { Enrollment = enrollment with { Epoch = Hex(NewId()) } }, ct).Error);
            Denied(manager.CreateFromCenter(create, call with { Action = RemoteGrantAction.SandboxConfigure }, ct).Error);
            Denied(manager.CreateFromCenter(create, call with { Revision = 2 }, ct).Error);
            var past = TimeProvider.System.GetUtcNow().AddMinutes(-1);
            Denied(manager.CreateFromCenter(create, call with { IssuedAt = past.AddSeconds(-10), ExpiresAt = past }, ct).Error);
            var changedBody = create.Clone();
            changedBody.DisplayName = "different body";
            Denied(manager.CreateFromCenter(changedBody, call, ct).Error);
            var widened = create.Clone();
            widened.Config.Resources.ClearMemoryMaxBytes();
            Denied(manager.CreateFromCenter(widened,
                Verified(enrollment, actor, provision.GrantId, 1, RemoteGrantAction.SandboxCreate, widened), ct).Error);
            AssertNoReceipt(store, create.Meta.CommandId);
            Assert.Equal(0L, Count(store, "SELECT count(*) FROM sandbox;"));

            var update = set.Clone();
            update.Meta = Command(1);
            update.Grant.CreationTemplate.Resources.MemoryMaxBytes /= 2;
            var updated = await node.SetRemoteGrantAsync(update, cancellationToken: ct);
            Assert.True(updated.Value is not null, updated.Error?.ToString());
            Assert.Equal(2, updated.Value!.Grant.Revision.Value);
            Assert.Equal(2, updated.Value.Grant.TemplateRevision.Value);
            var staleUpdate = update.Clone();
            staleUpdate.Meta = Command(1);
            Assert.Equal("revision_mismatch", (await node.SetRemoteGrantAsync(staleUpdate, cancellationToken: ct)).Error.Code);
            AssertNoReceipt(store, staleUpdate.Meta.CommandId);

            Denied(manager.CreateFromCenter(create, call, ct).Error);
            Denied(manager.CreateFromCenter(create,
                Verified(enrollment, actor, provision.GrantId, 2, RemoteGrantAction.SandboxCreate, create), ct).Error);
            AssertNoReceipt(store, create.Meta.CommandId);
            var revoke = RevokeRequest(epoch, provision.GrantId, 2);
            var revokeCall = Verified(enrollment, actor, provision.GrantId, 2, RemoteGrantAction.RevokeRemoteGrant, revoke);
            Denied(manager.RevokeRemoteGrantFromCenter(revoke, revokeCall with { GrantId = Hex(NewId()) }, ct).Error);
            AssertNoReceipt(store, revoke.Meta.CommandId);
            var revoked = manager.RevokeRemoteGrantFromCenter(revoke, revokeCall, ct);
            Assert.True(revoked.Value is not null, revoked.Error?.ToString());
            Assert.Equal(GrantState.Revoked, revoked.Value!.Grant.State);
            Assert.Equal(3, revoked.Value.Grant.Revision.Value);
            Denied(manager.RevokeRemoteGrantFromCenter(revoke, revokeCall, ct).Error);
            var local = await node.ListRemoteGrantsAsync(new() { Meta = Query() }, cancellationToken: ct);
            Assert.Equal(revoked.Value.Grant.Revision, Assert.Single(local.Value.Grants).Revision);
            Assert.Equal(1L, Count(store, "SELECT count(*) FROM remote_grant;"));
            Assert.Equal(0L, Count(store, "SELECT count(*) FROM sandbox;"));
        }
        finally
        {
            RemoveOwnerKey(fixture, epoch);
        }
    }

    private static NodeServiceSetRemoteGrantRequest ProvisionRequest(Id epoch, ActiveRemoteEnrollment enrollment, SandboxConfig config)
    {
        var grant = new RemoteGrant
        {
            GrantId = NewId(),
            EnrollmentId = FromHex(enrollment.EnrollmentId),
            ScopeKind = "provision",
            CreationTemplate = config.Clone(),
        };
        grant.Methods.AddRange(["/arcforges.sandbox.v2.SandboxService/Create", "/arcforges.sandbox.v2.SandboxService/Configure",
            "/arcforges.sandbox.v2.NodeService/GetOperation", "/arcforges.sandbox.v2.NodeService/ListRemoteGrants",
            "/arcforges.sandbox.v2.NodeService/RevokeRemoteGrant"]);
        return new() { Meta = Command(), OwnerEpoch = epoch, Grant = grant };
    }

    private static SandboxServiceCreateRequest CreateRequest(Id epoch, Id grant, long templateRevision, SandboxConfig config, string name) =>
        new()
        {
            Meta = Command(),
            OwnerEpoch = epoch,
            ProvisionGrantId = grant,
            TemplateRevision = new() { Value = templateRevision },
            DisplayName = name,
            Config = config.Clone()
        };

    private static SandboxServiceConfigureRequest ConfigureRequest(Id epoch, Id sandbox, long revision, SandboxConfig config) =>
        new() { Meta = Command(revision), OwnerEpoch = epoch, SandboxId = sandbox, Config = config.Clone() };

    private static NodeServiceRevokeRemoteGrantRequest RevokeRequest(Id epoch, Id grant, long revision) =>
        new() { Meta = Command(revision), OwnerEpoch = epoch, GrantId = grant };

    private static SandboxConfig DefaultConfig()
    {
        bool windows = OperatingSystem.IsWindows();
        return new()
        {
            ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
            ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
            Network = new() { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
            Resources = new() { PressureAction = PressureAction.Throttle, MemoryMaxBytes = 64 * 1024 * 1024 },
        };
    }

    private static ActiveRemoteEnrollment Enrollment(string owner) =>
        new(owner, Hex(NewId()), Hex(NewId()), "https://grant-fixture.example.invalid", "https://grant-fixture.example.invalid", Hex(NewId()));

    // This is the typed Core boundary used after the Center adapter verifies a message. No Center
    // channel or claimed localhost session is involved in this fixture.
    private static VerifiedRemoteGrantCall Verified(ActiveRemoteEnrollment enrollment, string actor, Id grant,
        long revision, RemoteGrantAction action, IMessage request)
    {
        var now = TimeProvider.System.GetUtcNow();
        return new(enrollment, actor, Hex(grant), revision, action, now.AddSeconds(-1), now.AddMinutes(3),
            ByteString.CopyFrom(SHA256.HashData(request.ToByteArray())));
    }

    private static void AssertPrivateTemplateRedacted(SandboxConfig config)
    {
        Assert.Empty(config.HostGrants);
        Assert.Empty(config.Environment);
        Assert.False(config.HasDefaultWorkdir);
    }

    private static void Denied(ArcError error)
    {
        Assert.NotNull(error);
        Assert.True(error.Category == ErrorCategory.Authorization, error.ToString());
        Assert.Equal("permission_denied", error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
    }

    private static RequestMeta Query() => new() { CorrelationId = NewId() };

    private static RequestMeta Command(long? revision = null) =>
        new() { CorrelationId = NewId(), CommandId = NewId(), ExpectedRev = revision is long value ? new() { Value = value } : null };

    private static Id NewId() => new() { Value = ByteString.CopyFrom(Guid.NewGuid().ToByteArray()) };

    private static Id FromHex(string hex) => new() { Value = ByteString.CopyFrom(Convert.FromHexString(hex)) };

    private static string Hex(Id id) => Convert.ToHexStringLower(id.Value.Span);

    private static long Count(NodeStore store, string sql) => store.Read(reader => (long)reader.Scalar(sql)!);

    private static string Receipt(NodeStore store, Id command) => store.Read(reader =>
        (string)reader.Scalar("SELECT response_json FROM command_receipt WHERE command_id=$id;", ("$id", Hex(command)))!);

    private static void AssertNoReceipt(NodeStore store, Id command) =>
        Assert.Equal(0L, store.Read(reader => (long)reader.Scalar("SELECT count(*) FROM command_receipt WHERE command_id=$id;",
            ("$id", Hex(command)))!));

    private static async Task<Id> OwnerEpochAsync(NodeService.NodeServiceClient node, CancellationToken ct)
    {
        var handshake = await node.HandshakeAsync(new() { Meta = Query() }, cancellationToken: ct);
        Assert.True(handshake.Value is not null, handshake.Error?.ToString());
        return handshake.Value!.OwnerEpoch;
    }

    private static string QualifiedStage()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), "Sandbox profiles require native Windows or Linux.");
        string? stage = Environment.GetEnvironmentVariable(StageVariable);
        Assert.SkipWhen(string.IsNullOrWhiteSpace(stage), "Use the exact authorized MXC-04 installation via " + StageVariable + ".");
        Assert.True(Path.IsPathFullyQualified(stage!), StageVariable + " must name an absolute stage directory.");
        Assert.True(File.Exists(Path.Combine(stage!, "mxc-manifest.json")), StageVariable + " must name the native MXC-04 stage.");
        return stage!;
    }

    private static async Task StartAsync(InProcessNode fixture, string stage)
    {
        fixture.SandboxMxcInstallationRoot = stage;
        if (OperatingSystem.IsWindows())
        {
            using var principal = WindowsIdentity.GetCurrent();
            var owner = principal.User ?? throw new InvalidOperationException("The test principal has no user SID.");
            var access = new DirectorySecurity();
            access.SetOwner(owner);
            access.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            access.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(fixture.DataRoot).Create(access);
        }
        else if (OperatingSystem.IsLinux())
        {
            Directory.CreateDirectory(fixture.DataRoot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        await fixture.StartAsync();
    }

    private static void RemoveOwnerKey(InProcessNode fixture, Id epoch)
    {
        string testKey = NodeDataKeyRing.TargetName(fixture.Runtime.Store.Metadata.NodeId.Span, "v2-owner-" + Hex(epoch));
        Assert.True(fixture.Secrets.Delete(testKey));
    }
}
