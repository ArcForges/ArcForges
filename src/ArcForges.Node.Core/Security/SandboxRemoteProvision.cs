// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Shape = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private StoredRemoteGrant? AuthorizeRemoteCreation(SandboxServiceCreateRequest request, VerifiedRemoteGrantCall remote,
        DateTimeOffset now)
    {
        var id = ToHex(request.ProvisionGrantId);
        var grant = _store.Read(reader => AuthorizedGrant(reader, remote, request, RemoteGrantAction.SandboxCreate, id, now));
        return grant is { Scope: StoredRemoteGrantScope.Provision, ParentGrantId: null }
            && grant.TemplateRevision == request.TemplateRevision.Value ? grant : null;
    }

    private StoredRemoteGrant? AuthorizeRemoteConfiguration(SandboxServiceConfigureRequest request,
        VerifiedRemoteGrantCall remote, string sandboxId, DateTimeOffset now)
    {
        if (request.HasRepairError)
        {
            return null;
        }

        var grant = _store.Read(reader => AuthorizedGrant(reader, remote, request, RemoteGrantAction.SandboxConfigure,
            remote.GrantId, now));
        return grant is { Scope: StoredRemoteGrantScope.Sandbox } && grant.SandboxId == sandboxId ? grant : null;
    }

    private static bool ValidRemoteCreationWire(SandboxServiceCreateRequest request) => Shape.IsValid(request)
        && ValidGrantMutation(request.Meta, request.OwnerEpoch)
        && KnownRemoteFields(request, SandboxServiceCreateRequest.Parser) && ValidGrantId(request.ProvisionGrantId)
        && request.TemplateRevision is { HasValue: true, Value: > 0 };

    private static bool ValidRemoteConfigurationWire(SandboxServiceConfigureRequest request) => Shape.IsValid(request)
        && ValidGrantMutation(request.Meta, request.OwnerEpoch) && ValidGrantId(request.SandboxId)
        && KnownRemoteFields(request, SandboxServiceConfigureRequest.Parser);

    private static bool KnownRemoteFields<T>(T request, MessageParser<T> parser) where T : class, IMessage<T> =>
        request.Equals(parser.WithDiscardUnknownFields(true).ParseFrom(request.ToByteArray()));

    private static byte[] RemoteSandboxIntent(byte[] body, VerifiedRemoteGrantCall remote) =>
        Encoding.UTF8.GetBytes(new JsonObject
        {
            // The durable store keys this entire envelope. Prehash the bounded DTO to leave
            // room for its exact actor and grant binding without expanding the wire body.
            ["requestSha256"] = Convert.ToHexStringLower(SHA256.HashData(body)),
            ["binding"] = EncodeGrantBinding(remote.Enrollment),
            ["actor"] = remote.ActorId,
            ["grant"] = remote.GrantId,
            ["grantRevision"] = remote.Revision,
        }.ToJsonString());

    private bool RemoteSandboxAdmissionCurrent(VerifiedRemoteGrantCall remote, StoredRemoteGrant grant, DateTimeOffset now) =>
        remote.Enrollment == _activeEnrollment && remote.IssuedAt <= now && remote.ExpiresAt > now
        && _store.Read(reader => RemoteGrantRecords.IsActiveRevision(reader, OwnerId, grant.GrantId, grant.Revision, now)
            && (grant.ParentGrantId is null || (grant.ParentGrantRevision is { } revision
                && RemoteGrantRecords.IsActiveRevision(reader, OwnerId, grant.ParentGrantId, revision, now))));

    private bool CanReplayRemoteSandbox(DurableReceipt receipt, StoredRemoteGrant grant, DateTimeOffset now)
    {
        if (receipt.AggregateKind != Aggregate || receipt.AggregateId is not { } id
            || !RemoteGrantPolicy.IsAllowed(GrantView(grant, now), RemoteGrantAction.GetOperation))
        {
            return false;
        }

        return _store.Read(reader =>
        {
            var sandbox = SandboxRecords.Get(reader, OwnerId, id);
            if (grant.Scope == StoredRemoteGrantScope.Sandbox)
            {
                return grant.SandboxId == id && sandbox?.State == StoredSandboxState.Ready;
            }

            // A successful provision is visible only through its original unrevoked child. A
            // pending or refused provision has no child and discloses only its own receipt.
            return sandbox is not null && receipt.Method == CreateMethod
                && (receipt.State == "SUCCEEDED"
                    ? RemoteGrantRecords.HasActiveDerivedGrant(reader, OwnerId, id, receipt.CommandId, grant.GrantId, grant.Revision, now)
                    : sandbox.State is StoredSandboxState.Creating or StoredSandboxState.Error or StoredSandboxState.RecoveryRequired);
        });
    }

    private static bool PrepareRemoteSandboxPolicy(SandboxConfig requested, SandboxConfig? bounds, ResourcePolicy? ceiling,
        SandboxConfig? current, [NotNullWhen(true)] out SandboxConfig? prepared)
    {
        prepared = null;
        return bounds is not null && !requested.Environment.Any(entry => entry.HasValue)
            && RemoteGrantPolicy.TryPrepareNarrowing(requested, bounds, out prepared)
            && RemotePolicyWithin(prepared, bounds, ceiling, current);
    }

    private static bool RemotePolicyWithin(SandboxConfig policy, SandboxConfig? bounds, ResourcePolicy? ceiling,
        SandboxConfig? current) => bounds is not null && ceiling is not null && policy.Resources is { } resources
        && RemoteGrantPolicy.IsNarrower(policy, bounds) && RemoteGrantPolicy.ResourcesWithin(resources, ceiling)
        && (current is null || RemoteGrantPolicy.IsNarrower(policy, current));

    private StoredRemoteGrant BuildDerivedGrant(VerifiedRemoteGrantCall remote, StoredRemoteGrant parent, string sandboxId,
        SandboxConfig prepared, RequestMeta meta, DateTimeOffset now)
    {
        var scope = GrantView(parent, now);
        string id = Guid.NewGuid().ToString("N");
        var grant = new RemoteGrant
        {
            GrantId = FromHex(id),
            SandboxId = FromHex(sandboxId),
            EnrollmentId = FromHex(parent.EnrollmentId),
            ParentGrantId = FromHex(parent.GrantId),
            Revision = new Revision { Value = 1 },
            State = GrantState.Active,
            ScopeKind = "sandbox",
            ResourceCeiling = prepared.Resources.Clone(),
            ExpiresAt = scope.ExpiresAt,
            AllowData = scope.AllowData,
            AllowDelete = scope.AllowDelete,
        };
        grant.Methods.AddRange(RemoteGrantPolicy.ProjectChildMethods(scope));
        return new(id, OwnerId, parent.EnrollmentId, StoredRemoteGrantScope.Sandbox, sandboxId, parent.GrantId,
            parent.Revision, 1, StoredRemoteGrantState.Active, GrantPolicyJson(remote.Enrollment, grant, prepared),
            ToHex(meta.CommandId), null, null, now, parent.ExpiresAt, null);
    }

    private static Sandbox RedactRemoteSandbox(Sandbox sandbox)
    {
        sandbox.ClearDataLocation();
        sandbox.Config.HostGrants.Clear();
        sandbox.Config.Environment.Clear();
        sandbox.Config.ClearDefaultWorkdir();
        return sandbox;
    }

    private void RecordRemoteSandboxConfiguration(StoreTransaction transaction, RequestMeta meta, string sandboxId, long revision,
        VerifiedRemoteGrantCall remote, DateTimeOffset now) =>
        _ = RemoteGrantRecords.AppendAudit(transaction, OwnerId, remote.ActorId, "remote", ToHex(meta.CommandId),
            ConfigureMethod, sandboxId, remote.Enrollment.EnrollmentId,
            ValidId(meta.CorrelationId) ? ToHex(meta.CorrelationId) : ToHex(meta.CommandId),
            revision, (int)EffectCertainty.Happened, "sandbox_configured", now);
}
