// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Shape = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Security
{
    // This projection contains no credentials. Only the authenticated V2 Center adapter supplies it.
    internal sealed record ActiveRemoteEnrollment(string OwnerId, string EnrollmentId, string AccountId, string Audience,
        string Issuer, string Epoch);

    internal sealed record ActiveRemoteChannel(string ConnectionId, ulong HubFence);

    // The adapter verifies the signed action and exact body (including command identity) before entering Core.
    internal sealed record VerifiedRemoteGrantCall(ActiveRemoteEnrollment Enrollment, string ActorId, string GrantId,
        long Revision, RemoteGrantAction Action, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, ByteString BodySha256,
        ActiveRemoteChannel? Channel = null, ReadOnlyMemory<byte> OriginalOwnerEpoch = default);
}

namespace ArcForges.Node.Core.Sandboxes
{
    internal sealed partial class SandboxManager
    {
        private const string SetGrantMethod = "NodeService.SetRemoteGrant";
        private const string RevokeGrantMethod = "NodeService.RevokeRemoteGrant";
        private const string GrantAggregate = "grant";
        private ActiveRemoteEnrollment? _activeEnrollment;
        private ActiveRemoteChannel? _activeRemoteChannel;

        // Serialize link replacement/disconnect with grant admission. The retained V1 link does not publish this authority.
        internal void UpdateRemoteEnrollment(ActiveRemoteEnrollment? enrollment, ActiveRemoteChannel? channel = null)
        {
            if (enrollment is not null && (enrollment.OwnerId != OwnerId || !IsRemoteGrantIdentity(enrollment.EnrollmentId)
                || !IsRemoteGrantIdentity(enrollment.AccountId) || !IsRemoteGrantIdentity(enrollment.Epoch)
                || !ValidRemoteAudience(enrollment.Audience) || !ValidRemoteAudience(enrollment.Issuer)))
            {
                throw new ArgumentException("Invalid verified enrollment projection.", nameof(enrollment));
            }

            if (channel is not null && (enrollment is null || !IsRemoteGrantIdentity(channel.ConnectionId)
                || channel.HubFence is 0 or > long.MaxValue))
            {
                throw new ArgumentException("Invalid verified channel projection.", nameof(channel));
            }

            lock (OwnershipGate)
            {
                _activeEnrollment = enrollment;
                _activeRemoteChannel = channel;
            }
        }

        private static bool ValidRemoteAudience(string value) =>
            value.Length is > 0 and <= 2048 && Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0
            && uri.Query.Length == 0;

        internal NodeServiceSetRemoteGrantResponse SetRemoteGrant(NodeServiceSetRemoteGrantRequest request,
            CancellationToken cancellationToken)
        {
            lock (OwnershipGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var (value, error) = SetGrantLocked(request);
                    return value is null ? new() { Meta = Response(request.Meta), Error = error }
                        : new() { Meta = Response(request.Meta, value.Revision.Value), Value = new() { Grant = value } };
                }
                catch (Exception failure) when (IsStorageFailure(failure) || failure is JsonException or InvalidProtocolBufferException)
                {
                    return new() { Meta = Response(request.Meta), Error = StorageFailure(request.Meta) };
                }
            }
        }

        private (RemoteGrant?, ArcError?) SetGrantLocked(NodeServiceSetRemoteGrantRequest request)
        {
            long? expected = request.Meta?.ExpectedRev?.Value;
            if (!ValidGrantMutation(request.Meta, request.OwnerEpoch) || request.Grant is not { } grant
                || !ValidGrantId(grant.EnrollmentId) || grant.ParentGrantId is not null
                || grant.HasState && grant.State != GrantState.Active || !RemoteGrantPolicy.HasValidMethods(grant)
                || grant.GrantId is not null && !ValidGrantId(grant.GrantId)
                || grant.Revision is not null && grant.Revision.Value != (expected ?? 1)
                || expected.HasValue && (expected is <= 0 or >= long.MaxValue || grant.GrantId is null))
            {
                return (null, InvalidGrant(request.Meta, "grant_set_shape_invalid"));
            }

            var meta = request.Meta;
            var command = meta.CommandId.Value.ToByteArray();
            var prior = Receipts.Inspect(command);
            var enrollment = _activeEnrollment;
            if (prior is { Method: SetGrantMethod, AggregateKind: GrantAggregate, AggregateId: { } recorded })
            {
                // The current OS owner may observe the original result after disconnect. Only the
                // retained binding can reproduce the original keyed intent, and this branch never creates a grant.
                var saved = _store.Read(reader => RemoteGrantRecords.Get(reader, OwnerId, recorded));
                enrollment = saved is null ? null : ReadGrantBinding(saved);
            }

            if (enrollment is null)
            {
                return (null, Error(meta, ErrorCategory.Authorization, "permission_denied", "active_v2_enrollment_required"));
            }

            if (ToHex(grant.EnrollmentId) != enrollment.EnrollmentId)
            {
                return (null, GrantDenied(request.Meta));
            }

            var id = grant.GrantId is not null ? ToHex(grant.GrantId)
                : prior?.AggregateId ?? Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            var intent = GrantIntent(meta, request.OwnerEpoch, id, SetGrantMethod, grant.ToByteArray(), enrollment,
                expected is long revision ? new(revision, DurableGrantAction.Replace) : null);
            if (prior is not null || !EpochMatches(request.OwnerEpoch))
            {
                return GrantMutationResult(Receipts.Admit(intent), meta);
            }

            var (existing, inUse) = _store.Read(reader => (
                RemoteGrantRecords.Get(reader, OwnerId, id),
                reader.Scalar("SELECT EXISTS(SELECT 1 FROM remote_grant WHERE grant_id=$id);", ("$id", id)) is 1L));
            if (expected.HasValue ? existing?.Revision != expected : inUse)
            {
                return (null, RevisionError(meta, expected ?? 0, existing?.Revision ?? 0));
            }

            var now = ObserveGrantTime();
            var expiry = ProtoTime.ToDateTimeOffset(grant.ExpiresAt);
            if (grant.ExpiresAt is not null && (expiry is null || expiry <= now))
            {
                return (null, InvalidGrant(meta, "grant_expiry_invalid"));
            }

            if (existing is not null && (!IsActiveGrant(existing, now) || existing.ParentGrantId is not null
                || ReadGrantBinding(existing) != enrollment))
            {
                return (null, GrantDenied(meta));
            }

            var value = grant.Clone();
            value.GrantId = FromHex(id);
            value.Revision = new Revision { Value = (expected ?? 0) + 1 };
            value.State = GrantState.Active;
            var scope = value.ScopeKind == "provision" ? StoredRemoteGrantScope.Provision : StoredRemoteGrantScope.Sandbox;
            SandboxConfig bounds;
            string? sandboxId = null;
            if (scope == StoredRemoteGrantScope.Provision)
            {
                if (value.SandboxId is not null || value.CreationTemplate is not { } template
                    || template.Environment.Any(entry => entry.HasValue)
                    || !RemoteGrantPolicy.IsAllowed(value, RemoteGrantAction.SandboxCreate))
                {
                    return (null, InvalidGrant(meta, "grant_provision_template_invalid"));
                }

                var priorTemplate = existing is null ? null : GetGrantTemplate(existing);
                long templateRevision = existing?.TemplateRevision ?? 0;
                var templateResult = EvaluatePolicy(template);
                if (!templateResult.Admission.Admitted || templateResult.Config is null)
                {
                    return (null, PolicyError(meta, templateResult.Admission));
                }

                bounds = templateResult.Config;
                if (!bounds.Equals(priorTemplate))
                {
                    templateRevision = checked(templateRevision + 1);
                }

                if ((value.TemplateRevision is not null && value.TemplateRevision.Value != templateRevision)
                    || templateRevision <= 0)
                {
                    return (null, InvalidGrant(meta, "grant_template_revision_invalid"));
                }

                value.TemplateRevision = new Revision { Value = templateRevision };
                value.CreationTemplate = bounds;
            }
            else
            {
                if (!ValidId(value.SandboxId) || value.CreationTemplate is not null || value.TemplateRevision is not null)
                {
                    return (null, InvalidGrant(meta, "grant_sandbox_scope_invalid"));
                }

                sandboxId = ToHex(value.SandboxId);
                var sandbox = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, sandboxId));
                if (sandbox?.State != StoredSandboxState.Ready)
                {
                    return (null, NotFound(meta));
                }

                bounds = FromStored(sandbox.Config);
                // Persistent Sandbox policy is already owner-local. The grant never duplicates its literal environment.
                for (int i = bounds.Environment.Count - 1; i >= 0; i--)
                {
                    if (bounds.Environment[i].HasValue)
                    {
                        bounds.Environment.RemoveAt(i);
                    }
                }
            }

            if (existing is not null && (existing.Scope != scope || existing.SandboxId != sandboxId))
            {
                return (null, InvalidGrant(meta, "grant_scope_immutable"));
            }

            value.ResourceCeiling ??= bounds.Resources.Clone();
            if (!Shape.IsValid(value) || !RemoteGrantPolicy.ResourcesWithin(value.ResourceCeiling, bounds.Resources))
            {
                return (null, InvalidGrant(meta, "grant_resource_ceiling_invalid"));
            }

            var row = new StoredRemoteGrant(id, OwnerId, enrollment.EnrollmentId, scope, sandboxId, null, null,
                value.Revision.Value, StoredRemoteGrantState.Active, GrantPolicyJson(enrollment, value, bounds),
                existing?.RevocationAnchorCommandId ?? ToHex(meta.CommandId), value.TemplateRevision?.Value,
                scope == StoredRemoteGrantScope.Provision ? EncodeGrantConfig(bounds) : null, existing?.CreatedAt ?? now, expiry, null);
            var redacted = GrantSummary(value);
            var outcome = Receipts.AdmitObserved(intent, "SUCCEEDED", (int)EffectCertainty.Happened, GrantResultJson(redacted),
                tx =>
                {
                    RequireChanged((existing is null ? RemoteGrantRecords.Insert(tx, row)
                        : RemoteGrantRecords.Replace(tx, row, expected!.Value, now)) == 1);
                    RecordGrantAudit(tx, meta, row, SetGrantMethod, now, remote: null);
                });
            return outcome.Decision == DurableDecision.Execute ? (redacted, null) : GrantMutationResult(outcome, meta);
        }

        internal NodeServiceRevokeRemoteGrantResponse RevokeRemoteGrant(NodeServiceRevokeRemoteGrantRequest request,
            CancellationToken cancellationToken) => RevokeGrant(request, null, cancellationToken);

        internal NodeServiceRevokeRemoteGrantResponse RevokeRemoteGrantFromCenter(NodeServiceRevokeRemoteGrantRequest request,
            VerifiedRemoteGrantCall verified, CancellationToken cancellationToken) =>
            RevokeGrant(request, verified, cancellationToken);

        private NodeServiceRevokeRemoteGrantResponse RevokeGrant(NodeServiceRevokeRemoteGrantRequest request,
            VerifiedRemoteGrantCall? remote, CancellationToken cancellationToken)
        {
            lock (OwnershipGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var (value, error) = RevokeGrantLocked(request, remote, cancellationToken);
                    return value is null ? new() { Meta = Response(request.Meta), Error = error }
                        : new() { Meta = Response(request.Meta, value.Revision.Value), Value = new() { Grant = value } };
                }
                catch (Exception failure) when (IsStorageFailure(failure) || failure is JsonException or InvalidProtocolBufferException)
                {
                    return new() { Meta = Response(request.Meta), Error = StorageFailure(request.Meta) };
                }
            }
        }

        private (RemoteGrant?, ArcError?) RevokeGrantLocked(NodeServiceRevokeRemoteGrantRequest request, VerifiedRemoteGrantCall? remote,
            CancellationToken cancellationToken)
        {
            if (!ValidGrantMutation(request.Meta, request.OwnerEpoch) || !ValidGrantId(request.GrantId)
                || request.Meta.ExpectedRev is not { Value: > 0 and < long.MaxValue }
                || remote is not null && (!Shape.IsValid(request) || !MatchesRemoteOwnerEpoch(remote, request.OwnerEpoch)
                    || !KnownRemoteFields(request, NodeServiceRevokeRemoteGrantRequest.Parser)))
            {
                return (null, InvalidGrant(request.Meta, "grant_revoke_shape_invalid"));
            }

            string id = ToHex(request.GrantId);
            long expected = request.Meta.ExpectedRev.Value;
            var now = ObserveGrantTime();
            var row = _store.Read(reader => remote is null ? RemoteGrantRecords.Get(reader, OwnerId, id)
                : AuthorizedGrant(reader, remote, request, RemoteGrantAction.RevokeRemoteGrant, id, now));
            if (remote is not null && (row is null || remote.Revision != expected))
            {
                return (null, GrantDenied(request.Meta));
            }

            if (remote is not null && !EpochMatches(request.OwnerEpoch))
            {
                return (null, RetiredRunEpoch(request.Meta));
            }

            var intent = GrantIntent(request.Meta, request.OwnerEpoch, id, RevokeGrantMethod, request.GrantId.ToByteArray(),
                remote?.Enrollment, new(expected, DurableGrantAction.Revoke), remote?.ActorId);
            if (remote is not null)
            {
                intent = intent with { Remote = RemoteReceiptBinding(remote, row!) };
            }

            var prior = Receipts.Inspect(intent.CommandId);
            if (prior is not null || !EpochMatches(request.OwnerEpoch))
            {
                if (remote is not null && prior is not null && prior.Remote != intent.Remote)
                {
                    return (null, GrantDenied(request.Meta));
                }

                return GrantMutationResult(Receipts.Admit(intent), request.Meta);
            }

            if (row is null)
            {
                return (null, NotFound(request.Meta));
            }

            if (row.Revision != expected || !IsActiveGrant(row, now))
            {
                return (null, RevisionError(request.Meta, expected, row.Revision));
            }

            var updated = row with { Revision = row.Revision + 1, State = StoredRemoteGrantState.Revoked, RevokedAt = now };
            var value = GrantSummary(GrantView(updated, now));
            if (remote is not null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!RemoteSandboxAdmissionCurrent(remote, row, ObserveGrantTime()))
                {
                    return (null, GrantDenied(request.Meta));
                }
            }

            var outcome = Receipts.AdmitObserved(intent, "SUCCEEDED", (int)EffectCertainty.Happened, GrantResultJson(value),
                tx =>
                {
                    RequireChanged(RemoteGrantRecords.Revoke(tx, OwnerId, id, expected, now, remote?.Enrollment.EnrollmentId) == 1);
                    RecordGrantAudit(tx, request.Meta, updated, RevokeGrantMethod, now, remote);
                });
            return outcome.Decision == DurableDecision.Execute ? (value, null) : GrantMutationResult(outcome, request.Meta);
        }

        internal NodeServiceListRemoteGrantsResponse ListRemoteGrants(NodeServiceListRemoteGrantsRequest request,
            CancellationToken cancellationToken) => ListGrants(request, null, cancellationToken);

        internal NodeServiceListRemoteGrantsResponse ListRemoteGrantsFromCenter(NodeServiceListRemoteGrantsRequest request,
            VerifiedRemoteGrantCall verified, CancellationToken cancellationToken) => ListGrants(request, verified, cancellationToken);

        private NodeServiceListRemoteGrantsResponse ListGrants(NodeServiceListRemoteGrantsRequest request,
            VerifiedRemoteGrantCall? remote, CancellationToken cancellationToken)
        {
            lock (OwnershipGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var meta = Response(request.Meta);
                if (!Shape.IsValid(request) || remote is not null && !KnownRemoteFields(request, NodeServiceListRemoteGrantsRequest.Parser))
                {
                    return new() { Meta = meta, Error = InvalidGrant(request.Meta, "grant_list_shape_invalid") };
                }

                try
                {
                    var now = ObserveGrantTime();
                    return _store.Read(reader =>
                    {
                        string? sandbox = request.SandboxId is { } id ? ToHex(id) : null;
                        if (remote is not null)
                        {
                            var row = AuthorizedGrant(reader, remote, request, RemoteGrantAction.ListRemoteGrants, remote.GrantId, now);
                            if (row is null || sandbox is not null && row.SandboxId != sandbox)
                            {
                                return new NodeServiceListRemoteGrantsResponse { Meta = meta, Error = GrantDenied(request.Meta) };
                            }

                            if (!CurrentRemoteOwnerEpoch(remote))
                            {
                                return new NodeServiceListRemoteGrantsResponse { Meta = meta, Error = RetiredRunEpoch(request.Meta) };
                            }

                            if (request.Cursor.Length != 0)
                            {
                                return new NodeServiceListRemoteGrantsResponse
                                {
                                    Meta = meta,
                                    Error = GrantCursorError(request.Meta)
                                };
                            }

                            return GrantList(meta, [GrantSummary(GrantView(row, now))], "");
                        }

                        long revision = RemoteGrantRecords.ListVersion(reader, OwnerId, sandbox, null);
                        if (!ReadGrantCursor(request.Cursor, revision, sandbox, out var after))
                        {
                            return new NodeServiceListRemoteGrantsResponse { Meta = meta, Error = GrantCursorError(request.Meta) };
                        }

                        int limit = request.HasLimit ? (int)request.Limit : 50;
                        var rows = RemoteGrantRecords.List(reader, OwnerId, sandbox, null, after, limit + 1);
                        var next = rows.Count > limit ? WriteGrantCursor(revision, sandbox, rows[limit - 1].GrantId) : "";
                        return GrantList(meta, rows.Take(limit).Select(row => GrantView(row, now)), next);
                    });
                }
                catch (Exception failure) when (IsStorageFailure(failure) || failure is JsonException or InvalidProtocolBufferException)
                {
                    return new() { Meta = meta, Error = StorageFailure(request.Meta) };
                }
            }
        }

        private static NodeServiceListRemoteGrantsResponse GrantList(ResponseMeta meta, IEnumerable<RemoteGrant> rows, string cursor)
        {
            var value = new NodeServiceListRemoteGrantsValue { Page = new() { NextCursor = cursor } };
            value.Grants.AddRange(rows);
            return new() { Meta = meta, Value = value };
        }

        private StoredRemoteGrant? AuthorizedGrant(StoreReader reader, VerifiedRemoteGrantCall remote, IMessage request,
            RemoteGrantAction action, string requiredGrantId, DateTimeOffset now)
        {
            if (!RemoteChannelCurrent(remote) || !IsRemoteGrantIdentity(remote.ActorId) || !IsRemoteGrantIdentity(remote.GrantId)
                || remote.GrantId != requiredGrantId || remote.Revision <= 0 || remote.Action != action
                || remote.OriginalOwnerEpoch.Length != 16 || !remote.OriginalOwnerEpoch.Span.ContainsAnyExcept((byte)0)
                || remote.IssuedAt > now || remote.ExpiresAt <= now || remote.ExpiresAt - remote.IssuedAt > TimeSpan.FromMinutes(5)
                || request.CalculateSize() > 1_048_576
                || !CryptographicOperations.FixedTimeEquals(remote.BodySha256.Span, SHA256.HashData(request.ToByteArray())))
            {
                return null;
            }

            var row = RemoteGrantRecords.Get(reader, OwnerId, remote.GrantId);
            if (row is null || row.Revision != remote.Revision || !IsActiveGrant(row, now)
                || ReadGrantBinding(row) != remote.Enrollment || !RemoteGrantPolicy.IsAllowed(GrantView(row, now), action))
            {
                return null;
            }

            if (row.ParentGrantId is { } parentId)
            {
                var parent = RemoteGrantRecords.Get(reader, OwnerId, parentId);
                if (parent is null || !IsActiveGrant(parent, now) || parent.Scope != StoredRemoteGrantScope.Provision
                    || parent.Revision != row.ParentGrantRevision || ReadGrantBinding(parent) != remote.Enrollment
                    || !RemoteGrantPolicy.ProjectChildMethods(GrantView(parent, now))
                        .Any(method => RemoteGrantPolicy.TryGetAction(method, out var allowed) && allowed == action))
                {
                    return null;
                }
            }

            return row;
        }

        private bool RemoteChannelCurrent(VerifiedRemoteGrantCall remote) => remote.Channel is not null
            && remote.Channel == _activeRemoteChannel && remote.Enrollment == _activeEnrollment;

        private DateTimeOffset ObserveGrantTime()
        {
            var now = _clock.GetUtcNow();
            _ = Receipts.ObserveGrantExpirations(now);
            return now;
        }

        private static bool ValidGrantMutation([NotNullWhen(true)] RequestMeta? meta, [NotNullWhen(true)] Id? epoch) =>
            meta is { ExpectedNative: null } && ValidGrantId(meta.CommandId) && epoch is not null && ValidGrantId(epoch);

        private static bool ValidGrantId(Id? value) => value?.Value is { Length: 16 } bytes
            && bytes.Span.ContainsAnyExcept((byte)0);

        private static bool IsRemoteGrantIdentity(string id) => IsSandboxId(id) && id.AsSpan().ContainsAnyExcept('0');

        private static bool MatchesRemoteOwnerEpoch(VerifiedRemoteGrantCall remote, Id? epoch) =>
            ValidGrantId(epoch) && remote.OriginalOwnerEpoch.Span.SequenceEqual(epoch!.Value.Span);

        private bool CurrentRemoteOwnerEpoch(VerifiedRemoteGrantCall remote) =>
            Receipts.OwnerEpoch.Span.SequenceEqual(remote.OriginalOwnerEpoch.Span);

        private static bool IsActiveGrant(StoredRemoteGrant row, DateTimeOffset now) =>
            row.State == StoredRemoteGrantState.Active && (row.ExpiresAt is null || row.ExpiresAt > now);

        private static ArcError InvalidGrant(RequestMeta? meta, string reason) =>
            Error(meta, ErrorCategory.Validation, "invalid_argument", reason);

        private static ArcError GrantDenied(RequestMeta? meta) =>
            Error(meta, ErrorCategory.Authorization, "permission_denied", "remote_grant_authority_unavailable");

        private static ArcError GrantCursorError(RequestMeta? meta) =>
            Error(meta, ErrorCategory.Validation, "invalid_cursor", "grant_cursor_invalid_or_stale");

        private static DurableIntent GrantIntent(RequestMeta meta, Id epoch, string id, string method, byte[] body,
            ActiveRemoteEnrollment? enrollment, DurableGrantPrecondition? grant, string? actor = null)
        {
            var canonical = new JsonObject
            {
                ["requestHash"] = Convert.ToHexStringLower(SHA256.HashData(body)),
                ["revision"] = meta.ExpectedRev?.Value,
                ["binding"] = enrollment is null ? null : EncodeGrantBinding(enrollment),
                ["actor"] = actor,
            };
            return new(meta.CommandId.Value.ToByteArray(), epoch.Value.ToByteArray(), method, GrantAggregate, id,
                Encoding.UTF8.GetBytes(canonical.ToJsonString()), Grant: grant);
        }

        private static string EncodeGrantConfig(SandboxConfig value) =>
            new JsonObject { ["configuration"] = Convert.ToBase64String(value.ToByteArray()) }.ToJsonString();

        private static SandboxConfig DecodeGrantConfig(JsonElement data) =>
            SandboxConfig.Parser.ParseFrom(data.GetProperty("configuration").GetBytesFromBase64());

        private static SandboxConfig? GetGrantTemplate(StoredRemoteGrant row)
        {
            if (row.CreationTemplateJson is null)
            {
                return null;
            }

            using var document = JsonDocument.Parse(row.CreationTemplateJson);
            return DecodeGrantConfig(document.RootElement);
        }

        private static string GrantPolicyJson(ActiveRemoteEnrollment enrollment, RemoteGrant grant, SandboxConfig bounds)
        {
            var persisted = grant.Clone();
            persisted.CreationTemplate = null;
            return new JsonObject
            {
                ["binding"] = EncodeGrantBinding(enrollment),
                ["policy"] = Convert.ToBase64String(persisted.ToByteArray()),
                ["configuration"] = Convert.ToBase64String(bounds.ToByteArray()),
            }.ToJsonString();
        }

        private static JsonObject EncodeGrantBinding(ActiveRemoteEnrollment enrollment) => new()
        {
            ["owner"] = enrollment.OwnerId,
            ["enrollment"] = enrollment.EnrollmentId,
            ["account"] = enrollment.AccountId,
            ["audience"] = enrollment.Audience,
            ["issuer"] = enrollment.Issuer,
            ["epoch"] = enrollment.Epoch,
        };

        private static ActiveRemoteEnrollment ReadGrantBinding(StoredRemoteGrant row)
        {
            using var document = JsonDocument.Parse(row.PolicyJson);
            var data = document.RootElement.GetProperty("binding");
            return new(data.GetProperty("owner").GetString()!, data.GetProperty("enrollment").GetString()!,
                data.GetProperty("account").GetString()!, data.GetProperty("audience").GetString()!,
                data.GetProperty("issuer").GetString()!, data.GetProperty("epoch").GetString()!);
        }

        private static SandboxConfig ReadGrantBounds(StoredRemoteGrant row)
        {
            using var document = JsonDocument.Parse(row.PolicyJson);
            return DecodeGrantConfig(document.RootElement);
        }

        private static RemoteGrant GrantView(StoredRemoteGrant row, DateTimeOffset now)
        {
            using var document = JsonDocument.Parse(row.PolicyJson);
            var grant = RemoteGrant.Parser.ParseFrom(document.RootElement.GetProperty("policy").GetBytesFromBase64());
            grant.Revision = new Revision { Value = row.Revision };
            grant.State = row.State == StoredRemoteGrantState.Active && row.ExpiresAt <= now ? GrantState.Expired : (GrantState)row.State;
            grant.CreationTemplate = GetGrantTemplate(row);
            return grant;
        }

        private static RemoteGrant GrantSummary(RemoteGrant grant)
        {
            var value = grant.Clone();
            if (value.CreationTemplate is { } template)
            {
                template.HostGrants.Clear();
                template.Environment.Clear();
                template.ClearDefaultWorkdir();
            }

            return value;
        }

        private static string GrantResultJson(RemoteGrant value) => new JsonObject
        {
            ["revision"] = value.Revision.Value,
            ["grant"] = Convert.ToBase64String(value.ToByteArray()),
        }.ToJsonString();

        private (RemoteGrant?, ArcError?) GrantMutationResult(DurableAdmission outcome, RequestMeta meta)
        {
            if (outcome is { Decision: DurableDecision.Replay, Receipt: { ResponseJson: { } json } })
            {
                using var document = JsonDocument.Parse(json);
                return (RemoteGrant.Parser.ParseFrom(document.RootElement.GetProperty("grant").GetBytesFromBase64()), null);
            }

            return (null, Resolve(outcome, meta).Error);
        }

        private void RecordGrantAudit(StoreTransaction tx, RequestMeta meta, StoredRemoteGrant row, string method,
            DateTimeOffset now, VerifiedRemoteGrantCall? remote) =>
            _ = RemoteGrantRecords.AppendAudit(tx, OwnerId, remote?.ActorId ?? OwnerId, remote is null ? "local" : "remote",
                ToHex(meta.CommandId), method, row.GrantId, row.EnrollmentId,
                ValidId(meta.CorrelationId) ? ToHex(meta.CorrelationId) : ToHex(meta.CommandId),
                row.Revision, (int)EffectCertainty.Happened, "remote_grant_changed", now);

        private string WriteGrantCursor(long revision, string? sandbox, string after)
        {
            Span<byte> token = stackalloc byte[56];
            BinaryPrimitives.WriteInt64LittleEndian(token, revision);
            Convert.FromHexString(after).CopyTo(token[8..24]);
            GrantCursorMac(token[..24], sandbox, token[24..]);
            return Convert.ToBase64String(token);
        }

        private bool ReadGrantCursor(string cursor, long revision, string? sandbox, out string? after)
        {
            after = null;
            if (cursor.Length == 0)
            {
                return true;
            }

            Span<byte> token = stackalloc byte[56];
            if (!Convert.TryFromBase64String(cursor, token, out int length) || length != token.Length
                || BinaryPrimitives.ReadInt64LittleEndian(token) != revision)
            {
                return false;
            }

            Span<byte> mac = stackalloc byte[32];
            GrantCursorMac(token[..24], sandbox, mac);
            if (!CryptographicOperations.FixedTimeEquals(mac, token[24..]))
            {
                return false;
            }

            after = Convert.ToHexStringLower(token[8..24]);
            return true;
        }

        private void GrantCursorMac(ReadOnlySpan<byte> payload, string? sandbox, Span<byte> mac)
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _cursorKey);
            hmac.AppendData(Encoding.UTF8.GetBytes("remote-grant:" + OwnerId + ":" + sandbox));
            hmac.AppendData(payload);
            hmac.GetHashAndReset(mac);
        }
    }
}
