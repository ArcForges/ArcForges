// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Sandboxes;

/// <summary>Owns the serialization point for V2 Sandbox mutations and native ownership checks.</summary>
internal sealed partial class SandboxManager : IDisposable
{
    private const string CreateMethod = "SandboxService.Create";
    private const string ConfigureMethod = "SandboxService.Configure";
    private const string Aggregate = "sandbox";
    private readonly NodeStore _store;
    private readonly string _dataRoot;
    private readonly TimeProvider _clock;
    private readonly string _nodeEpoch;
    private readonly string _mxcInstallationRoot;
    private readonly SandboxPrivateRoots _roots;
    private readonly SandboxRunSecrets _runSecrets;
    private readonly SandboxProtectedEndpoint? _protectedEndpoint;
    private readonly Lazy<DurableCommandStore> _receipts;
    private readonly byte[] _cursorKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    private bool _disposed;

    internal SandboxManager(NodeStore store, string dataRoot, string ownerId, NodeSecretStore secrets,
        TimeProvider clock, string? nodeEpoch = null, string? mxcInstallationRoot = null,
        SandboxProtectedEndpoint? protectedEndpoint = null)
    {
        _store = store;
        _dataRoot = dataRoot;
        _clock = clock;
        _nodeEpoch = nodeEpoch ?? Guid.NewGuid().ToString("N");
        _mxcInstallationRoot = mxcInstallationRoot ?? Path.Combine(AppContext.BaseDirectory, "mxc");
        OwnerId = ownerId;
        _roots = new(dataRoot);
        _runSecrets = new SandboxRunSecrets(secrets, dataRoot, ownerId);
        _protectedEndpoint = protectedEndpoint;
        _receipts = new(() => OpenReceipts(secrets));
    }

    internal string OwnerId { get; }

    // The same lock covers reservation, native proof and revision changes. Start and Delete use
    // this gate when they bind their own durable intent to a particular owned root/revision.
    internal Lock OwnershipGate { get; } = new();

    internal NodeServiceHandshakeResponse Handshake(NodeServiceHandshakeRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var response = new NodeServiceHandshakeResponse { Meta = Response(request.Meta) };
            try
            {
                var receipts = Receipts;
                var value = new NodeServiceHandshakeValue
                {
                    ContractVersion = "2.0",
                    Cohort = ContractCohort,
                    NodeEpoch = _nodeEpoch,
                    OwnerEpoch = FromBytes(receipts.OwnerEpoch.Span),
                };
                value.Capabilities.AddRange(SandboxPolicyAdmission.HandshakeCapabilities(_dataRoot, _mxcInstallationRoot));
                response.Value = value;
            }
            catch (SandboxPrivateRootException error)
            {
                response.Error = ControlPathFailure(request.Meta, error);
            }
            catch (Exception error) when (IsStorageFailure(error))
            {
                response.Error = StorageFailure(request.Meta);
            }

            return response;
        }
    }

    internal SandboxServiceCreateResponse Create(SandboxServiceCreateRequest request, CancellationToken cancellationToken) =>
        Create(request, null, cancellationToken);

    internal SandboxServiceCreateResponse CreateFromCenter(SandboxServiceCreateRequest request, VerifiedRemoteGrantCall remote,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remote);
        return Create(request, remote, cancellationToken);
    }

    private SandboxServiceCreateResponse Create(SandboxServiceCreateRequest request, VerifiedRemoteGrantCall? remote,
        CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var outcome = CreateLocked(request, remote);
                return outcome.Value is { } value
                    ? new()
                    {
                        Meta = Response(request.Meta, value.Revision.Value),
                        Value = new() { Sandbox = remote is null ? value : RedactRemoteSandbox(value) }
                    }
                    : new() { Meta = Response(request.Meta), Error = outcome.Error };
            }
            catch (SandboxPrivateRootException error)
            {
                return new() { Meta = Response(request.Meta), Error = ControlPathFailure(request.Meta, error) };
            }
            catch (Exception error) when (IsStorageFailure(error))
            {
                return new() { Meta = Response(request.Meta), Error = StorageFailure(request.Meta) };
            }
        }
    }

    private MutationOutcome CreateLocked(SandboxServiceCreateRequest request, VerifiedRemoteGrantCall? remote)
    {
        if ((remote is not null && !ValidRemoteCreationWire(request))
            || request.Meta is null || !ValidId(request.Meta.CommandId) || request.Meta.ExpectedRev is not null
            || !ValidId(request.OwnerEpoch) || request.Config is null
            || !NormalizeName(request.DisplayName, out var name, out var normalized))
        {
            return Fail(Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "create_shape_invalid"));
        }

        var canonical = request.Clone();
        canonical.Meta = null;
        canonical.OwnerEpoch = null;
        var projectedRequest = new SandboxServiceCreateRequest
        {
            Config = request.Config,
            ProvisionGrantId = request.ProvisionGrantId,
            TemplateRevision = request.TemplateRevision,
        };
        if (request.HasDisplayName)
        {
            projectedRequest.DisplayName = request.DisplayName;
        }

        if (!canonical.Equals(projectedRequest))
        {
            return Fail(Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "unknown_create_fields"));
        }

        var now = remote is null ? _clock.GetUtcNow() : ObserveGrantTime();
        StoredRemoteGrant? parent = null;
        SandboxConfig? template = null;
        ResourcePolicy? ceiling = null;
        if (remote is not null)
        {
            parent = AuthorizeRemoteCreation(request, remote, now);
            if (parent is null)
            {
                return Fail(GrantDenied(request.Meta));
            }

            template = GetGrantTemplate(parent);
            ceiling = GrantView(parent, now).ResourceCeiling;
        }
        else if (request.ProvisionGrantId is not null || request.TemplateRevision is not null)
        {
            return Fail(Error(request.Meta, ErrorCategory.Authorization, "permission_denied", "local_provision_only"));
        }

        canonical.DisplayName = name;
        var command = request.Meta.CommandId.Value.ToByteArray();
        var receipts = Receipts;
        var previous = receipts.Inspect(command);
        var id = previous?.AggregateId ?? Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        var body = canonical.ToByteArray();
        var intent = new DurableIntent(command, request.OwnerEpoch.Value.ToByteArray(), CreateMethod, Aggregate,
            id, remote is null ? body : RemoteSandboxIntent(body, remote), AdditionalSafetyReservations: remote is null ? 0 : 1);
        if (previous is not null || !EpochMatches(request.OwnerEpoch))
        {
            if (remote is not null && previous is not null && !CanReplayRemoteSandbox(previous, parent!, now))
            {
                return Fail(GrantDenied(request.Meta));
            }

            return Resolve(receipts.Admit(intent), request.Meta);
        }

        var requested = request.Config;
        if (remote is not null && !PrepareRemoteSandboxPolicy(requested, template, ceiling, null, out requested))
        {
            return Fail(GrantDenied(request.Meta));
        }

        var policy = EvaluatePolicy(requested);
        if (!policy.Admission.Admitted || policy.Config is null)
        {
            return Fail(PolicyError(request.Meta, policy.Admission));
        }

        if (remote is not null && !RemotePolicyWithin(policy.Config, template, ceiling, null))
        {
            return Fail(GrantDenied(request.Meta));
        }

        if (_store.Read(reader => SandboxRecords.NameInUse(reader, OwnerId, normalized)))
        {
            return Fail(Error(request.Meta, ErrorCategory.Conflict, "identity_changed", "sandbox_name_in_use"));
        }

        now = remote is null ? _clock.GetUtcNow() : ObserveGrantTime();
        if (remote is not null && !RemoteSandboxAdmissionCurrent(remote, parent!, now))
        {
            return Fail(GrantDenied(request.Meta));
        }

        var reservation = new StoredSandbox(id, OwnerId, name, normalized, 1, StoredSandboxState.Creating,
            SandboxPrivateRoots.RelativePath(id), SandboxRecords.PendingRootIdentity, 1, now, now, ToStored(policy.Config));
        var child = remote is null ? null : BuildDerivedGrant(remote, parent!, id, policy.Config, request.Meta, now);
        if (child is not null)
        {
            intent = intent with { Provision = new DurableProvisionBinding(parent!.GrantId, parent.Revision, child.GrantId) };
        }

        var admitted = receipts.Admit(intent, transaction => SandboxRecords.Reserve(transaction, reservation));
        if (admitted.Decision != DurableDecision.Execute)
        {
            return Resolve(admitted, request.Meta);
        }

        SandboxPrivateRoot root;
        try
        {
            root = _roots.Provision(id);
        }
        catch (SandboxPrivateRootException failure)
        {
            var definitelyNotOwned = failure.PartialRoot is null
                && failure.Reason is ("private_root_already_exists" or "sandbox_id_invalid");
            var effect = definitelyNotOwned ? EffectCertainty.DidNotHappen : EffectCertainty.Unknown;
            var code = definitelyNotOwned ? "identity_changed" : "outcome_unknown";
            var category = definitelyNotOwned ? ErrorCategory.Conflict : ErrorCategory.Execution;
            var summary = ResultBody(null, null, category, code, failure.Reason);
            receipts.SetResult(command, effect == EffectCertainty.Unknown ? "UNKNOWN" : "FAILED", (int)effect, summary,
                transaction => RequireChanged(SandboxRecords.SettleCreation(transaction, OwnerId, id,
                    failure.PartialRoot?.Identity, definitelyNotOwned ? StoredSandboxState.Error : StoredSandboxState.RecoveryRequired)));
            return Fail(Error(request.Meta, category, code, failure.Reason, effect));
        }

        receipts.SetResult(command, "SUCCEEDED", (int)EffectCertainty.Happened, ResultBody(1, name, capabilities: SandboxPolicyAdmission.Capabilities(policy.Admission)),
            transaction =>
            {
                RequireChanged(SandboxRecords.SettleCreation(transaction, OwnerId, id, root.Identity, StoredSandboxState.Ready));
                if (child is not null)
                {
                    RequireChanged(RemoteGrantRecords.Insert(transaction, child) == 1);
                    RecordGrantAudit(transaction, request.Meta, child, CreateMethod, now, remote);
                }
            });
        return new(View(reservation with { State = StoredSandboxState.Ready, RootIdentity = root.Identity }, policy.Admission));
    }

    internal SandboxServiceConfigureResponse Configure(SandboxServiceConfigureRequest request, CancellationToken cancellationToken) =>
        Configure(request, null, cancellationToken);

    internal SandboxServiceConfigureResponse ConfigureFromCenter(SandboxServiceConfigureRequest request, VerifiedRemoteGrantCall remote,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remote);
        return Configure(request, remote, cancellationToken);
    }

    private SandboxServiceConfigureResponse Configure(SandboxServiceConfigureRequest request, VerifiedRemoteGrantCall? remote,
        CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var outcome = ConfigureLocked(request, remote);
                return outcome.Value is { } value
                    ? new()
                    {
                        Meta = Response(request.Meta, value.Revision.Value),
                        Value = new() { Sandbox = remote is null ? value : RedactRemoteSandbox(value) }
                    }
                    : new() { Meta = Response(request.Meta), Error = outcome.Error };
            }
            catch (SandboxPrivateRootException error)
            {
                return new() { Meta = Response(request.Meta), Error = ControlPathFailure(request.Meta, error) };
            }
            catch (Exception error) when (IsStorageFailure(error))
            {
                return new() { Meta = Response(request.Meta), Error = StorageFailure(request.Meta) };
            }
        }
    }

    private MutationOutcome ConfigureLocked(SandboxServiceConfigureRequest request, VerifiedRemoteGrantCall? remote)
    {
        if ((remote is not null && !ValidRemoteConfigurationWire(request))
            || request.Meta is null || !ValidId(request.Meta.CommandId) || !ValidId(request.OwnerEpoch)
            || !ValidId(request.SandboxId) || request.Config is null
            || request.Meta.ExpectedRev is not { Value: > 0 and < long.MaxValue })
        {
            return Fail(Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "configure_shape_invalid"));
        }

        var canonical = request.Clone();
        canonical.Meta = null;
        canonical.OwnerEpoch = null;
        var effect = new SandboxServiceConfigureRequest { SandboxId = request.SandboxId, Config = request.Config };
        if (request.HasDisplayName)
        {
            effect.DisplayName = request.DisplayName;
        }

        if (request.HasRepairError)
        {
            effect.RepairError = request.RepairError;
        }

        if (!canonical.Equals(effect))
        {
            return Fail(Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "unknown_configure_fields"));
        }

        if (canonical.HasDisplayName)
        {
            canonical.DisplayName = canonical.DisplayName.Normalize(System.Text.NormalizationForm.FormC);
        }

        var id = ToHex(request.SandboxId);
        var now = remote is null ? _clock.GetUtcNow() : ObserveGrantTime();
        StoredRemoteGrant? grant = null;
        if (remote is not null)
        {
            grant = AuthorizeRemoteConfiguration(request, remote, id, now);
            if (grant is null)
            {
                return Fail(GrantDenied(request.Meta));
            }
        }

        var expected = request.Meta.ExpectedRev.Value;
        var command = request.Meta.CommandId.Value.ToByteArray();
        var body = canonical.ToByteArray();
        var intent = new DurableIntent(command, request.OwnerEpoch.Value.ToByteArray(), ConfigureMethod, Aggregate,
            id, remote is null ? body : RemoteSandboxIntent(body, remote), expected);
        var receipts = Receipts;
        var previous = receipts.Inspect(command);
        if (previous is not null || !EpochMatches(request.OwnerEpoch))
        {
            if (remote is not null && previous is not null && !CanReplayRemoteSandbox(previous, grant!, now))
            {
                return Fail(GrantDenied(request.Meta));
            }

            return Resolve(receipts.Admit(intent), request.Meta);
        }

        var row = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, id));
        if (row is null)
        {
            return Fail(NotFound(request.Meta));
        }

        if (row.Revision != expected)
        {
            return Fail(RevisionError(request.Meta, expected, row.Revision));
        }

        bool repair = request.HasRepairError && request.RepairError;
        if (row.State != (repair ? StoredSandboxState.Error : StoredSandboxState.Ready))
        {
            return Fail(Error(request.Meta, ErrorCategory.State, "busy", "sandbox_state_conflict"));
        }

        var name = row.DisplayName;
        var normalized = row.NormalizedName;
        if (request.HasDisplayName && !NormalizeName(request.DisplayName, out name, out normalized))
        {
            return Fail(Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "display_name_invalid"));
        }

        if (_store.Read(reader => SandboxRecords.NameInUse(reader, OwnerId, normalized, id)))
        {
            return Fail(Error(request.Meta, ErrorCategory.Conflict, "identity_changed", "sandbox_name_in_use"));
        }

        var requested = request.Config;
        var bounds = grant is null ? null : ReadGrantBounds(grant);
        var ceiling = grant is null ? null : GrantView(grant, now).ResourceCeiling;
        var current = grant is null ? null : FromStored(row.Config);
        if (grant is not null && !PrepareRemoteSandboxPolicy(requested, bounds, ceiling, current, out requested))
        {
            return Fail(GrantDenied(request.Meta));
        }

        var policy = EvaluatePolicy(requested);
        if (!policy.Admission.Admitted || policy.Config is null)
        {
            return Fail(PolicyError(request.Meta, policy.Admission));
        }

        if (grant is not null && !RemotePolicyWithin(policy.Config, bounds, ceiling, current))
        {
            return Fail(GrantDenied(request.Meta));
        }

        var config = ToStored(policy.Config);
        bool changesPolicy = config != row.Config;
        if (_store.Read(reader => repair ? SandboxRecords.HasUnresolvedUse(reader, OwnerId, id)
            : changesPolicy && SandboxRecords.HasNonterminalRuns(reader, id)))
        {
            return Fail(Error(request.Meta, ErrorCategory.State, "managed_use", "sandbox_managed_use"));
        }

        try
        {
            if (repair && row.RootRelative != SandboxPrivateRoots.RelativePath(id))
            {
                return Fail(Error(request.Meta, ErrorCategory.Conflict, "identity_changed", "private_root_location_changed"));
            }

            using var root = _roots.Inspect(id, row.RootIdentity);
            if (remote is not null)
            {
                now = ObserveGrantTime();
                if (!RemoteSandboxAdmissionCurrent(remote, grant!, now))
                {
                    return Fail(GrantDenied(request.Meta));
                }
            }

            var revision = checked(row.Revision + 1);
            string result = ResultBody(revision, name, capabilities: SandboxPolicyAdmission.Capabilities(policy.Admission));
            var admitted = receipts.AdmitObserved(intent, "SUCCEEDED", (int)EffectCertainty.Happened, result, transaction =>
            {
                if (repair)
                {
                    var currentRoot = SandboxRecords.Get(transaction, OwnerId, id);
                    RequireChanged(currentRoot is not null && currentRoot.RootIdentity == row.RootIdentity
                        && currentRoot.RootRelative == row.RootRelative && currentRoot.RootGeneration == row.RootGeneration
                        && !SandboxRecords.HasUnresolvedUse(transaction, OwnerId, id, intent.OwnerEpoch, ToHex(request.Meta.CommandId)));
                }

                RequireChanged(SandboxRecords.AppendRevision(transaction, OwnerId, id, expected, name, normalized, config, repair));
                if (remote is not null)
                {
                    RecordRemoteSandboxConfiguration(transaction, request.Meta, id, revision, remote, now);
                }
            });
            return Resolve(admitted, request.Meta);
        }
        catch (SandboxPrivateRootException failure)
        {
            return Fail(Error(request.Meta, ErrorCategory.Conflict, "identity_changed", failure.Reason));
        }
    }

    private MutationOutcome Resolve(DurableAdmission admitted, RequestMeta meta)
    {
        var receipt = admitted.Receipt;
        switch (admitted.Decision)
        {
            case DurableDecision.Replay when receipt is not null:
                var result = ReadResult(receipt.ResponseJson);
                if (receipt.State != "SUCCEEDED")
                {
                    return Fail(Error(meta, result.Category, result.Code, result.Reason, (EffectCertainty)receipt.Effect));
                }

                if (result.Revision is not long revision || result.Name is not { } name || receipt.AggregateId is not { } id)
                {
                    return Fail(StorageFailure(meta));
                }

                var snapshot = _store.Read(reader =>
                {
                    var row = SandboxRecords.Get(reader, OwnerId, id);
                    var config = SandboxRecords.GetConfig(reader, OwnerId, id, revision);
                    return row is null || config is null ? null : row with
                    {
                        Revision = revision,
                        DisplayName = name,
                        Config = config,
                        State = StoredSandboxState.Ready,
                    };
                });
                if (snapshot is null)
                {
                    return Fail(StorageFailure(meta));
                }

                var retained = View(snapshot);
                retained.Capabilities.AddRange(result.Capabilities);
                return new(retained);

            case DurableDecision.Compacted when receipt is not null:
                var compacted = Error(meta, ErrorCategory.State, "receipt_compacted", "original_response_compacted",
                    (EffectCertainty)receipt.Effect);
                compacted.Details.State.State = receipt.State;
                compacted.Details.State.Resource = AggregateIdentity(receipt);
                compacted.Retry.ReconciliationOperation = "NodeService.GetOperation";
                return Fail(compacted);

            case DurableDecision.Conflict:
                return Fail(Error(meta, ErrorCategory.Conflict, "command_id_reused", "command_intent_changed"));

            case DurableDecision.EpochRetired:
                return Fail(Error(meta, ErrorCategory.Conflict, "owner_epoch_retired", "owner_epoch_mismatch"));

            case DurableDecision.RevisionConflict:
                return Fail(Error(meta, ErrorCategory.Conflict, "revision_mismatch", "sandbox_revision_changed"));

            case DurableDecision.InProgress:
                return Fail(Error(meta, ErrorCategory.Execution, "outcome_unknown", "original_operation_unresolved",
                    EffectCertainty.Unknown));

            case DurableDecision.Capacity:
                return Fail(Error(meta, ErrorCategory.Resource, "disk_space", "durable_receipt_capacity"));

            default:
                return Fail(StorageFailure(meta));
        }
    }

    internal DurableCommandStore Receipts
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var authority = _receipts.Value;
            if (authority.MaintenanceRequired)
            {
                throw new DurableStoreMaintenanceException();
            }

            return authority;
        }
    }

    private DurableCommandStore OpenReceipts(NodeSecretStore secrets)
    {
        _roots.PrepareControlPaths();
        return new DurableCommandStore(_store, OwnerId, secrets);
    }

    private SandboxPolicyResult EvaluatePolicy(SandboxConfig config) =>
        SandboxPolicyAdmission.Evaluate(config, _dataRoot, _mxcInstallationRoot, _protectedEndpoint);

    private bool EpochMatches(Id epoch) => epoch.Value.Span.SequenceEqual(Receipts.OwnerEpoch.Span);

    public void Dispose()
    {
        lock (OwnershipGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_receipts.IsValueCreated)
            {
                _receipts.Value.Dispose();
            }

            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_cursorKey);
        }
    }
}
