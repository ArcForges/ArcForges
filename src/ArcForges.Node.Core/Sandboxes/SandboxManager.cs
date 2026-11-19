// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
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
    private readonly Lazy<DurableCommandStore> _receipts;
    private readonly byte[] _cursorKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    private bool _disposed;

    internal SandboxManager(NodeStore store, string dataRoot, string ownerId, NodeSecretStore secrets,
        TimeProvider clock, string? nodeEpoch = null, string? mxcInstallationRoot = null)
    {
        _store = store;
        _dataRoot = dataRoot;
        _clock = clock;
        _nodeEpoch = nodeEpoch ?? Guid.NewGuid().ToString("N");
        _mxcInstallationRoot = mxcInstallationRoot ?? Path.Combine(AppContext.BaseDirectory, "mxc");
        OwnerId = ownerId;
        _roots = new(dataRoot);
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

    internal SandboxServiceCreateResponse Create(SandboxServiceCreateRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var outcome = CreateLocked(request);
                return outcome.Value is { } value
                    ? new() { Meta = Response(request.Meta, value.Revision.Value), Value = new() { Sandbox = value } }
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

    private MutationOutcome CreateLocked(SandboxServiceCreateRequest request)
    {
        if (request.Meta is null || !ValidId(request.Meta.CommandId) || request.Meta.ExpectedRev is not null
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

        canonical.DisplayName = name;
        var command = request.Meta.CommandId.Value.ToByteArray();
        var receipts = Receipts;
        var previous = receipts.Inspect(command);
        var id = previous?.AggregateId ?? Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        var intent = new DurableIntent(command, request.OwnerEpoch.Value.ToByteArray(), CreateMethod, Aggregate,
            id, canonical.ToByteArray());
        if (previous is not null || !EpochMatches(request.OwnerEpoch))
        {
            return Resolve(receipts.Admit(intent), request.Meta);
        }

        if (request.ProvisionGrantId is not null || request.TemplateRevision is not null)
        {
            return Fail(Error(request.Meta, ErrorCategory.Authorization, "permission_denied", "local_provision_only"));
        }

        var policy = EvaluatePolicy(request.Config);
        if (!policy.Admission.Admitted || policy.Config is null)
        {
            return Fail(PolicyError(request.Meta, policy.Admission));
        }

        if (_store.Read(reader => SandboxRecords.NameInUse(reader, OwnerId, normalized)))
        {
            return Fail(Error(request.Meta, ErrorCategory.Conflict, "identity_changed", "sandbox_name_in_use"));
        }

        var now = _clock.GetUtcNow();
        var reservation = new StoredSandbox(id, OwnerId, name, normalized, 1, StoredSandboxState.Creating,
            SandboxPrivateRoots.RelativePath(id), SandboxRecords.PendingRootIdentity, 1, now, now, ToStored(policy.Config));
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
            transaction => RequireChanged(SandboxRecords.SettleCreation(transaction, OwnerId, id, root.Identity, StoredSandboxState.Ready)));
        return new(View(reservation with { State = StoredSandboxState.Ready, RootIdentity = root.Identity }, policy.Admission));
    }

    internal SandboxServiceConfigureResponse Configure(SandboxServiceConfigureRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var outcome = ConfigureLocked(request);
                return outcome.Value is { } value
                    ? new() { Meta = Response(request.Meta, value.Revision.Value), Value = new() { Sandbox = value } }
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

    private MutationOutcome ConfigureLocked(SandboxServiceConfigureRequest request)
    {
        if (request.Meta is null || !ValidId(request.Meta.CommandId) || !ValidId(request.OwnerEpoch)
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
        var expected = request.Meta.ExpectedRev.Value;
        var command = request.Meta.CommandId.Value.ToByteArray();
        var intent = new DurableIntent(command, request.OwnerEpoch.Value.ToByteArray(), ConfigureMethod, Aggregate,
            id, canonical.ToByteArray(), expected);
        var receipts = Receipts;
        if (receipts.Inspect(command) is not null || !EpochMatches(request.OwnerEpoch))
        {
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

        var policy = EvaluatePolicy(request.Config);
        if (!policy.Admission.Admitted || policy.Config is null)
        {
            return Fail(PolicyError(request.Meta, policy.Admission));
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
            using var root = _roots.Inspect(id, row.RootIdentity);
            var admitted = receipts.Admit(intent);
            if (admitted.Decision != DurableDecision.Execute)
            {
                return Resolve(admitted, request.Meta);
            }

            var revision = checked(row.Revision + 1);
            receipts.SetResult(command, "SUCCEEDED", (int)EffectCertainty.Happened, ResultBody(revision, name, capabilities: SandboxPolicyAdmission.Capabilities(policy.Admission)),
                transaction => RequireChanged(SandboxRecords.AppendRevision(transaction, OwnerId, id, expected,
                    name, normalized, config, repair)));
            return new(View(row with { Revision = revision, DisplayName = name, Config = config, State = StoredSandboxState.Ready },
                policy.Admission));
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

    private DurableCommandStore Receipts
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
        SandboxPolicyAdmission.Evaluate(config, _dataRoot, _mxcInstallationRoot);

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
