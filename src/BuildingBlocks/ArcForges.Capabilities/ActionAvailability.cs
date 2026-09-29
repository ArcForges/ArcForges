// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;
using FoundationActionDescriptor = ArcForges.Contracts.Foundation.V1.ActionDescriptor;

namespace ArcForges.Capabilities;

/// <summary>The closed availability projection defined by the shared Action contract.</summary>
public enum AvailabilityResult
{
    Available = 0,
    NotApplicableToContext = 1,
    AppNotInstalled = 2,
    AppNotRunning = 3,
    IncompatibleVersion = 4,
    PermissionRequired = 5,
    EntitlementRequired = 6,
    PolicyDisabled = 7,
    TemporarilyUnavailable = 8,
}

/// <summary>Stable identity of a user-facing action; it is distinct from a capability operation key.</summary>
public sealed record ActionKey
{
    public ActionKey(string value)
    {
        if (!AvailabilityEvidenceValidation.IsKey(value))
        {
            throw new ArgumentException("An action key must be a non-empty bounded contract key.", nameof(value));
        }

        Value = value;
    }

    public string Value { get; }
}

/// <summary>Whether a trusted host's captured fact is explicitly established.</summary>
public enum AvailabilityFactState
{
    Unknown = 0,
    Yes = 1,
    No = 2,
}

/// <summary>The precomputed freshness result for one short-lived UI enumeration snapshot.</summary>
public enum AvailabilityFreshnessDisposition
{
    Unknown = 0,
    Current = 1,
    StaleAtCapture = 2,
}

/// <summary>Provider identity fixed for one in-process enumeration and its frozen owner.</summary>
public sealed record AvailabilityProviderScope
{
    public AvailabilityProviderScope(InstanceIdentity owner, string principalKey, string sessionKey)
    {
        Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        if (!AvailabilityEvidenceValidation.IsKey(principalKey) ||
            !AvailabilityEvidenceValidation.IsKey(sessionKey))
        {
            throw new ArgumentException("Principal and session keys must be non-empty bounded identifiers.");
        }

        PrincipalKey = principalKey;
        SessionKey = sessionKey;
    }

    public InstanceIdentity Owner { get; }
    public string PrincipalKey { get; }
    public string SessionKey { get; }
}

/// <summary>A closed target identity used only to key captured availability evidence.</summary>
public sealed record AvailabilityTargetKey
{
    private AvailabilityTargetKey(
        string value,
        AvailabilityTargetKind kind,
        InstanceIdentity? productInstance,
        SearchService? cloudService)
    {
        Value = value;
        Kind = kind;
        ProductInstance = productInstance;
        CloudService = cloudService;
    }

    public string Value { get; }
    public AvailabilityTargetKind Kind { get; }
    public InstanceIdentity? ProductInstance { get; }
    public SearchService? CloudService { get; }

    /// <summary>Creates a key for an already captured local product instance, without selecting or launching it.</summary>
    public static AvailabilityTargetKey ForProductInstance(InstanceIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var installation = identity.Installation;
        var value = string.Join(':',
            "product",
            installation.App.ProductId,
            installation.DeviceId.Value.ToString("N"),
            installation.InstallationId.Value.ToString("N"),
            identity.InstanceId.Value.ToString("N"),
            identity.Epoch.ToString("D20", System.Globalization.CultureInfo.InvariantCulture));
        return new AvailabilityTargetKey(value, AvailabilityTargetKind.ProductInstance, identity, null);
    }

    /// <summary>Creates static catalogue metadata for the one declared Cloud search service.</summary>
    public static AvailabilityTargetKey ForCloudSearchService(SearchService service)
    {
        ArgumentNullException.ThrowIfNull(service);
        if (!ReferenceEquals(service, SearchService.Instance))
        {
            throw new ArgumentException("Only the declared SearchService catalogue identity is supported.", nameof(service));
        }

        return new AvailabilityTargetKey("cloud.search", AvailabilityTargetKind.CloudSearchService, null, service);
    }
}

/// <summary>The closed target identity variants understood by the availability projection.</summary>
public enum AvailabilityTargetKind
{
    ProductInstance = 0,
    CloudSearchService = 1,
}

/// <summary>Owner-captured local target facts; compatibility is explicit and never inferred from contract version.</summary>
public sealed record AvailabilityTargetFacts
{
    public AvailabilityTargetFacts(
        AvailabilityFactState installed,
        AvailabilityFactState running,
        AvailabilityFactState compatible,
        AvailabilityFactState ready,
        AvailabilityFactState acceptsWork,
        string? productVersion,
        string sourceGeneration,
        DateTimeOffset observedAtUtc)
    {
        AvailabilityEvidenceValidation.RequireDefined(installed, nameof(installed));
        AvailabilityEvidenceValidation.RequireDefined(running, nameof(running));
        AvailabilityEvidenceValidation.RequireDefined(compatible, nameof(compatible));
        AvailabilityEvidenceValidation.RequireDefined(ready, nameof(ready));
        AvailabilityEvidenceValidation.RequireDefined(acceptsWork, nameof(acceptsWork));
        if (installed == AvailabilityFactState.No && running == AvailabilityFactState.Yes)
        {
            throw new ArgumentException("A target cannot be explicitly running while explicitly not installed.");
        }

        if (compatible != AvailabilityFactState.Unknown &&
            !AvailabilityEvidenceValidation.IsKey(productVersion))
        {
            throw new ArgumentException("An explicit compatibility fact must retain its product version.", nameof(productVersion));
        }

        if (!AvailabilityEvidenceValidation.IsKey(sourceGeneration))
        {
            throw new ArgumentException("A target fact must retain its source generation.", nameof(sourceGeneration));
        }

        AvailabilityEvidenceValidation.RequireUtc(observedAtUtc, nameof(observedAtUtc));
        Installed = installed;
        Running = running;
        Compatible = compatible;
        Ready = ready;
        AcceptsWork = acceptsWork;
        ProductVersion = productVersion;
        SourceGeneration = sourceGeneration;
        ObservedAtUtc = observedAtUtc;
    }

    public AvailabilityFactState Installed { get; }
    public AvailabilityFactState Running { get; }
    public AvailabilityFactState Compatible { get; }
    public AvailabilityFactState Ready { get; }
    public AvailabilityFactState AcceptsWork { get; }
    public string? ProductVersion { get; }
    public string SourceGeneration { get; }
    public DateTimeOffset ObservedAtUtc { get; }

    internal bool IsUnspecified =>
        Installed == AvailabilityFactState.Unknown &&
        Running == AvailabilityFactState.Unknown &&
        Compatible == AvailabilityFactState.Unknown &&
        Ready == AvailabilityFactState.Unknown &&
        AcceptsWork == AvailabilityFactState.Unknown &&
        ProductVersion is null;
}

/// <summary>Owner-issued permission evidence preserved for a single principal and capability binding.</summary>
public sealed record AvailabilityPermissionEvidence
{
    private readonly string[] _constraints;
    private readonly IReadOnlyList<string> _constraintView;

    public AvailabilityPermissionEvidence(
        InstanceIdentity issuerOwner,
        string principalKey,
        string capabilityKey,
        AvailabilityPermissionDisposition disposition,
        string scopeKey,
        IEnumerable<string> constraints,
        DateTimeOffset validFromUtc,
        DateTimeOffset validUntilUtc,
        string sourceGeneration)
    {
        IssuerOwner = issuerOwner ?? throw new ArgumentNullException(nameof(issuerOwner));
        if (!AvailabilityEvidenceValidation.IsKey(principalKey) ||
            !AvailabilityEvidenceValidation.IsKey(capabilityKey) ||
            !AvailabilityEvidenceValidation.IsKey(scopeKey) ||
            !AvailabilityEvidenceValidation.IsKey(sourceGeneration))
        {
            throw new ArgumentException("Permission evidence must retain principal, capability, scope and source generation.");
        }

        AvailabilityEvidenceValidation.RequireDefined(disposition, nameof(disposition));
        ArgumentNullException.ThrowIfNull(constraints);
        _constraints = constraints.ToArray();
        if (_constraints.Length > 200 ||
            _constraints.Any(item => !AvailabilityEvidenceValidation.IsKey(item)) ||
            _constraints.Distinct(StringComparer.Ordinal).Count() != _constraints.Length)
        {
            throw new ArgumentException("Permission constraints must be a bounded, unique set of non-empty keys.", nameof(constraints));
        }

        AvailabilityEvidenceValidation.RequireUtc(validFromUtc, nameof(validFromUtc));
        AvailabilityEvidenceValidation.RequireUtc(validUntilUtc, nameof(validUntilUtc));
        if (validUntilUtc <= validFromUtc)
        {
            throw new ArgumentException("Permission evidence must retain a non-empty validity interval.", nameof(validUntilUtc));
        }

        PrincipalKey = principalKey;
        CapabilityKey = capabilityKey;
        Disposition = disposition;
        ScopeKey = scopeKey;
        _constraintView = Array.AsReadOnly(_constraints);
        ValidFromUtc = validFromUtc;
        ValidUntilUtc = validUntilUtc;
        SourceGeneration = sourceGeneration;
    }

    public InstanceIdentity IssuerOwner { get; }
    public string PrincipalKey { get; }
    public string CapabilityKey { get; }
    public AvailabilityPermissionDisposition Disposition { get; }
    public string ScopeKey { get; }
    public IReadOnlyList<string> Constraints => _constraintView;
    public DateTimeOffset ValidFromUtc { get; }
    public DateTimeOffset ValidUntilUtc { get; }
    public string SourceGeneration { get; }
}

/// <summary>Explicit owner-produced permission disposition; this projection does not grant or authorize.</summary>
public enum AvailabilityPermissionDisposition
{
    Unknown = 0,
    Granted = 1,
    Required = 2,
}

/// <summary>Entitlement evidence preserves the producer reason and version instead of recomputing entitlement.</summary>
public sealed record AvailabilityEntitlementEvidence
{
    public AvailabilityEntitlementEvidence(
        string capabilityKey,
        AvailabilityEntitlementDisposition disposition,
        string reasonCode,
        string producerVersion,
        string sourceGeneration)
    {
        if (!AvailabilityEvidenceValidation.IsKey(capabilityKey) ||
            !AvailabilityEvidenceValidation.IsKey(reasonCode) ||
            !AvailabilityEvidenceValidation.IsKey(producerVersion) ||
            !AvailabilityEvidenceValidation.IsKey(sourceGeneration))
        {
            throw new ArgumentException("Entitlement evidence must retain its capability, reason, producer version and source generation.");
        }

        AvailabilityEvidenceValidation.RequireDefined(disposition, nameof(disposition));
        CapabilityKey = capabilityKey;
        Disposition = disposition;
        ReasonCode = reasonCode;
        ProducerVersion = producerVersion;
        SourceGeneration = sourceGeneration;
    }

    public string CapabilityKey { get; }
    public AvailabilityEntitlementDisposition Disposition { get; }
    public string ReasonCode { get; }
    public string ProducerVersion { get; }
    public string SourceGeneration { get; }
}

/// <summary>Whether an entitlement producer explicitly reports that the capability is covered.</summary>
public enum AvailabilityEntitlementDisposition
{
    Unknown = 0,
    Satisfied = 1,
    Required = 2,
}

/// <summary>Explicit policy input supplied by the trusted host; this value is not a policy engine.</summary>
public sealed record AvailabilityPolicyEvidence
{
    public AvailabilityPolicyEvidence(
        AvailabilityPolicyDisposition disposition,
        string sourceKey,
        string revision)
    {
        AvailabilityEvidenceValidation.RequireDefined(disposition, nameof(disposition));
        if (!AvailabilityEvidenceValidation.IsKey(sourceKey) ||
            !AvailabilityEvidenceValidation.IsKey(revision))
        {
            throw new ArgumentException("Policy evidence must identify its authorized source and revision.");
        }

        Disposition = disposition;
        SourceKey = sourceKey;
        Revision = revision;
    }

    public AvailabilityPolicyDisposition Disposition { get; }
    public string SourceKey { get; }
    public string Revision { get; }
}

/// <summary>A host-provided policy fact; unknown policy never produces Available.</summary>
public enum AvailabilityPolicyDisposition
{
    Unknown = 0,
    Enabled = 1,
    Disabled = 2,
}

/// <summary>One immutable evidence row, bound to exactly one action/capability/target triple.</summary>
public sealed record AvailabilityEvidenceRecord
{
    public AvailabilityEvidenceRecord(
        ActionKey actionKey,
        string capabilityKey,
        AvailabilityTargetKey targetKey,
        AvailabilityTargetFacts targetFacts,
        AvailabilityPermissionEvidence permission,
        AvailabilityEntitlementEvidence entitlement,
        AvailabilityPolicyEvidence policy)
    {
        ActionKey = actionKey ?? throw new ArgumentNullException(nameof(actionKey));
        if (!AvailabilityEvidenceValidation.IsKey(capabilityKey))
        {
            throw new ArgumentException("A capability evidence row requires a valid capability key.", nameof(capabilityKey));
        }

        TargetKey = targetKey ?? throw new ArgumentNullException(nameof(targetKey));
        TargetFacts = targetFacts ?? throw new ArgumentNullException(nameof(targetFacts));
        Permission = permission ?? throw new ArgumentNullException(nameof(permission));
        Entitlement = entitlement ?? throw new ArgumentNullException(nameof(entitlement));
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        if (Permission.CapabilityKey != capabilityKey || Entitlement.CapabilityKey != capabilityKey)
        {
            throw new ArgumentException("Permission and entitlement facts must bind the evidence row's exact capability key.");
        }

        CapabilityKey = capabilityKey;
    }

    public ActionKey ActionKey { get; }
    public string CapabilityKey { get; }
    public AvailabilityTargetKey TargetKey { get; }
    public AvailabilityTargetFacts TargetFacts { get; }
    public AvailabilityPermissionEvidence Permission { get; }
    public AvailabilityEntitlementEvidence Entitlement { get; }
    public AvailabilityPolicyEvidence Policy { get; }
}

/// <summary>
/// Immutable evidence captured by a trusted host for one short-lived UI enumeration. Freshness is precomputed
/// by the host; evaluation never reads a clock or performs I/O.
/// </summary>
public sealed class AvailabilityEvidenceSnapshot
{
    private readonly AvailabilityEvidenceRecord[] _records;
    private readonly IReadOnlyList<AvailabilityEvidenceRecord> _recordView;
    private readonly Dictionary<(string ActionKey, string CapabilityKey), AvailabilityEvidenceRecord> _byActionCapability;

    public AvailabilityEvidenceSnapshot(
        AvailabilityProviderScope scope,
        DateTimeOffset asOfUtc,
        AvailabilityFreshnessDisposition freshness,
        IEnumerable<AvailabilityEvidenceRecord> records)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        AvailabilityEvidenceValidation.RequireUtc(asOfUtc, nameof(asOfUtc));
        AvailabilityEvidenceValidation.RequireDefined(freshness, nameof(freshness));
        ArgumentNullException.ThrowIfNull(records);
        _records = records.ToArray();
        if (_records.Any(record => record is null))
        {
            throw new ArgumentException("Availability evidence cannot contain null rows.", nameof(records));
        }

        _byActionCapability = new Dictionary<(string ActionKey, string CapabilityKey), AvailabilityEvidenceRecord>();
        foreach (var record in _records)
        {
            if (!_byActionCapability.TryAdd((record.ActionKey.Value, record.CapabilityKey), record))
            {
                throw new ArgumentException("Each action/capability binding must have exactly one target evidence row.", nameof(records));
            }

            if (record.Permission.IssuerOwner != Scope.Owner ||
                record.Permission.PrincipalKey != Scope.PrincipalKey)
            {
                throw new ArgumentException("Permission evidence must be issued for the bound owner and principal.", nameof(records));
            }

            if (record.TargetFacts.ObservedAtUtc > asOfUtc)
            {
                throw new ArgumentException("Target evidence cannot be observed after the fixed enumeration as-of time.", nameof(records));
            }
        }

        AsOfUtc = asOfUtc;
        // Permission lifetime is evaluated against the host's fixed as-of value here, before provider construction.
        // The UI evaluator consumes only this immutable disposition and never reads a clock.
        Freshness = freshness == AvailabilityFreshnessDisposition.Current &&
            _records.Any(record =>
                asOfUtc < record.Permission.ValidFromUtc ||
                asOfUtc >= record.Permission.ValidUntilUtc)
                ? AvailabilityFreshnessDisposition.StaleAtCapture
                : freshness;
        _recordView = Array.AsReadOnly(_records);
    }

    public AvailabilityProviderScope Scope { get; }
    public DateTimeOffset AsOfUtc { get; }
    public AvailabilityFreshnessDisposition Freshness { get; }
    public IReadOnlyList<AvailabilityEvidenceRecord> Records => _recordView;

    internal bool TryGet(string actionKey, string capabilityKey, out AvailabilityEvidenceRecord? record) =>
        _byActionCapability.TryGetValue((actionKey, capabilityKey), out record);
}

internal sealed record BoundCapabilityEvidence(
    CapabilityRegistration Capability,
    AvailabilityEvidenceRecord Evidence);

/// <summary>Pairs the generated Foundation action descriptor with its finite registered pure rule kind.</summary>
public sealed class ActionAvailabilityRegistration
{
    private const string StandardRuleKey = "capability.availability.v1";
    private readonly FoundationActionDescriptor _descriptor;
    private readonly string[] _capabilityKeys;
    private readonly IReadOnlyList<string> _capabilityKeyView;
    private readonly AvailabilityRuleKind _ruleKind;

    public ActionAvailabilityRegistration(FoundationActionDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        _descriptor = descriptor.Clone();
        if (!IsDescriptorKey(_descriptor.Key) || !_descriptor.HasKey ||
            !IsDescriptorKey(_descriptor.TitleKey) || !_descriptor.HasTitleKey ||
            !IsDescriptorKey(_descriptor.AvailabilityRule) || !_descriptor.HasAvailabilityRule)
        {
            throw new ArgumentException("Action descriptors require valid key, titleKey and availabilityRule values.", nameof(descriptor));
        }

        if (_descriptor.HasDescriptionKey && !IsDescriptorKey(_descriptor.DescriptionKey))
        {
            throw new ArgumentException("An action descriptionKey must be a valid contract identifier when present.", nameof(descriptor));
        }

        if (_descriptor.AcceptedContext.Count > 200 ||
            _descriptor.AcceptedContext.Any(item => !IsDescriptorKey(item)) ||
            _descriptor.AcceptedContext.Distinct(StringComparer.Ordinal).Count() != _descriptor.AcceptedContext.Count)
        {
            throw new ArgumentException("An action's acceptedContext values must be unique valid contract identifiers.", nameof(descriptor));
        }

        if (_descriptor.Capabilities.Count is < 1 or > 200 ||
            _descriptor.Capabilities.Any(item => !IsDescriptorKey(item)) ||
            _descriptor.Capabilities.Distinct(StringComparer.Ordinal).Count() != _descriptor.Capabilities.Count)
        {
            throw new ArgumentException("An action must bind 1–200 unique valid capability keys.", nameof(descriptor));
        }

        _ruleKind = _descriptor.AvailabilityRule switch
        {
            StandardRuleKey => AvailabilityRuleKind.Standard,
            _ => throw new ArgumentException("The action's availabilityRule is not in the private closed rule table.", nameof(descriptor)),
        };
        Key = new ActionKey(_descriptor.Key);
        _capabilityKeys = _descriptor.Capabilities.ToArray();
        _capabilityKeyView = Array.AsReadOnly(_capabilityKeys);
    }

    public ActionKey Key { get; }
    public IReadOnlyList<string> CapabilityKeys => _capabilityKeyView;

    /// <summary>Returns a clone of the generated Foundation descriptor; callers cannot mutate registration state.</summary>
    public FoundationActionDescriptor Descriptor => _descriptor.Clone();

    internal AvailabilityResult Evaluate(
        IReadOnlyList<BoundCapabilityEvidence> evidence,
        FrozenContextSnapshot context,
        AvailabilityFreshnessDisposition freshness)
    {
        if (_descriptor.AcceptedContext.Count > 0 &&
            !context.Items.Any(item => _descriptor.AcceptedContext.Contains(item.TypeName, StringComparer.Ordinal)))
        {
            return AvailabilityResult.NotApplicableToContext;
        }

        if (freshness != AvailabilityFreshnessDisposition.Current)
        {
            return AvailabilityResult.TemporarilyUnavailable;
        }

        return _ruleKind switch
        {
            AvailabilityRuleKind.Standard => EvaluateStandard(evidence),
            _ => AvailabilityResult.TemporarilyUnavailable,
        };
    }

    private static AvailabilityResult EvaluateStandard(IReadOnlyList<BoundCapabilityEvidence> evidence)
    {
        foreach (var binding in evidence)
        {
            var row = binding.Evidence;
            if (binding.Capability.Owner.CloudServiceIdentity is not null)
            {
                // Cloud catalogue entries are not local processes or CapabilityTargets.
                if (row.TargetKey.Kind != AvailabilityTargetKind.CloudSearchService ||
                    row.TargetKey.CloudService != binding.Capability.Owner.CloudServiceIdentity ||
                    !row.TargetFacts.IsUnspecified)
                {
                    return AvailabilityResult.TemporarilyUnavailable;
                }
            }
            else
            {
                var productOwner = binding.Capability.Owner.ProductApp;
                var productTarget = row.TargetKey.ProductInstance;
                if (productOwner is null ||
                    row.TargetKey.Kind != AvailabilityTargetKind.ProductInstance ||
                    productTarget is null ||
                    productTarget.Installation.App != productOwner)
                {
                    return AvailabilityResult.TemporarilyUnavailable;
                }

                var targetResult = EvaluateProductTarget(row.TargetFacts);
                if (targetResult != AvailabilityResult.Available)
                {
                    return targetResult;
                }
            }

            var permissionResult = row.Permission.Disposition switch
            {
                AvailabilityPermissionDisposition.Granted => AvailabilityResult.Available,
                AvailabilityPermissionDisposition.Required => AvailabilityResult.PermissionRequired,
                _ => AvailabilityResult.TemporarilyUnavailable,
            };
            if (permissionResult != AvailabilityResult.Available)
            {
                return permissionResult;
            }

            var entitlementResult = row.Entitlement.Disposition switch
            {
                AvailabilityEntitlementDisposition.Satisfied => AvailabilityResult.Available,
                AvailabilityEntitlementDisposition.Required => AvailabilityResult.EntitlementRequired,
                _ => AvailabilityResult.TemporarilyUnavailable,
            };
            if (entitlementResult != AvailabilityResult.Available)
            {
                return entitlementResult;
            }

            var policyResult = row.Policy.Disposition switch
            {
                AvailabilityPolicyDisposition.Enabled => AvailabilityResult.Available,
                AvailabilityPolicyDisposition.Disabled => AvailabilityResult.PolicyDisabled,
                _ => AvailabilityResult.TemporarilyUnavailable,
            };
            if (policyResult != AvailabilityResult.Available)
            {
                return policyResult;
            }
        }

        return AvailabilityResult.Available;
    }

    private static AvailabilityResult EvaluateProductTarget(AvailabilityTargetFacts facts)
    {
        if (facts.Installed == AvailabilityFactState.No)
        {
            return AvailabilityResult.AppNotInstalled;
        }

        if (facts.Installed != AvailabilityFactState.Yes)
        {
            return AvailabilityResult.TemporarilyUnavailable;
        }

        if (facts.Running == AvailabilityFactState.No)
        {
            return AvailabilityResult.AppNotRunning;
        }

        if (facts.Running != AvailabilityFactState.Yes)
        {
            return AvailabilityResult.TemporarilyUnavailable;
        }

        if (facts.Compatible == AvailabilityFactState.No)
        {
            return AvailabilityResult.IncompatibleVersion;
        }

        if (facts.Compatible != AvailabilityFactState.Yes ||
            facts.Ready != AvailabilityFactState.Yes ||
            facts.AcceptsWork != AvailabilityFactState.Yes)
        {
            return AvailabilityResult.TemporarilyUnavailable;
        }

        return AvailabilityResult.Available;
    }

    private static bool IsDescriptorKey(string value) => AvailabilityEvidenceValidation.IsKey(value);

    private enum AvailabilityRuleKind
    {
        Standard,
    }
}

/// <summary>Computes action availability from its static capability bindings and a frozen context snapshot.</summary>
public interface ICapabilityProvider
{
    /// <summary>Returns true only when the exact action catalogue row declares this capability.</summary>
    bool IsBoundToCapability(ActionKey actionKey, string capabilityKey);

    ValueTask<Outcome<AvailabilityResult>> EvaluateAvailabilityAsync(
        ActionKey actionKey,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Short-lived per-composition projection over a fixed catalogue and host-captured evidence. It performs no
/// discovery, I/O, authorization, clock reads, or mutable registration while UI code enumerates availability.
/// </summary>
public sealed class CapabilityAvailabilityProvider : ICapabilityProvider
{
    private readonly Dictionary<ActionKey, RegisteredAction> _actions;
    private readonly AvailabilityProviderScope _scope;
    private readonly AvailabilityFreshnessDisposition _freshness;

    public CapabilityAvailabilityProvider(
        CapabilityRegistry capabilities,
        IEnumerable<ActionAvailabilityRegistration> actions,
        AvailabilityProviderScope scope,
        AvailabilityEvidenceSnapshot evidenceSnapshot)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(actions);
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        ArgumentNullException.ThrowIfNull(evidenceSnapshot);
        if (evidenceSnapshot.Scope != scope)
        {
            throw new ArgumentException("Evidence owner, principal and session must exactly match the provider scope.", nameof(evidenceSnapshot));
        }

        _freshness = evidenceSnapshot.Freshness;
        var registered = new Dictionary<ActionKey, RegisteredAction>();
        var matchedRows = 0;
        foreach (var action in actions)
        {
            ArgumentNullException.ThrowIfNull(action);
            var bound = new List<BoundCapabilityEvidence>(action.CapabilityKeys.Count);
            foreach (var key in action.CapabilityKeys)
            {
                var capability = capabilities.Find(key);
                if (capability is null)
                {
                    throw new ArgumentException($"Action '{action.Key.Value}' references an unregistered capability '{key}'.", nameof(actions));
                }

                if (!evidenceSnapshot.TryGet(action.Key.Value, key, out var row) || row is null)
                {
                    throw new ArgumentException($"Action '{action.Key.Value}' is missing its exact evidence row for '{key}'.", nameof(evidenceSnapshot));
                }

                ValidateTargetBinding(capability, row);
                bound.Add(new BoundCapabilityEvidence(capability, row));
                matchedRows++;
            }

            var registration = new RegisteredAction(action, Array.AsReadOnly(bound.ToArray()));
            if (!registered.TryAdd(action.Key, registration))
            {
                throw new ArgumentException($"Action '{action.Key.Value}' is registered more than once.", nameof(actions));
            }
        }

        if (matchedRows != evidenceSnapshot.Records.Count)
        {
            throw new ArgumentException("The evidence snapshot contains an unknown or extra action/capability/target key.", nameof(evidenceSnapshot));
        }

        _actions = registered;
    }

    public bool IsBoundToCapability(ActionKey actionKey, string capabilityKey)
    {
        ArgumentNullException.ThrowIfNull(actionKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(capabilityKey);
        return _actions.TryGetValue(actionKey, out var registration) &&
            registration.Registration.CapabilityKeys.Contains(capabilityKey, StringComparer.Ordinal);
    }

    ValueTask<Outcome<AvailabilityResult>> ICapabilityProvider.EvaluateAvailabilityAsync(
        ActionKey actionKey,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken)
    {
        if (actionKey is null || context is null)
        {
            return Refuse("validation.invalid_request");
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (context.Owner != _scope.Owner)
        {
            return Refuse("validation.invalid_request");
        }

        if (!_actions.TryGetValue(actionKey, out var registration))
        {
            return Refuse("validation.invalid_request");
        }

        var result = registration.Registration.Evaluate(registration.Evidence, context, _freshness);
        return Enum.IsDefined(result)
            ? ValueTask.FromResult(Outcome.Success(result))
            : Refuse("internal.unexpected");
    }

    private static void ValidateTargetBinding(CapabilityRegistration capability, AvailabilityEvidenceRecord row)
    {
        if (capability.Owner.CloudServiceIdentity is not null)
        {
            if (capability.Owner.CloudServiceIdentity != SearchService.Instance ||
                row.TargetKey.Kind != AvailabilityTargetKind.CloudSearchService ||
                row.TargetKey.CloudService != capability.Owner.CloudServiceIdentity ||
                !row.TargetFacts.IsUnspecified)
            {
                throw new ArgumentException("Cloud catalogue evidence cannot become a local target or carry local-process facts.");
            }

            return;
        }

        var productOwner = capability.Owner.ProductApp;
        var productTarget = row.TargetKey.ProductInstance;
        if (productOwner is null ||
            row.TargetKey.Kind != AvailabilityTargetKind.ProductInstance ||
            productTarget is null ||
            productTarget.Installation.App != productOwner)
        {
            throw new ArgumentException("A product capability requires evidence for one exact instance of its closed product owner.");
        }
    }

    private static ValueTask<Outcome<AvailabilityResult>> Refuse(string code) =>
        ValueTask.FromResult(Outcome.Failure<AvailabilityResult>(TypedFailure.Create(code)));

    private sealed record RegisteredAction(
        ActionAvailabilityRegistration Registration,
        IReadOnlyList<BoundCapabilityEvidence> Evidence);
}

internal static class AvailabilityEvidenceValidation
{
    internal static bool IsKey(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 256 &&
        value.All(character => !char.IsControl(character));

    internal static void RequireDefined<TEnum>(TEnum value, string parameterName)
        where TEnum : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
    }

    internal static void RequireUtc(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Availability evidence timestamps must be UTC.", parameterName);
        }
    }
}
