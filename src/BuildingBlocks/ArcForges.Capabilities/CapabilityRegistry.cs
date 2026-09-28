// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Capabilities;

/// <summary>
/// Registration owner metadata is deliberately distinct from request scope and local installation
/// identity. Cloud service registrations are catalogue-only and can never identify a local target.
/// </summary>
public sealed record CapabilityOwner
{
    private CapabilityOwner(AppIdentity? productApp, SearchService? cloudService)
    {
        ProductApp = productApp;
        CloudServiceIdentity = cloudService;
    }

    public AppIdentity? ProductApp { get; }
    public SearchService? CloudServiceIdentity { get; }

    public static CapabilityOwner Product(AppIdentity app) =>
        new(app ?? throw new ArgumentNullException(nameof(app)), null);

    public static CapabilityOwner CloudService(SearchService service) =>
        new(null, service ?? throw new ArgumentNullException(nameof(service)));
}

/// <summary>The one Cloud service permitted in this static capability catalogue.</summary>
public sealed record SearchService
{
    private SearchService()
    {
    }

    public static SearchService Instance { get; } = new();
}

/// <summary>Closed first-party capability registration; protobuf values are never exposed mutably.</summary>
public sealed class CapabilityRegistration
{
    private readonly CapabilityDescriptor _descriptor;

    public CapabilityRegistration(CapabilityOwner owner, CapabilityDescriptor descriptor)
    {
        Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        ArgumentNullException.ThrowIfNull(descriptor);
        _descriptor = descriptor.Clone();
    }

    public CapabilityOwner Owner { get; }
    public string Key => _descriptor.Key;
    public CapabilityDescriptor Descriptor => _descriptor.Clone();

    internal CapabilityDescriptor SnapshotDescriptor() => _descriptor.Clone();
}

public enum CapabilityRegistryFailure
{
    DuplicateBinding,
    MissingBinding,
    UnexpectedBinding,
    UnsupportedMajor,
    InconsistentEffect,
    MetadataMismatch,
}

[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Design",
    "CA1032:Implement standard exception constructors",
    Justification = "Every instance must carry a typed registry failure and operation key; untyped standard constructors would violate that invariant.")]
public sealed class CapabilityRegistryException : InvalidOperationException
{
    public CapabilityRegistryException(CapabilityRegistryFailure failure, string capabilityKey, string message)
        : base(message)
    {
        Failure = failure;
        CapabilityKey = capabilityKey;
    }

    public CapabilityRegistryFailure Failure { get; }
    public string CapabilityKey { get; }
}

/// <summary>
/// Exact current first-party tool-eligible method set. No dynamic extension, infrastructure port,
/// or human-only approval method is admitted here. Cloud service entries are static catalogue
/// metadata, not local product targets.
/// </summary>
public sealed class CapabilityRegistry
{
    private const uint InitialContractMajor = 1;
    private const string ScopeService = "ScopeOperationsService";
    private const string ChatService = "ChatOperationsService";
    private const string ScopePackage = "arcforges.local.scope.v1";
    private const string ChatPackage = "arcforges.local.chat.v1";

    private readonly IReadOnlyDictionary<string, CapabilityRegistration> _registrations;

    private CapabilityRegistry(IEnumerable<CapabilityRegistration> registrations) =>
        _registrations = registrations.ToDictionary(item => item.Key, CloneRegistration, StringComparer.Ordinal);

    public static CapabilityRegistry CreateInitial() => ValidateInitial(CreateInitialRegistrations());

    public IReadOnlyList<CapabilityRegistration> Registrations =>
        Array.AsReadOnly(_registrations.Values
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .Select(CloneRegistration)
            .ToArray());

    public CapabilityRegistration? Find(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        return _registrations.TryGetValue(key, out var registration) ? CloneRegistration(registration) : null;
    }

    public static CapabilityRegistry ValidateInitial(IEnumerable<CapabilityRegistration> registrations)
    {
        ArgumentNullException.ThrowIfNull(registrations);
        var supplied = registrations.ToArray();
        if (supplied.Any(item => item is null))
        {
            throw new ArgumentException("Capability registries cannot contain null registrations.", nameof(registrations));
        }

        var duplicate = supplied.GroupBy(item => item.Key, StringComparer.Ordinal).FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
        {
            throw Failure(CapabilityRegistryFailure.DuplicateBinding, duplicate.Key, "A capability operation may be registered only once.");
        }

        var expected = CreateInitialRegistrations().ToDictionary(item => item.Key, StringComparer.Ordinal);
        var actual = new Dictionary<string, CapabilityRegistration>(StringComparer.Ordinal);
        foreach (var registration in supplied)
        {
            ArgumentNullException.ThrowIfNull(registration);
            var descriptor = registration.SnapshotDescriptor();
            ValidateDescriptorShape(descriptor);
            if (!expected.TryGetValue(registration.Key, out var canonical))
            {
                throw Failure(CapabilityRegistryFailure.UnexpectedBinding, registration.Key, "The operation is not in the current first-party capability matrix.");
            }

            if (registration.Owner != canonical.Owner || !descriptor.Equals(canonical.SnapshotDescriptor()))
            {
                throw Failure(CapabilityRegistryFailure.MetadataMismatch, registration.Key, "Capability owner, binding, risk, grant posture or execution metadata differs from the authored contract matrix.");
            }

            actual.Add(registration.Key, CloneRegistration(registration));
        }

        foreach (var missing in expected.Keys.Except(actual.Keys, StringComparer.Ordinal).OrderBy(key => key, StringComparer.Ordinal))
        {
            throw Failure(CapabilityRegistryFailure.MissingBinding, missing, "A required first-party method is missing from the capability registry.");
        }

        return new CapabilityRegistry(actual.Values);
    }

    internal static void ValidateTargetDescriptor(CapabilityDescriptor actual, CapabilityRegistration expected)
    {
        ValidateDescriptorShape(actual);
        if (!actual.Equals(expected.SnapshotDescriptor()))
        {
            throw Failure(CapabilityRegistryFailure.MetadataMismatch, actual.Key, "The target advertises a descriptor outside the compiled first-party binding matrix.");
        }
    }

    private static void ValidateDescriptorShape(CapabilityDescriptor descriptor)
    {
        if (!descriptor.HasCheckpoint)
        {
            throw Failure(CapabilityRegistryFailure.MetadataMismatch, descriptor.Key,
                "Every first-party descriptor must declare the authored checkpoint posture explicitly.");
        }

        if (descriptor.Binding.ContractMajor != InitialContractMajor)
        {
            throw Failure(CapabilityRegistryFailure.UnsupportedMajor, descriptor.Key, "The capability binding uses an unsupported Contracts major version.");
        }

        var pureRead = descriptor.Effect == EffectKind.PureRead;
        if (pureRead && (descriptor.Writes.Count != 0 || descriptor.Exclusive))
        {
            throw Failure(CapabilityRegistryFailure.InconsistentEffect, descriptor.Key, "A pureRead descriptor cannot write or require mutation exclusivity.");
        }

        if (!pureRead && (!descriptor.Exclusive || descriptor.Reads.Count != 0 || descriptor.Writes.Count != 0))
        {
            throw Failure(CapabilityRegistryFailure.InconsistentEffect, descriptor.Key, "An effectful descriptor must serialize at its owner; no unauthored fine-grained conflict keys are accepted.");
        }
    }

    private static IEnumerable<CapabilityRegistration> CreateInitialRegistrations() =>
    [
        Product("IScopeOperations.ListSessions", AppIdentity.ArcScope, ScopeService, ScopePackage, "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead),
        Product("IScopeOperations.GetSession", AppIdentity.ArcScope, ScopeService, ScopePackage, "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead),
        Product("IScopeOperations.ListCaptures", AppIdentity.ArcScope, ScopeService, ScopePackage, "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead),
        Product("IScopeOperations.GetConfigurationSnapshot", AppIdentity.ArcScope, ScopeService, ScopePackage, "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead),
        Product("IScopeOperations.RunMeasurement", AppIdentity.ArcScope, ScopeService, ScopePackage, "R2", "perOperation", "none", "NI", RetryMode.Never, EffectKind.LocalWrite),
        Product("IScopeOperations.RunAnalysis", AppIdentity.ArcScope, ScopeService, ScopePackage, "R2", "perOperation", "none", "NI", RetryMode.Reconcile, EffectKind.LocalWrite, "IProductLifecycle.GetJob"),
        Product("IScopeOperations.CompareSessions", AppIdentity.ArcScope, ScopeService, ScopePackage, "R2", "none", "none", "NI", RetryMode.Never, EffectKind.LocalWrite),
        Product("IScopeOperations.CreateAnnotation", AppIdentity.ArcScope, ScopeService, ScopePackage, "R2", "perOperation", "none", "CC", RetryMode.SameCommand, EffectKind.LocalWrite),
        Product("IScopeOperations.CreateFinding", AppIdentity.ArcScope, ScopeService, ScopePackage, "R2", "perOperation", "none", "CC", RetryMode.SameCommand, EffectKind.LocalWrite),
        Product("IScopeOperations.GenerateReport", AppIdentity.ArcScope, ScopeService, ScopePackage, "R2", "perOperation", "none", "NI", RetryMode.Never, EffectKind.LocalWrite),
        Product("IScopeOperations.StartCapture", AppIdentity.ArcScope, ScopeService, ScopePackage, "R3", "perOperation", "none", "NI", RetryMode.Reconcile, EffectKind.ExternalWrite, "IScopeOperations.ListCaptures"),
        Product("IScopeOperations.StopCapture", AppIdentity.ArcScope, ScopeService, ScopePackage, "R3", "perOperation", "none", "IW", RetryMode.Reconcile, EffectKind.ExternalWrite, "IScopeOperations.ListCaptures"),
        Product("IScopeOperations.GetStructuredContext", AppIdentity.ArcScope, ScopeService, ScopePackage, "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead),
        Product("IChatOperations.ListConversations", AppIdentity.Companion, ChatService, ChatPackage, "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead),
        Product("IChatOperations.GetConversation", AppIdentity.Companion, ChatService, ChatPackage, "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead),
        Product("IChatOperations.CreateConversation", AppIdentity.Companion, ChatService, ChatPackage, "R2", "none", "none", "CC", RetryMode.SameCommand, EffectKind.LocalWrite),
        Product("IChatOperations.AppendUserMessage", AppIdentity.Companion, ChatService, ChatPackage, "R2", "none", "none", "AP", RetryMode.SameCommand, EffectKind.LocalWrite),
        Product("IChatOperations.StartAgentTurn", AppIdentity.Companion, ChatService, ChatPackage, "R2", "perPlanStep", "none", "NI", RetryMode.Reconcile, EffectKind.CloudWrite, "IProductLifecycle.GetJob"),
        Product("IChatOperations.OpenArtifact", AppIdentity.Companion, ChatService, ChatPackage, "R1", "none", "ownedContent", "NI", RetryMode.Never, EffectKind.LocalWrite),
        // Ordinary local/internal search has no egress. Optional external Web search is a
        // runtime source-consent branch and cannot be folded into this single static descriptor.
        Create(new(
            "search.query",
            CapabilityOwner.CloudService(SearchService.Instance),
            "SearchService",
            "arcforges.publicapi.v1",
            "R1",
            "none",
            "none",
            "Q",
            RetryMode.SameCommand,
            EffectKind.PureRead,
            Method: "Query",
            Protocol: BindingProtocol.PublicGrpc,
            Locality: ToolLocality.Cloud,
            Execution: ExecutionLocus.Cloud)),
    ];

    private static CapabilityRegistration Product(
        string operationId,
        AppIdentity owner,
        string service,
        string package,
        string risk,
        string approval,
        string egress,
        string idempotency,
        RetryMode retry,
        EffectKind effect,
        string? statusOperation = null) =>
        Create(new(operationId, CapabilityOwner.Product(owner), service, package, risk, approval,
            egress, idempotency, retry, effect, statusOperation));

    private static CapabilityRegistration Create(Spec spec)
    {
        var methodSeparator = spec.OperationId.LastIndexOf('.');
        var method = spec.Method ?? spec.OperationId[(methodSeparator + 1)..];
        var requestSchema = $"{spec.Package}.{spec.Service}{method}Request";
        var responseSchema = $"{spec.Package}.{spec.Service}{method}Response";
        var mutation = spec.Effect != EffectKind.PureRead;
        var descriptor = new CapabilityDescriptor
        {
            Key = spec.OperationId,
            Version = "1",
            RequestSchema = requestSchema,
            ResponseSchema = responseSchema,
            Risk = spec.Risk,
            Locality = spec.Locality,
            Idempotency = spec.Idempotency,
            Exclusive = mutation,
            Egress = spec.Egress,
            Approval = spec.Approval,
            Binding = new OperationBinding
            {
                OperationId = spec.OperationId,
                Protocol = spec.Protocol,
                Service = spec.Service,
                Method = method,
                ContractMajor = InitialContractMajor,
            },
            Execution = spec.Execution,
            Effect = spec.Effect,
            Retry = spec.Retry,
            Cancel = new CancelSupport
            {
                Accepted = true,
                BeforeDispatchOnly = true,
            },
            Checkpoint = false,
            Limits = new CapabilityLimits
            {
                MaxInputBytes = 262_144,
                MaxOutputBytes = 262_144,
                MaxDurationMs = 30_000,
                MaxConcurrency = mutation ? 1u : 4u,
                MaxContextItems = 50,
            },
        };

        if (spec.StatusOperation is not null)
        {
            descriptor.StatusOperation = spec.StatusOperation;
        }

        return new CapabilityRegistration(spec.Owner, descriptor);
    }

    private static CapabilityRegistration CloneRegistration(CapabilityRegistration registration) =>
        new(registration.Owner, registration.SnapshotDescriptor());

    private static CapabilityRegistryException Failure(CapabilityRegistryFailure failure, string key, string message) =>
        new(failure, key, message);

    private sealed record Spec(
        string OperationId,
        CapabilityOwner Owner,
        string Service,
        string Package,
        string Risk,
        string Approval,
        string Egress,
        string Idempotency,
        RetryMode Retry,
        EffectKind Effect,
        string? StatusOperation = null,
        string? Method = null,
        BindingProtocol Protocol = BindingProtocol.InProcess,
        ToolLocality Locality = ToolLocality.Device,
        ExecutionLocus Execution = ExecutionLocus.Device);
}

/// <summary>One observed owner instance and its current generated descriptor/readiness snapshot.</summary>
public sealed class CapabilityTarget
{
    private readonly CapabilityDescriptor _descriptor;

    public CapabilityTarget(InstanceIdentity identity, CapabilityDescriptor descriptor, InstanceHealth health, bool acceptsWork)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        ArgumentNullException.ThrowIfNull(descriptor);
        _descriptor = descriptor.Clone();
        Health = health;
        AcceptsWork = acceptsWork;
    }

    public InstanceIdentity Identity { get; }
    public InstanceHealth Health { get; }
    public bool AcceptsWork { get; }
    public CapabilityDescriptor Descriptor => _descriptor.Clone();

    internal CapabilityDescriptor SnapshotDescriptor() => _descriptor.Clone();
}

public enum CapabilitySelectionReason
{
    None,
    CapabilityNotRegistered,
    TargetUnavailable,
    IncompatibleVersion,
    NotReady,
    AmbiguousTarget,
    DescriptorMismatch,
    RetargetingDenied,
    WrongOwner,
    CloudServiceNotLocalTarget,
}

public sealed record CapabilitySelectionResult(
    CapabilityTarget? Target,
    CapabilitySelectionReason Reason,
    string Explanation,
    IReadOnlyList<string> ConsideredTargets)
{
    public bool IsSelected => Target is not null && Reason == CapabilitySelectionReason.None;
}

/// <summary>
/// Applies fixed target rules without process-order or installation fallback: captured identity,
/// explicit target, a single ready target, otherwise an explainable refusal.
/// </summary>
public static class CapabilitySelector
{
    public static CapabilitySelectionResult Select(
        CapabilityRegistry registry,
        string capabilityKey,
        IEnumerable<CapabilityTarget> targets,
        InstanceIdentity? capturedTarget = null,
        InstanceIdentity? explicitlySelectedTarget = null)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentException.ThrowIfNullOrWhiteSpace(capabilityKey);
        ArgumentNullException.ThrowIfNull(targets);

        var registration = registry.Find(capabilityKey);
        if (registration is null)
        {
            return Refuse(CapabilitySelectionReason.CapabilityNotRegistered,
                "The operation is not in the current first-party registry.", []);
        }

        if (registration.Owner.CloudServiceIdentity is not null)
        {
            return Refuse(CapabilitySelectionReason.CloudServiceNotLocalTarget,
                "A Cloud service catalogue entry is not a local target; the caller's request ApplicationScope remains independent.", []);
        }

        var productOwner = registration.Owner.ProductApp
            ?? throw new InvalidOperationException("The closed capability owner union contains an unsupported variant.");

        if (capturedTarget is not null && explicitlySelectedTarget is not null && capturedTarget != explicitlySelectedTarget)
        {
            return Refuse(CapabilitySelectionReason.RetargetingDenied,
                "An existing execution identity cannot be retargeted to a different application instance.", []);
        }

        var candidates = targets.ToArray();
        if (candidates.Any(target => target is null))
        {
            throw new ArgumentException("Capability target collections cannot contain null.", nameof(targets));
        }

        var matching = candidates
            .Where(target => target.Descriptor.Key == capabilityKey)
            .OrderBy(IdentityOrder, StringComparer.Ordinal)
            .ToArray();
        if (matching.GroupBy(target => target.Identity).Any(group => group.Count() > 1))
        {
            return Refuse(CapabilitySelectionReason.DescriptorMismatch,
                "A target identity was registered more than once in this selection snapshot.", matching.Select(IdentityOrder).ToArray());
        }
        if (matching.Any(target => target.Identity.Installation.App != productOwner))
        {
            var wrongOwner = matching.Where(target => target.Identity.Installation.App != productOwner)
                .Select(IdentityOrder).OrderBy(value => value, StringComparer.Ordinal).ToArray();
            return Refuse(CapabilitySelectionReason.WrongOwner,
                "The capability can execute only inside its declared product owner.", wrongOwner);
        }

        foreach (var target in matching)
        {
            try
            {
                CapabilityRegistry.ValidateTargetDescriptor(target.SnapshotDescriptor(), registration);
            }
            catch (CapabilityRegistryException exception) when (exception.Failure == CapabilityRegistryFailure.UnsupportedMajor)
            {
                return Refuse(CapabilitySelectionReason.IncompatibleVersion,
                    "The target does not advertise the supported contract major.", matching.Select(IdentityOrder).ToArray());
            }
            catch (CapabilityRegistryException)
            {
                return Refuse(CapabilitySelectionReason.DescriptorMismatch,
                    "The target's operation binding or authority metadata differs from the compiled descriptor.", matching.Select(IdentityOrder).ToArray());
            }
        }

        var requestedTarget = capturedTarget ?? explicitlySelectedTarget;
        if (requestedTarget is not null)
        {
            var exact = matching.SingleOrDefault(target => target.Identity == requestedTarget);
            if (exact is null)
            {
                return Refuse(CapabilitySelectionReason.TargetUnavailable,
                    "The captured or explicitly selected target is absent; another installation will not be substituted.", matching.Select(IdentityOrder).ToArray());
            }

            return IsReady(exact)
                ? Select(exact, capturedTarget is null
                    ? "The explicitly selected own-product target is ready and contract-compatible."
                    : "The previously captured execution target is retained exactly.", matching.Select(IdentityOrder).ToArray())
                : Refuse(CapabilitySelectionReason.NotReady,
                    ReadinessExplanation(exact), matching.Select(IdentityOrder).ToArray());
        }

        var eligible = matching.Where(IsReady).ToArray();
        if (eligible.Length == 1)
        {
            return Select(eligible[0], "Exactly one eligible own-product target is ready; no other installation is selected implicitly.", matching.Select(IdentityOrder).ToArray());
        }

        if (eligible.Length > 1)
        {
            return Refuse(CapabilitySelectionReason.AmbiguousTarget,
                "Multiple eligible own-product targets exist; the user must select the exact application instance.", eligible.Select(IdentityOrder).OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        return Refuse(CapabilitySelectionReason.NotReady,
            matching.Length == 0
                ? "No registered target owns this capability."
                : $"No matching target currently accepts work: {string.Join("; ", matching.Select(target => ReadinessExplanation(target)))}",
            matching.Select(IdentityOrder).ToArray());
    }

    private static bool IsReady(CapabilityTarget target) => target.Health == InstanceHealth.Ready && target.AcceptsWork;

    private static string ReadinessExplanation(CapabilityTarget target) =>
        !target.AcceptsWork
            ? "The exact target currently refuses new work."
            : $"The exact target health is {target.Health}; only ready targets accept a new invocation.";

    private static string IdentityOrder(CapabilityTarget target)
    {
        var identity = target.Identity;
        return string.Join('/',
            identity.Installation.App.ProductId,
            identity.Installation.DeviceId.Value.ToString("N"),
            identity.Installation.InstallationId.Value.ToString("N"),
            identity.InstanceId.Value.ToString("N"),
            identity.Epoch.ToString("D20", System.Globalization.CultureInfo.InvariantCulture));
    }

    private static CapabilitySelectionResult Select(CapabilityTarget target, string explanation, IReadOnlyList<string> considered) =>
        new(target, CapabilitySelectionReason.None, explanation, Array.AsReadOnly(considered.ToArray()));

    private static CapabilitySelectionResult Refuse(CapabilitySelectionReason reason, string explanation, IReadOnlyList<string> considered) =>
        new(null, reason, explanation, Array.AsReadOnly(considered.ToArray()));
}
