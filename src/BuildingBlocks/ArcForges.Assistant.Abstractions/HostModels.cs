// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Assistant.Abstractions;

public enum AssistantPresentationMode
{
    None = 0,
    Docked = 1,
    Floating = 2,
    Expanded = 3,
}

public enum AssistantHistoryMode
{
    None = 0,
    Ephemeral = 1,
    Local = 2,
    CloudSynced = 3,
}

public enum HostPreviewMode
{
    None = 0,
    Inline = 1,
    Expanded = 2,
    MetadataOnly = 3,
}

public readonly record struct AssistantWindowId
{
    public AssistantWindowId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Window identity must be initialized.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
    public static AssistantWindowId New() => new(Guid.NewGuid());
}

public readonly record struct AssistantConversationId
{
    public AssistantConversationId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Conversation identity must be initialized.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
    public static AssistantConversationId New() => new(Guid.NewGuid());
}

public readonly record struct ContextSelectionId
{
    public ContextSelectionId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Context selection identity must be initialized.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
    public static ContextSelectionId New() => new(Guid.NewGuid());
}

/// <summary>
/// Clone-on-entry/exit wrapper over the published Foundation resource reference. Construction validates that
/// the reference names a supported product owner, a kind namespaced by that owner, a typed revision and a
/// SHA-256 content hash, so a malformed or ownerless reference never reaches a host port.
/// </summary>
public sealed class AssistantResourceReference
{
    private readonly ResourceVersionRef _reference;

    public AssistantResourceReference(ResourceVersionRef reference)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (reference.Resource is null || reference.RevisionCase == ResourceVersionRef.RevisionOneofCase.None)
        {
            throw new ArgumentException("A resource reference and a typed revision are required.", nameof(reference));
        }

        var resource = reference.Resource;
        AssistantProductIdentity owner;
        try
        {
            owner = AssistantProductIdentity.Parse(resource.OwnerAppId);
        }
        catch (ArgumentException)
        {
            throw new ArgumentException("The resource owner must be a supported product identity.", nameof(reference));
        }

        if (!resource.ResourceKind.StartsWith(owner.ProductId + ".", StringComparison.Ordinal) ||
            resource.ResourceKind.Length == owner.ProductId.Length + 1 || resource.ResourceKind.Length > 128)
        {
            throw new ArgumentException("The resource kind must be namespaced by its owning product.", nameof(reference));
        }

        if (!reference.HasContentHash || reference.ContentHash.Length != 64 ||
            !reference.ContentHash.All(static character => character is >= 'a' and <= 'f' or >= '0' and <= '9'))
        {
            throw new ArgumentException("A lowercase SHA-256 content hash is required.", nameof(reference));
        }

        Owner = owner;
        _reference = reference.Clone();
    }

    /// <summary>The product that owns the resource; hosts act only on their own product's resources.</summary>
    public AssistantProductIdentity Owner { get; }

    public bool IsOwnedBy(AssistantProductIdentity product)
    {
        ArgumentNullException.ThrowIfNull(product);
        return Owner == product;
    }

    public ResourceVersionRef ToWire() => _reference.Clone();
}

/// <summary>One explicitly selected, revision-bound resource; it never contains bytes or a path.</summary>
public sealed record HostContextSelection
{
    public HostContextSelection(ContextSelectionId id, AssistantResourceReference resource, string labelKey,
        uint approximateItemCount, ulong estimatedBytes)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException("Context selection identity must be initialized.", nameof(id));
        }

        ArgumentNullException.ThrowIfNull(resource);
        Id = id;
        Resource = new AssistantResourceReference(resource.ToWire());
        LabelKey = HostKeys.Require(labelKey, nameof(labelKey));
        ApproximateItemCount = approximateItemCount;
        EstimatedBytes = estimatedBytes;
    }

    public ContextSelectionId Id { get; }
    public AssistantResourceReference Resource { get; }
    public string LabelKey { get; }
    public uint ApproximateItemCount { get; }
    public ulong EstimatedBytes { get; }
}

public sealed record AssistantContextBudget
{
    public const ulong AbsoluteMaximumBytes = 64UL * 1024 * 1024;
    public const int AbsoluteMaximumItems = 128;

    public AssistantContextBudget(int maximumItems, ulong maximumBytes)
    {
        if (maximumItems is < 1 or > AbsoluteMaximumItems)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumItems), $"Context item limit must be between 1 and {AbsoluteMaximumItems}.");
        }

        if (maximumBytes is 0 or > AbsoluteMaximumBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes), $"Context byte limit must be between 1 and {AbsoluteMaximumBytes}.");
        }

        MaximumItems = maximumItems;
        MaximumBytes = maximumBytes;
    }

    public int MaximumItems { get; }
    public ulong MaximumBytes { get; }
}

/// <summary>
/// Immutable authorized context. It can only be constructed within a budget, only from the owning product's own
/// resources, and never changes after a turn has been submitted from it.
/// </summary>
public sealed class FrozenHostContext
{
    private readonly ImmutableArray<HostContextSelection> _included;
    private readonly ImmutableArray<ContextSelectionId> _excluded;

    public FrozenHostContext(AssistantHostIdentity owner, AssistantContextBudget budget,
        IEnumerable<HostContextSelection> included, IEnumerable<ContextSelectionId>? excluded = null)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(budget);
        ArgumentNullException.ThrowIfNull(included);
        Owner = owner;
        Budget = budget;
        _included = included.Select(static item => new HostContextSelection(item.Id, item.Resource, item.LabelKey,
            item.ApproximateItemCount, item.EstimatedBytes)).ToImmutableArray();
        _excluded = (excluded ?? []).Distinct().ToImmutableArray();
        if (_included.Select(static item => item.Id).Distinct().Count() != _included.Length ||
            _excluded.Any(id => _included.Any(item => item.Id == id)))
        {
            throw new ArgumentException("A frozen context must contain unique, disjoint selection identifiers.", nameof(included));
        }

        if (_included.Any(item => !item.Resource.IsOwnedBy(owner.Product)))
        {
            throw new ArgumentException("A frozen context may contain only the owning product's resources.", nameof(included));
        }

        if (_included.Length > budget.MaximumItems)
        {
            throw new ArgumentException("The frozen context exceeds the item budget.", nameof(included));
        }

        UInt128 total = 0;
        foreach (var item in _included)
        {
            total += item.EstimatedBytes;
        }

        if (total > budget.MaximumBytes)
        {
            throw new ArgumentException("The frozen context exceeds the byte budget.", nameof(included));
        }

        TotalEstimatedBytes = (ulong)total;
    }

    public AssistantHostIdentity Owner { get; }
    public AssistantContextBudget Budget { get; }
    public ulong TotalEstimatedBytes { get; }
    public bool IsPartial => !_excluded.IsEmpty;
    public IReadOnlyList<HostContextSelection> Included => _included;
    public IReadOnlyList<ContextSelectionId> Excluded => _excluded;
}

/// <summary>
/// Runtime-only projection of an action descriptor. It is an in-process composition value, not a second
/// Contracts wire model; the owning product binds it to its generated, admitted descriptor at registration.
/// </summary>
public sealed record AssistantActionDescriptor
{
    public AssistantActionDescriptor(string operationId, string titleKey, string descriptionKey,
        IEnumerable<string> acceptedContextKeys, IEnumerable<string> requiredCapabilities, string availabilityRule)
    {
        OperationId = RequireKey(operationId, nameof(operationId));
        TitleKey = RequireKey(titleKey, nameof(titleKey));
        DescriptionKey = RequireKey(descriptionKey, nameof(descriptionKey));
        AvailabilityRule = RequireKey(availabilityRule, nameof(availabilityRule));
        ArgumentNullException.ThrowIfNull(acceptedContextKeys);
        ArgumentNullException.ThrowIfNull(requiredCapabilities);
        AcceptedContextKeys = CopyKeys(acceptedContextKeys, nameof(acceptedContextKeys));
        RequiredCapabilities = CopyKeys(requiredCapabilities, nameof(requiredCapabilities));
    }

    public string OperationId { get; }
    public string TitleKey { get; }
    public string DescriptionKey { get; }
    public ImmutableArray<string> AcceptedContextKeys { get; }
    public ImmutableArray<string> RequiredCapabilities { get; }
    public string AvailabilityRule { get; }

    private static string RequireKey(string value, string parameter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameter);
        if (value.Length > 160 || value.Any(static character => char.IsControl(character) || char.IsWhiteSpace(character) ||
                !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-')))
        {
            throw new ArgumentException("A bounded lowercase descriptor key is required.", parameter);
        }

        return value;
    }

    private static ImmutableArray<string> CopyKeys(IEnumerable<string> values, string parameter)
    {
        var keys = values.Select(value => RequireKey(value, parameter)).ToImmutableArray();
        if (keys.Distinct(StringComparer.Ordinal).Count() != keys.Length)
        {
            throw new ArgumentException("Descriptor keys must be unique.", parameter);
        }

        return keys;
    }
}

/// <summary>An action is either available, or unavailable with a visible localization reason.</summary>
public sealed record ActionAvailability
{
    public ActionAvailability(bool isAvailable, string? reasonKey = null)
    {
        if (isAvailable && reasonKey is not null)
        {
            throw new ArgumentException("An available action cannot carry an unavailable reason.", nameof(reasonKey));
        }

        if (!isAvailable)
        {
            reasonKey = HostKeys.Require(reasonKey, nameof(reasonKey));
        }

        IsAvailable = isAvailable;
        ReasonKey = reasonKey;
    }

    public bool IsAvailable { get; }
    public string? ReasonKey { get; }
}

public sealed record AssistantSurfaceRequest(AssistantPresentationMode Mode, AssistantWindowId Window,
    AssistantConversationId? Conversation = null);

public sealed record AssistantSurfaceHandle(AssistantPresentationMode Mode, AssistantWindowId Window,
    AssistantConversationId? Conversation = null);

/// <summary>Bounded localization/identifier key rules shared by every host value that crosses into UI code.</summary>
internal static class HostKeys
{
    internal const int MaximumLength = 160;

    internal static string Require(string? value, string parameter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameter);
        if (value.Length > MaximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("A bounded key without control characters is required.", parameter);
        }

        return value;
    }
}

/// <summary>An attention item addressed by a bounded identifier and a localization key; never free text.</summary>
public sealed record AssistantAttention
{
    public AssistantAttention(string attentionId, string messageKey, DateTimeOffset createdAt)
    {
        AttentionId = HostKeys.Require(attentionId, nameof(attentionId));
        MessageKey = HostKeys.Require(messageKey, nameof(messageKey));
        CreatedAt = createdAt;
    }

    public string AttentionId { get; }
    public string MessageKey { get; }
    public DateTimeOffset CreatedAt { get; }
}

/// <summary>
/// Outcome of preparing to quit. A summary that allows closing carries no refusals, and one that refuses
/// carries at least one localization key, so shutdown can never be silently refused or silently forced.
/// </summary>
public sealed record AssistantShutdownSummary
{
    public AssistantShutdownSummary(bool canClose, int activeLocalOperations, IEnumerable<string> refusalMessageKeys)
    {
        ArgumentNullException.ThrowIfNull(refusalMessageKeys);
        ArgumentOutOfRangeException.ThrowIfNegative(activeLocalOperations);
        var keys = refusalMessageKeys.Select(key => HostKeys.Require(key, nameof(refusalMessageKeys))).ToImmutableArray();
        if (canClose && !keys.IsEmpty)
        {
            throw new ArgumentException("A shutdown that can close cannot carry refusal reasons.", nameof(refusalMessageKeys));
        }

        if (!canClose && keys.IsEmpty)
        {
            throw new ArgumentException("A refused shutdown requires at least one reason.", nameof(refusalMessageKeys));
        }

        CanClose = canClose;
        ActiveLocalOperations = activeLocalOperations;
        RefusalMessageKeys = keys;
    }

    public bool CanClose { get; }
    public int ActiveLocalOperations { get; }
    public IReadOnlyList<string> RefusalMessageKeys { get; }
}

public readonly record struct HostByteRange
{
    public HostByteRange(long offset, long? length)
    {
        if (offset < 0 || length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), "A byte range must be non-negative.");
        }

        Offset = offset;
        Length = length;
    }

    public long Offset { get; }
    public long? Length { get; }
}

public sealed record HostFileGrant
{
    public HostFileGrant(AssistantHostIdentity owner, Guid grantId, bool canRead, bool canWrite)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if (grantId == Guid.Empty || (!canRead && !canWrite))
        {
            throw new ArgumentException("A non-empty, permissioned host file grant is required.", nameof(grantId));
        }

        Owner = owner;
        GrantId = grantId;
        CanRead = canRead;
        CanWrite = canWrite;
    }

    public AssistantHostIdentity Owner { get; }
    public Guid GrantId { get; }
    public bool CanRead { get; }
    public bool CanWrite { get; }
}

public sealed record HostResourceReadGrant
{
    public HostResourceReadGrant(AssistantHostIdentity owner, Guid grantId, AssistantResourceReference resource)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(resource);
        if (grantId == Guid.Empty)
        {
            throw new ArgumentException("Resource grants require a non-empty grant identity.", nameof(grantId));
        }

        Owner = owner;
        GrantId = grantId;
        Resource = new AssistantResourceReference(resource.ToWire());
    }

    public AssistantHostIdentity Owner { get; }
    public Guid GrantId { get; }
    public AssistantResourceReference Resource { get; }
}

/// <summary>A resolved reference; a read grant, when present, is bound to exactly this resource.</summary>
public sealed record ResolvedHostResource
{
    public ResolvedHostResource(AssistantResourceReference reference, HostResourceReadGrant? readGrant, string availabilityKey)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (readGrant is not null && !readGrant.Resource.ToWire().Equals(reference.ToWire()))
        {
            throw new ArgumentException("A read grant must be bound to the resolved resource.", nameof(readGrant));
        }

        Reference = reference;
        ReadGrant = readGrant;
        AvailabilityKey = HostKeys.Require(availabilityKey, nameof(availabilityKey));
    }

    public AssistantResourceReference Reference { get; }
    public HostResourceReadGrant? ReadGrant { get; }
    public string AvailabilityKey { get; }
}

public sealed record HostPreview
{
    public HostPreview(AssistantResourceReference reference, HostPreviewMode mode, string previewKey)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (!Enum.IsDefined(mode) || mode == HostPreviewMode.None)
        {
            throw new ArgumentOutOfRangeException(nameof(mode), "A known preview mode is required.");
        }

        Reference = reference;
        Mode = mode;
        PreviewKey = HostKeys.Require(previewKey, nameof(previewKey));
    }

    public AssistantResourceReference Reference { get; }
    public HostPreviewMode Mode { get; }
    public string PreviewKey { get; }
}

public sealed record HostSaveReceipt
{
    public HostSaveReceipt(Guid grantId, AssistantResourceReference savedResource)
    {
        ArgumentNullException.ThrowIfNull(savedResource);
        if (grantId == Guid.Empty)
        {
            throw new ArgumentException("A save receipt names the destination grant that was used.", nameof(grantId));
        }

        GrantId = grantId;
        SavedResource = savedResource;
    }

    public Guid GrantId { get; }
    public AssistantResourceReference SavedResource { get; }
}

public sealed record AssistantAttentionRequest
{
    public AssistantAttentionRequest(string attentionId, string messageKey)
    {
        AttentionId = HostKeys.Require(attentionId, nameof(attentionId));
        MessageKey = HostKeys.Require(messageKey, nameof(messageKey));
    }

    public string AttentionId { get; }
    public string MessageKey { get; }
}

public enum HostThemeMode
{
    None = 0,
    System = 1,
    Light = 2,
    Dark = 3,
    HighContrast = 4,
}

public sealed record HostAccessibilityPreferences
{
    public const double MinimumTextScale = 0.5;
    public const double MaximumTextScale = 4.0;

    public HostAccessibilityPreferences(bool reduceMotion, bool screenReader, double textScale)
    {
        if (!double.IsFinite(textScale) || textScale is < MinimumTextScale or > MaximumTextScale)
        {
            throw new ArgumentOutOfRangeException(nameof(textScale), "Text scale must be a finite value within the supported range.");
        }

        ReduceMotion = reduceMotion;
        ScreenReader = screenReader;
        TextScale = textScale;
    }

    public bool ReduceMotion { get; }
    public bool ScreenReader { get; }
    public double TextScale { get; }
}

/// <summary>
/// Immutable, validated application host settings. The product-specific data root is derived here rather
/// than accepted as a product-selected path.
/// </summary>
public sealed class AssistantHostOptions
{
    private readonly ImmutableArray<AssistantPresentationMode> _presentationModes;

    public AssistantHostOptions(AssistantHostIdentity identity, AssistantProfileId initialProfile,
        string platformDataRoot, string displayName, string iconResourceKey,
        IEnumerable<AssistantPresentationMode> availablePresentationModes)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (initialProfile.Value == Guid.Empty)
        {
            throw new ArgumentException("An initialized profile is required.", nameof(initialProfile));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(iconResourceKey);
        ArgumentNullException.ThrowIfNull(availablePresentationModes);
        if (displayName.Length > 120 || displayName.Any(char.IsControl))
        {
            throw new ArgumentException("A bounded display name is required.", nameof(displayName));
        }

        if (iconResourceKey.Length > 160 || iconResourceKey.Any(char.IsControl) ||
            iconResourceKey.Contains(':', StringComparison.Ordinal))
        {
            throw new ArgumentException("An icon must be an owned resource key, not a URI or file path.", nameof(iconResourceKey));
        }

        var modes = availablePresentationModes.ToImmutableArray();
        if (modes.IsEmpty || modes.Any(static mode => !Enum.IsDefined(mode) || mode == AssistantPresentationMode.None) ||
            modes.Distinct().Count() != modes.Length)
        {
            throw new ArgumentException("At least one unique, known presentation mode is required.", nameof(availablePresentationModes));
        }

        Identity = identity;
        InitialProfile = initialProfile;
        DataRoot = AssistantDataRoot.ForApplication(platformDataRoot, identity.Installation);
        DisplayName = displayName;
        IconResourceKey = iconResourceKey;
        _presentationModes = modes;
    }

    public AssistantHostIdentity Identity { get; }
    public AssistantProductIdentity Product => Identity.Product;
    public AssistantProfileId InitialProfile { get; }
    public AssistantStorePartition InitialStorePartition => DataRoot.ForProfile(InitialProfile);
    public AssistantDataRoot DataRoot { get; }
    public string DisplayName { get; }
    public string IconResourceKey { get; }
    public IReadOnlyList<AssistantPresentationMode> AvailablePresentationModes => _presentationModes;

    public bool Supports(AssistantPresentationMode mode) => _presentationModes.Contains(mode);
}
