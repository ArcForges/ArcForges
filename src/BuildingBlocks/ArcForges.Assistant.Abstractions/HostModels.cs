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

/// <summary>Clone-on-entry/exit wrapper over the published Foundation resource reference.</summary>
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

        _reference = reference.Clone();
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
        ArgumentException.ThrowIfNullOrWhiteSpace(labelKey);
        if (labelKey.Length > 160 || labelKey.Any(char.IsControl))
        {
            throw new ArgumentException("A bounded localization key is required.", nameof(labelKey));
        }

        Id = id;
        Resource = new AssistantResourceReference(resource.ToWire());
        LabelKey = labelKey;
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

public sealed class FrozenHostContext
{
    private readonly ImmutableArray<HostContextSelection> _included;
    private readonly ImmutableArray<ContextSelectionId> _excluded;

    public FrozenHostContext(AssistantHostIdentity owner, IEnumerable<HostContextSelection> included,
        IEnumerable<ContextSelectionId>? excluded = null)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(included);
        Owner = owner;
        _included = included.Select(static item => new HostContextSelection(item.Id, item.Resource, item.LabelKey,
            item.ApproximateItemCount, item.EstimatedBytes)).ToImmutableArray();
        _excluded = (excluded ?? []).Distinct().ToImmutableArray();
        if (_included.Select(static item => item.Id).Distinct().Count() != _included.Length ||
            _excluded.Any(id => _included.Any(item => item.Id == id)))
        {
            throw new ArgumentException("A frozen context must contain unique, disjoint selection identifiers.", nameof(included));
        }
    }

    public AssistantHostIdentity Owner { get; }
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

public sealed record ActionAvailability
{
    public ActionAvailability(bool isAvailable, string? reasonKey = null)
    {
        if (reasonKey is { Length: > 160 } || reasonKey?.Any(char.IsControl) == true)
        {
            throw new ArgumentException("A bounded availability reason key is required.", nameof(reasonKey));
        }

        if (isAvailable && reasonKey is not null)
        {
            throw new ArgumentException("An available action cannot carry an unavailable reason.", nameof(reasonKey));
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

public sealed record AssistantAttention(string AttentionId, string MessageKey, DateTimeOffset CreatedAt);

public sealed record AssistantShutdownSummary(bool CanClose, int ActiveLocalOperations,
    IReadOnlyList<string> RefusalMessageKeys);

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

public sealed record ResolvedHostResource(AssistantResourceReference Reference, HostResourceReadGrant? ReadGrant,
    string AvailabilityKey);

public sealed record HostPreview(AssistantResourceReference Reference, HostPreviewMode Mode, string PreviewKey);

public sealed record HostSaveReceipt(Guid GrantId, AssistantResourceReference SavedResource);

public sealed record AssistantAttentionRequest(string AttentionId, string MessageKey);

public enum HostThemeMode
{
    None = 0,
    System = 1,
    Light = 2,
    Dark = 3,
    HighContrast = 4,
}

public sealed record HostAccessibilityPreferences(bool ReduceMotion, bool ScreenReader, double TextScale);

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
    internal string PlatformDataRoot => DataRoot.Path;
    public string DisplayName { get; }
    public string IconResourceKey { get; }
    public IReadOnlyList<AssistantPresentationMode> AvailablePresentationModes => _presentationModes;

    public bool Supports(AssistantPresentationMode mode) => _presentationModes.Contains(mode);
}
