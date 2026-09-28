// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;

namespace ArcForges.Contributions;

/// <summary>
/// Static per-composition registration. The catalog is snapshotted and verified at construction;
/// runtime callers may bind handlers only to descriptors that were already present in that catalog.
/// </summary>
public sealed class ContributionRegistry<TOwner> where TOwner : class
{
    private readonly object gate = new();
    private readonly ApplicationComposition<TOwner> composition;
    private readonly IContributionRegistrationStore stateStore;
    private readonly Dictionary<string, ContributionDefinition> catalog;
    private readonly Dictionary<string, ContributionDefinition> definitions = new(StringComparer.Ordinal);

    public ContributionRegistry(ApplicationComposition<TOwner> composition,
        IContributionRegistrationStore stateStore,
        IContributionCatalog catalog)
    {
        this.composition = composition ?? throw new ArgumentNullException(nameof(composition));
        this.stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        this.catalog = SnapshotCatalog(catalog, composition.Identity.Installation.App.ProductId);
    }

    /// <summary>A stable ordinal snapshot of registered descriptors; handlers are never exposed as untyped objects.</summary>
    public IReadOnlyList<ContributionDefinition> Definitions
    {
        get
        {
            lock (gate)
            {
                return definitions.Values.OrderBy(value => value.Id, StringComparer.Ordinal).ToArray();
            }
        }
    }

    /// <summary>Binds a handler to one exact immutable catalog descriptor and owner composition.</summary>
    public ContributionRegistration<TOwner, TRequest, TResult> Register<TRequest, TResult>(
        ContributionDefinition definition,
        Func<TOwner, TRequest, CancellationToken, ValueTask<ArcForges.Foundation.Errors.Outcome<TResult>>> operation)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(operation);
        var declared = Validate(definition);

        lock (gate)
        {
            if (definitions.ContainsKey(declared.Id))
            {
                throw Failure(ContributionRegistrationFailure.DuplicateId,
                    "A contribution ID can be bound only once in an application composition.");
            }

            var handler = composition.Bind(operation);
            ContributionPersistenceResult persisted;
            try
            {
                persisted = stateStore.Add(composition.Identity.Installation, declared);
            }
            catch (ContributionPersistenceConflictException exception)
            {
                throw Failure(ContributionRegistrationFailure.PersistenceConflict,
                    "The durable contribution ID is already bound to different metadata.", exception);
            }

            if (persisted is not (ContributionPersistenceResult.Added or ContributionPersistenceResult.AlreadyPresent))
            {
                throw Failure(ContributionRegistrationFailure.PersistenceConflict,
                    "The owner store returned an unknown contribution persistence result.");
            }

            var registration = new ContributionRegistration<TOwner, TRequest, TResult>(
                composition, handler, declared, persisted);
            definitions.Add(declared.Id, declared);
            return registration;
        }
    }

    /// <summary>
    /// Refuses child-process registrations until a pinned generated contract and admitted host/grant
    /// boundary are connected. A child cannot become an in-process callback by metadata alone.
    /// </summary>
    public void RegisterChild(ContributionDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        throw Failure(ContributionRegistrationFailure.ChildUnavailable,
            "No admitted extension-child boundary is connected to this registration package.");
    }

    private ContributionDefinition Validate(ContributionDefinition definition)
    {
        var ownerProductId = composition.Identity.Installation.App.ProductId;
        if (!IsCanonicalKey(definition.Id) || definition.Kind is < ContributionKind.Capability or > ContributionKind.LifecycleHandler)
        {
            throw Failure(ContributionRegistrationFailure.InvalidDescriptor,
                "Contribution metadata must use a canonical ID and a known local kind.");
        }

        if (!string.Equals(definition.OwnerProductId, ownerProductId, StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.WrongOwner,
                "Contribution metadata must name the exact product that owns this composition.");
        }

        if (!definition.Id.StartsWith(ownerProductId + ".", StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.ForeignNamespace,
                "A product can register only in its own reserved contribution namespace.");
        }

        if (definition.ToolSchemaId is { } schema &&
            (definition.Kind != ContributionKind.Capability || !IsCanonicalKey(schema)))
        {
            throw Failure(ContributionRegistrationFailure.UndeclaredToolSchema,
                "A tool schema must be canonical and attached to a capability.");
        }

        if (!catalog.TryGetValue(definition.Id, out var declared))
        {
            throw Failure(definition.ToolSchemaId is null
                    ? ContributionRegistrationFailure.UndeclaredContribution
                    : ContributionRegistrationFailure.UndeclaredToolSchema,
                "The contribution descriptor is not present in the immutable owner catalog.");
        }

        if (!string.Equals(definition.OwnerProductId, declared.OwnerProductId, StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.WrongOwner,
                "The selected descriptor owner differs from the catalog owner.");
        }

        if (!string.Equals(definition.ToolSchemaId, declared.ToolSchemaId, StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.UndeclaredToolSchema,
                "The selected tool schema does not match the catalog-bound schema.");
        }

        if (definition.Kind != declared.Kind ||
            !string.Equals(definition.Fingerprint, declared.Fingerprint, StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.InvalidDescriptor,
                "The selected descriptor fingerprint does not match the immutable owner catalog.");
        }

        return declared;
    }

    private static Dictionary<string, ContributionDefinition> SnapshotCatalog(
        IContributionCatalog catalog,
        string expectedOwnerProductId)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        var ownerProductId = catalog.OwnerProductId;
        if (!string.Equals(ownerProductId, expectedOwnerProductId, StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.WrongOwner,
                "The contribution catalog must be bound to the exact product that owns this composition.");
        }

        var source = catalog.Descriptors;
        if (source is null)
        {
            throw Failure(ContributionRegistrationFailure.InvalidDescriptor,
                "The contribution catalog descriptor list is required.");
        }

        var descriptors = source.ToArray();
        var snapshot = new Dictionary<string, ContributionDefinition>(StringComparer.Ordinal);
        foreach (var descriptor in descriptors)
        {
            if (descriptor is null || !IsCanonicalKey(descriptor.Id) ||
                descriptor.Kind is < ContributionKind.Capability or > ContributionKind.LifecycleHandler)
            {
                throw Failure(ContributionRegistrationFailure.InvalidDescriptor,
                    "Catalog descriptors must use a canonical ID and a known local kind.");
            }

            if (!string.Equals(descriptor.OwnerProductId, ownerProductId, StringComparison.Ordinal))
            {
                throw Failure(ContributionRegistrationFailure.WrongOwner,
                    "Every catalog descriptor must name the catalog's exact owner product.");
            }

            if (!descriptor.Id.StartsWith(ownerProductId + ".", StringComparison.Ordinal))
            {
                throw Failure(ContributionRegistrationFailure.ForeignNamespace,
                    "Every catalog descriptor must use the catalog owner's reserved namespace.");
            }

            if (descriptor.ToolSchemaId is { } schema &&
                (descriptor.Kind != ContributionKind.Capability || !IsCanonicalKey(schema)))
            {
                throw Failure(ContributionRegistrationFailure.UndeclaredToolSchema,
                    "Catalog tool schemas must be canonical and bound to capability descriptors.");
            }

            if (!snapshot.TryAdd(descriptor.Id, descriptor))
            {
                throw Failure(ContributionRegistrationFailure.DuplicateId,
                    "An immutable contribution catalog cannot contain duplicate IDs.");
            }
        }

        var expectedFingerprint = ContributionCatalogFingerprint.Compute(ownerProductId, descriptors);
        if (!string.Equals(catalog.Fingerprint, expectedFingerprint, StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.InvalidDescriptor,
                "The contribution catalog fingerprint does not match its exact owner and descriptor set.");
        }

        return snapshot;
    }

    private static bool IsCanonicalKey(string value)
    {
        if (string.IsNullOrEmpty(value) || value[0] == '.' || value[^1] == '.') return false;
        var previousWasSeparator = true;
        foreach (var character in value)
        {
            var separator = character is '.' or '-';
            if (separator && previousWasSeparator) return false;
            if (!separator && !(character is >= 'a' and <= 'z' or >= '0' and <= '9')) return false;
            previousWasSeparator = separator;
        }
        return !previousWasSeparator;
    }

    private static ContributionRegistrationException Failure(ContributionRegistrationFailure failure,
        string message, Exception? inner = null) => new(failure, message, inner);
}
