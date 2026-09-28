// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;

namespace ArcForges.Contributions;

/// <summary>
/// Static per-composition registration. It has no process-global state or discovery path;
/// one registry is created from the owning application's explicit composition root.
/// </summary>
public sealed class ContributionRegistry<TOwner> where TOwner : class
{
    private readonly object gate = new();
    private readonly ApplicationComposition<TOwner> composition;
    private readonly IContributionRegistrationStore stateStore;
    private readonly HashSet<string> declaredToolSchemas;
    private readonly Dictionary<string, ContributionDefinition> definitions = new(StringComparer.Ordinal);

    public ContributionRegistry(ApplicationComposition<TOwner> composition,
        IContributionRegistrationStore stateStore,
        IEnumerable<string>? declaredToolSchemas = null)
    {
        this.composition = composition ?? throw new ArgumentNullException(nameof(composition));
        this.stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        this.declaredToolSchemas = new HashSet<string>(StringComparer.Ordinal);
        if (declaredToolSchemas is not null)
        {
            foreach (var schema in declaredToolSchemas)
            {
                if (!IsCanonicalKey(schema) || !this.declaredToolSchemas.Add(schema))
                {
                    throw new ArgumentException("Declared tool schemas must be canonical, unique keys.", nameof(declaredToolSchemas));
                }
            }
        }
    }

    /// <summary>A stable ordinal snapshot for diagnostics; handlers are never exposed as untyped objects.</summary>
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

    /// <summary>Registers an application-supplied static descriptor and a strongly typed owner callback.</summary>
    public ContributionRegistration<TOwner, TRequest, TResult> Register<TRequest, TResult>(
        ContributionDefinition definition,
        Func<TOwner, TRequest, CancellationToken, ValueTask<ArcForges.Foundation.Errors.Outcome<TResult>>> operation)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(operation);
        Validate(definition);

        lock (gate)
        {
            if (definitions.ContainsKey(definition.Id))
            {
                throw Failure(ContributionRegistrationFailure.DuplicateId,
                    "A contribution ID can be bound only once in an application composition.");
            }

            var handler = composition.Bind(operation);
            ContributionPersistenceResult persisted;
            try
            {
                persisted = stateStore.Add(composition.Identity.Installation, definition);
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
                composition, handler, definition, persisted);
            definitions.Add(definition.Id, definition);
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

    private void Validate(ContributionDefinition definition)
    {
        var app = composition.Identity.Installation.App.ProductId;
        if (!IsCanonicalKey(definition.Id) || definition.Kind is < ContributionKind.Capability or > ContributionKind.LifecycleHandler)
        {
            throw Failure(ContributionRegistrationFailure.InvalidDescriptor,
                "Contribution metadata must use a canonical ID and a known local kind.");
        }

        if (!string.Equals(definition.OwnerProductId, app, StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.WrongOwner,
                "Contribution metadata must name the exact product that owns this composition.");
        }

        if (!definition.Id.StartsWith(app + ".", StringComparison.Ordinal))
        {
            throw Failure(ContributionRegistrationFailure.ForeignNamespace,
                "A product can register only in its own reserved contribution namespace.");
        }

        if (definition.ToolSchemaId is { } schema)
        {
            if (definition.Kind != ContributionKind.Capability || !IsCanonicalKey(schema) || !declaredToolSchemas.Contains(schema))
            {
                throw Failure(ContributionRegistrationFailure.UndeclaredToolSchema,
                    "A tool schema must be canonical, explicitly declared by the owner, and attached to a capability.");
            }
        }
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
