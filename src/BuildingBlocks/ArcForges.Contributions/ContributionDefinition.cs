// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Contributions;

/// <summary>
/// Immutable, local metadata emitted by a product's static contribution catalog.
/// This is not a wire DTO; generated Contracts messages remain owned by Contracts.
/// </summary>
public sealed record ContributionDefinition
{
    public ContributionDefinition(string id, string ownerProductId, ContributionKind kind, string? toolSchemaId = null)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        OwnerProductId = ownerProductId ?? throw new ArgumentNullException(nameof(ownerProductId));
        Kind = kind;
        ToolSchemaId = toolSchemaId;
    }

    public string Id { get; }
    public string OwnerProductId { get; }
    public ContributionKind Kind { get; }
    public string? ToolSchemaId { get; }
}

/// <summary>Known local contribution roles; lifecycle is a process binding, not a public wire kind.</summary>
public enum ContributionKind
{
    None = 0,
    Capability = 1,
    Action = 2,
    ContextProvider = 3,
    ArtifactHandler = 4,
    SuggestedTask = 5,
    DeepLink = 6,
    LifecycleHandler = 7,
}

public enum ContributionRegistrationFailure
{
    InvalidDescriptor = 0,
    WrongOwner,
    ForeignNamespace,
    DuplicateId,
    UndeclaredToolSchema,
    ChildUnavailable,
    PersistenceConflict,
}

public enum ContributionPersistenceResult
{
    Added,
    AlreadyPresent,
}

public sealed class ContributionRegistrationException : InvalidOperationException
{
    public ContributionRegistrationException()
        : this(ContributionRegistrationFailure.InvalidDescriptor, "Contribution registration failed.") { }

    public ContributionRegistrationException(string message)
        : this(ContributionRegistrationFailure.InvalidDescriptor, message) { }

    public ContributionRegistrationException(string message, Exception innerException)
        : this(ContributionRegistrationFailure.InvalidDescriptor, message, innerException) { }

    public ContributionRegistrationException(ContributionRegistrationFailure failure, string message, Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    public ContributionRegistrationFailure Failure { get; }
}

/// <summary>Raised by an owner store when an existing key contains different static metadata.</summary>
public sealed class ContributionPersistenceConflictException : InvalidOperationException
{
    public ContributionPersistenceConflictException() { }
    public ContributionPersistenceConflictException(string message) : base(message) { }
    public ContributionPersistenceConflictException(string message, Exception innerException) : base(message, innerException) { }
}
