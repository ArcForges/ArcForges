// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;

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
        Fingerprint = ContributionCatalogFingerprint.ComputeDefinition(Id, OwnerProductId, Kind, ToolSchemaId);
    }

    public string Id { get; }
    public string OwnerProductId { get; }
    public ContributionKind Kind { get; }
    public string? ToolSchemaId { get; }
    /// <summary>A deterministic hash of every declared field; catalogs bind registrations to this exact descriptor.</summary>
    public string Fingerprint { get; }
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
    UndeclaredContribution,
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

/// <summary>
/// Immutable product-owned descriptor inventory supplied by the application composition root.
/// Product source generation may implement this contract; the registration package does not discover
/// or add descriptors at runtime.
/// </summary>
public interface IContributionCatalog
{
    string OwnerProductId { get; }
    IReadOnlyList<ContributionDefinition> Descriptors { get; }
    string Fingerprint { get; }
}

/// <summary>Canonical SHA-256 identities shared by static catalog implementations and the registry.</summary>
public static class ContributionCatalogFingerprint
{
    public static string Compute(string ownerProductId, IEnumerable<ContributionDefinition> descriptors)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerProductId);
        ArgumentNullException.ThrowIfNull(descriptors);

        var entries = descriptors.ToArray();
        if (entries.Any(value => value is null))
        {
            throw new ArgumentException("A contribution catalog cannot contain a null descriptor.", nameof(descriptors));
        }

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        writer.Write("ArcForges.Contributions.Catalog.v1");
        writer.Write(ownerProductId);
        writer.Write(entries.Length);
        foreach (var descriptor in entries.OrderBy(value => value.Id, StringComparer.Ordinal))
        {
            writer.Write(descriptor.Id);
            writer.Write(descriptor.Fingerprint);
        }

        writer.Flush();
        return Convert.ToHexStringLower(SHA256.HashData(stream.ToArray()));
    }

    internal static string ComputeDefinition(string id, string ownerProductId, ContributionKind kind, string? toolSchemaId)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        writer.Write("ArcForges.Contributions.Descriptor.v1");
        writer.Write(id);
        writer.Write(ownerProductId);
        writer.Write((int)kind);
        writer.Write(toolSchemaId is not null);
        if (toolSchemaId is not null)
        {
            writer.Write(toolSchemaId);
        }

        writer.Flush();
        return Convert.ToHexStringLower(SHA256.HashData(stream.ToArray()));
    }
}
