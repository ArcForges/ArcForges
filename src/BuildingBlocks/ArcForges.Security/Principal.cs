// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Security;

public enum HumanIdentityKind
{
    None = 0,
    CloudUser = 1,
    LocalHuman = 2,
}

/// <summary>The human owner. A local human identity is not a cloud authentication claim.</summary>
public sealed record HumanPrincipal
{
    public HumanPrincipal(RealmId realm, UserId id, HumanIdentityKind kind)
    {
        _ = realm.ToWire();
        _ = id.ToWire();
        if ((int)kind == 0 || !Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Realm = realm;
        Id = id;
        Kind = kind;
    }

    public RealmId Realm { get; }
    public UserId Id { get; }
    public HumanIdentityKind Kind { get; }
}

public enum ActorKind
{
    None = 0,
    Agent = 1,
    Extension = 2,
    Automation = 3,
    InternalService = 4,
}

/// <summary>A delegated actor, distinct from its executor and software identity.</summary>
public sealed record DelegatedActor
{
    public DelegatedActor(ActorKind kind, Guid actorId, InstanceId executor, string softwareIdentity)
    {
        if ((int)kind == 0 || !Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        if (actorId == Guid.Empty)
        {
            throw new ArgumentException("An actor identity is required.", nameof(actorId));
        }

        _ = executor.ToWire();
        ArgumentException.ThrowIfNullOrWhiteSpace(softwareIdentity);
        if (softwareIdentity.Length > 256 || softwareIdentity.Any(char.IsControl))
        {
            throw new ArgumentException("Software identity must be bounded and contain no control characters.", nameof(softwareIdentity));
        }

        Kind = kind;
        // Reject malformed UTF-16 before JSON can replace it and alter identity.
        _ = new System.Text.UTF8Encoding(false, true).GetByteCount(softwareIdentity);
        ActorId = actorId;
        Executor = executor;
        SoftwareIdentity = softwareIdentity;
    }

    public ActorKind Kind { get; }
    public Guid ActorId { get; }
    public InstanceId Executor { get; }
    public string SoftwareIdentity { get; }
}
