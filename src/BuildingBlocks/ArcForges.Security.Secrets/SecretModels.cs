// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Secrets;

/// <summary>
/// What the backing store itself enforces between processes. This is declared by the store and is never
/// inferred from the broker's namespace, because a namespace only constrains callers that go through the broker.
/// </summary>
public enum SecretStoreIsolation
{
    /// <summary>
    /// Every process of the same OS user can address every entry (Windows Credential Manager from an unpackaged
    /// application is this class). Sibling denial then holds only for code that goes through the owning host's
    /// broker; hostile same-user code is not stopped by the store.
    /// </summary>
    SameUserShared = 0,

    /// <summary>
    /// The operating system itself denies sibling applications: package identity or AppContainer, a code-signature
    /// bound keychain access group, a per-application UID keystore or a per-application secret portal.
    /// </summary>
    OsEnforcedPerApplication = 1,
}

/// <summary>Explicit composition decision about which store isolation class a broker may run over.</summary>
public enum SecretIsolationPolicy
{
    /// <summary>Construction fails closed unless the store declares <see cref="SecretStoreIsolation.OsEnforcedPerApplication"/>.</summary>
    RequireOsEnforcedPerApplication = 0,

    /// <summary>
    /// The host accepts a same-user shared store and the limitation that sibling denial is not OS-enforced. This is a
    /// recorded weaker assurance, not evidence that sibling credential reads are denied.
    /// </summary>
    AllowSameUserSharedStore = 1,
}

/// <summary>Chooses one hard-separated secret owner; personal and workspace secrets never alias.</summary>
public readonly record struct SecretPartition
{
    private SecretPartition(bool isWorkspace, WorkspaceId workspace)
    {
        if (isWorkspace && workspace.Value == Guid.Empty)
        {
            throw new ArgumentException("A non-empty workspace identity is required.", nameof(workspace));
        }

        IsWorkspace = isWorkspace;
        Workspace = isWorkspace ? workspace : null;
    }

    public bool IsWorkspace { get; }
    public WorkspaceId? Workspace { get; }

    public static SecretPartition Personal() => new(false, default);
    public static SecretPartition ForWorkspace(WorkspaceId workspace) => new(true, workspace);
}

/// <summary>
/// Closed storage namespace dimension, not a second product-identity authority. Composition maps its
/// trusted AppIdentity here so the security package does not depend on the application-composition layer.
/// </summary>
public sealed record SecretApplicationDimension
{
    private SecretApplicationDimension(string productId) => ProductId = productId;

    public static SecretApplicationDimension ArcScope { get; } = new("arcscope");
    public static SecretApplicationDimension Companion { get; } = new("companion");
    public string ProductId { get; }

    public static SecretApplicationDimension Parse(string productId) => productId switch
    {
        "arcscope" => ArcScope,
        "companion" => Companion,
        _ => throw new ArgumentException("An exact supported product identity is required.", nameof(productId)),
    };
}

/// <summary>Product and durable device/installation binding supplied by the owning application.</summary>
public sealed record SecretInstallationBinding
{
    public SecretInstallationBinding(SecretApplicationDimension app, DeviceId deviceId, InstallationId installationId)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (deviceId.Value == Guid.Empty || installationId.Value == Guid.Empty)
        {
            throw new ArgumentException("Device and installation identities must be initialized.");
        }

        App = app;
        DeviceId = deviceId;
        InstallationId = installationId;
    }

    public SecretApplicationDimension App { get; }
    public DeviceId DeviceId { get; }
    public InstallationId InstallationId { get; }
}

/// <summary>
/// Opaque reference to a protected value. It has no plaintext or printable identifier surface;
/// only the broker can resolve its private identity and application namespace.
/// </summary>
public sealed class SecretRef
{
    internal SecretRef(Guid id, SecretLocation location)
    {
        if (id == Guid.Empty) throw new ArgumentException("Secret reference identity is required.", nameof(id));
        Id = id;
        Location = location;
    }

    internal Guid Id { get; }
    internal SecretLocation Location { get; }

    public override string ToString() => "SecretRef:[redacted]";
}

/// <summary>Trusted, in-process host context. Never deserialize this type from a child or wire request.</summary>
public sealed class SecretHostContext
{
    public SecretHostContext(ActorChain actorChain, SecretInstallationBinding installation, SessionId session,
        ulong recoveryGeneration, bool isSignedIn, bool isForeground)
    {
        ArgumentNullException.ThrowIfNull(actorChain);
        ArgumentNullException.ThrowIfNull(installation);
        if (session.Value == Guid.Empty) throw new ArgumentException("A session identity is required.", nameof(session));
        if (actorChain.Device != installation.DeviceId || actorChain.Installation != installation.InstallationId)
        {
            throw new ArgumentException("Actor provenance and application installation do not match.");
        }

        ActorChain = actorChain;
        Installation = installation;
        Session = session;
        RecoveryGeneration = recoveryGeneration;
        IsSignedIn = isSignedIn;
        IsForeground = isForeground;
    }

    public ActorChain ActorChain { get; }
    public SecretInstallationBinding Installation { get; }
    public SessionId Session { get; }
    public ulong RecoveryGeneration { get; }
    public bool IsSignedIn { get; }
    public bool IsForeground { get; }
}

/// <summary>Supplies current authenticated host state; implementations belong to the first-party app host.</summary>
public interface ISecretHostContextProvider
{
    SecretHostContext GetCurrent();
}

/// <summary>
/// First-party in-process extension host operation executor. It is supplied only by the owning host;
/// connector children never implement this interface, receive this object, or receive its secret span.
/// Implementations perform the granted credential-bearing operation in the owning host and must never
/// forward the raw credential over connector IPC. A connector child cannot supply an arbitrary callback.
/// </summary>
public interface IConnectorSecretOperationExecutor
{
    void Execute(string connectorDefinitionId, ReadOnlySpan<byte> secret);
}

/// <summary>
/// Opaque, short-lived permission to use one secret for one foreground connector definition.
/// It contains no value and cannot be serialized into connector input.
/// </summary>
public sealed class ConnectorSecretGrant
{
    internal ConnectorSecretGrant(Guid id, Guid brokerId, string definitionId, SecretRef secret,
        byte[] actorFingerprint, SessionId session, ulong recoveryGeneration, DateTimeOffset expiresAt)
    {
        Id = id;
        BrokerId = brokerId;
        DefinitionId = definitionId;
        Secret = secret;
        ActorFingerprint = actorFingerprint;
        Session = session;
        RecoveryGeneration = recoveryGeneration;
        ExpiresAt = expiresAt;
    }

    internal Guid Id { get; }
    internal Guid BrokerId { get; }
    internal string DefinitionId { get; }
    internal SecretRef Secret { get; }
    internal byte[] ActorFingerprint { get; }
    internal SessionId Session { get; }
    internal ulong RecoveryGeneration { get; }
    internal object SyncRoot { get; } = new();
    internal bool IsRevoked { get; set; }
    public DateTimeOffset ExpiresAt { get; }

    public override string ToString() => "ConnectorSecretGrant:[redacted]";
}

internal readonly record struct SecretLocation(Guid Realm, Guid Account, string ProductId, Guid Device,
    Guid Installation, bool IsWorkspace, Guid Workspace, Guid Secret)
{
    public static SecretLocation Create(SecretHostContext context, SecretPartition partition, Guid secretId) =>
        new(context.ActorChain.Owner.Realm.Value, context.ActorChain.Owner.Id.Value,
            context.Installation.App.ProductId, context.Installation.DeviceId.Value,
            context.Installation.InstallationId.Value, partition.IsWorkspace,
            partition.Workspace?.Value ?? Guid.Empty, secretId);
}
