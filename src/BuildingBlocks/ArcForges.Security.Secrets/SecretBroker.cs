// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Secrets;

/// <summary>
/// Application-bound secret broker. It grants use, never reveal; references resolve only inside the
/// realm/account/product/device/installation/workspace namespace captured at creation.
/// </summary>
public sealed class SecretBroker
{
    public static readonly TimeSpan MaximumConnectorGrantLifetime = TimeSpan.FromMinutes(2);
    public const int MaximumSecretBytes = 2560;

    private const string TargetPrefix = "ArcForges.Secrets.v1.";
    private readonly SecretInstallationBinding _installation;
    private readonly ISecretHostContextProvider _contextProvider;
    private readonly ISecretBackingStore _store;
    private readonly IConnectorSecretOperationExecutor _connectorExecutor;
    private readonly TimeProvider _timeProvider;
    private readonly SecretStoreIsolation _isolation;
    private readonly Guid _brokerId = Guid.NewGuid();
    private readonly ConcurrentDictionary<Guid, ConnectorSecretGrant> _grants = new();

    public SecretBroker(SecretInstallationBinding installation, ISecretHostContextProvider contextProvider,
        ISecretBackingStore store, IConnectorSecretOperationExecutor connectorExecutor,
        SecretIsolationPolicy isolationPolicy, TimeProvider? timeProvider = null)
    {
        _installation = installation ?? throw new ArgumentNullException(nameof(installation));
        _contextProvider = contextProvider ?? throw new ArgumentNullException(nameof(contextProvider));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _connectorExecutor = connectorExecutor ?? throw new ArgumentNullException(nameof(connectorExecutor));
        _timeProvider = timeProvider ?? TimeProvider.System;
        if (!Enum.IsDefined(isolationPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(isolationPolicy), "An explicit isolation policy is required.");
        }

        // Captured once: a store cannot upgrade its declared assurance after the composition decision was made.
        _isolation = store.Isolation;
        if (isolationPolicy == SecretIsolationPolicy.RequireOsEnforcedPerApplication
            && _isolation != SecretStoreIsolation.OsEnforcedPerApplication)
        {
            throw new NotSupportedException(
                "The secret store does not enforce per-application isolation in the operating system; "
                + "the host must supply an OS-enforced adapter or explicitly accept the same-user shared-store limitation.");
        }
    }

    /// <summary>
    /// What the backing store enforces between processes. <see cref="SecretStoreIsolation.SameUserShared"/> means sibling
    /// denial is a property of this broker's namespace only and is not an OS-enforced boundary.
    /// </summary>
    public SecretStoreIsolation IsolationAssurance => _isolation;

    /// <summary>Stores a secret in the host installation's protected namespace and returns only an opaque ref.</summary>
    public SecretRef Store(SecretPartition partition, ReadOnlySpan<byte> secret)
    {
        var context = RequireDirectHumanContext();
        ValidateSecret(secret);
        Guid id = Guid.NewGuid();
        var location = SecretLocation.Create(context, partition, id);
        var reference = new SecretRef(id, location);
        byte[] owned = secret.ToArray();
        try { _store.Write(Target(location), owned); }
        finally { CryptographicOperations.ZeroMemory(owned); }
        return reference;
    }

    /// <summary>
    /// Issues one foreground, definition-bound grant from the direct human owner to a planned child chain.
    /// A child actor cannot mint its own grant, and the grant is tied to the full target actor-chain snapshot.
    /// </summary>
    public ConnectorSecretGrant GrantConnectorUse(SecretRef reference, ActorChain targetActorChain,
        string connectorDefinitionId, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(targetActorChain);
        ValidateDefinitionId(connectorDefinitionId);
        if (lifetime <= TimeSpan.Zero || lifetime > MaximumConnectorGrantLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Connector grants must be positive and no longer than two minutes.");
        }

        var context = RequireDirectHumanContext();
        if (!context.IsForeground)
        {
            throw new UnauthorizedAccessException("Connector secret use requires an active foreground human grant.");
        }

        if (targetActorChain.Session != context.Session
            || targetActorChain.Device != _installation.DeviceId
            || targetActorChain.Installation != _installation.InstallationId
            || targetActorChain.Owner != context.ActorChain.Owner
            || targetActorChain.Actors.Count == 0)
        {
            throw new UnauthorizedAccessException("Connector grant target does not belong to the current human session and installation.");
        }

        var connector = targetActorChain.Actors[^1];
        if (connector.Kind != ActorKind.Extension || !StringComparer.Ordinal.Equals(connector.SoftwareIdentity, connectorDefinitionId))
        {
            throw new UnauthorizedAccessException("The final target actor is not the named connector definition.");
        }

        EnsureSameNamespace(reference, context);
        var grant = new ConnectorSecretGrant(Guid.NewGuid(), _brokerId, connectorDefinitionId, reference,
            SHA256.HashData(ActorChainSnapshot.Encode(targetActorChain)), context.Session,
            context.RecoveryGeneration, _timeProvider.GetUtcNow() + lifetime, _timeProvider.GetTimestamp(), lifetime);
        EvictExpiredGrants();
        if (!_grants.TryAdd(grant.Id, grant)) throw new InvalidOperationException("Connector grant identity collision.");
        return grant;
    }

    /// <summary>Uses, but never returns, the granted secret while the same foreground/session/definition remains active.</summary>
    public void UseConnectorGrant(ConnectorSecretGrant grant, string connectorDefinitionId)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ValidateDefinitionId(connectorDefinitionId);
        lock (grant.SyncRoot)
        {
            if (grant.BrokerId != _brokerId || grant.IsRevoked
                || !_grants.TryGetValue(grant.Id, out var active) || !ReferenceEquals(active, grant))
            {
                throw new UnauthorizedAccessException("Connector secret grant is unknown or revoked.");
            }

            if (IsExpired(grant))
            {
                grant.IsRevoked = true;
                _grants.TryRemove(grant.Id, out _);
                throw new UnauthorizedAccessException("Connector secret grant has expired.");
            }

            if (!StringComparer.Ordinal.Equals(connectorDefinitionId, grant.DefinitionId))
            {
                throw new UnauthorizedAccessException("Connector secret grant is bound to a different definition.");
            }

            var context = RequireCurrentContext();
            if (!context.IsForeground || context.Session != grant.Session || context.RecoveryGeneration != grant.RecoveryGeneration
                || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(ActorChainSnapshot.Encode(context.ActorChain)), grant.ActorFingerprint))
            {
                throw new UnauthorizedAccessException("Connector grant is stale or no longer in its foreground session.");
            }

            EnsureSameNamespace(grant.Secret, context);
            var connector = context.ActorChain.Actors.Count == 0 ? null : context.ActorChain.Actors[^1];
            if (connector?.Kind != ActorKind.Extension || !StringComparer.Ordinal.Equals(connector.SoftwareIdentity, connectorDefinitionId))
            {
                throw new UnauthorizedAccessException("The active actor is not the granted connector definition.");
            }

            UseCore(grant.Secret, secret => _connectorExecutor.Execute(connectorDefinitionId, secret));
        }
    }

    /// <summary>Immediately revokes a child grant; secret material and unrelated app data are not deleted.</summary>
    public bool Revoke(ConnectorSecretGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        if (grant.BrokerId != _brokerId) throw new UnauthorizedAccessException("Connector grant belongs to another broker.");
        lock (grant.SyncRoot)
        {
            if (grant.IsRevoked || !_grants.TryRemove(grant.Id, out var active) || !ReferenceEquals(active, grant))
            {
                return false;
            }

            grant.IsRevoked = true;
            return true;
        }
    }

    /// <summary>
    /// Revokes every outstanding connector grant of this broker, as own sign-out must: no use starts after this returns,
    /// while an executor operation already in flight completes first (revocation waits for it). Stored secrets, other
    /// applications' vaults and local data are untouched.
    /// </summary>
    public int RevokeAllConnectorGrants()
    {
        int revoked = 0;
        foreach (var pair in _grants.ToArray())
        {
            var grant = pair.Value;
            lock (grant.SyncRoot)
            {
                if (!grant.IsRevoked && _grants.TryRemove(grant.Id, out var active) && ReferenceEquals(active, grant))
                {
                    grant.IsRevoked = true;
                    revoked++;
                }
            }
        }

        return revoked;
    }

    /// <summary>Deletes a secret only from this app installation's own protected namespace.</summary>
    public bool Delete(SecretRef reference)
    {
        ArgumentNullException.ThrowIfNull(reference);
        var context = RequireDirectHumanContext();
        EnsureSameNamespace(reference, context);
        return _store.Delete(Target(reference.Location));
    }

    private bool IsExpired(ConnectorSecretGrant grant) =>
        _timeProvider.GetElapsedTime(grant.IssuedTimestamp) >= grant.Lifetime;

    // Expired grants are evicted when the next grant is minted, so only the human host can grow the table.
    private void EvictExpiredGrants()
    {
        foreach (var pair in _grants.ToArray())
        {
            var grant = pair.Value;
            if (!IsExpired(grant)) continue;
            lock (grant.SyncRoot)
            {
                if (_grants.TryRemove(grant.Id, out var active) && ReferenceEquals(active, grant)) grant.IsRevoked = true;
            }
        }
    }

    private SecretHostContext RequireDirectHumanContext()
    {
        var context = RequireCurrentContext();
        if (context.ActorChain.Actors.Count != 0)
        {
            throw new UnauthorizedAccessException("A delegated agent or extension cannot act as the human secret owner.");
        }

        return context;
    }

    private SecretHostContext RequireCurrentContext()
    {
        var context = _contextProvider.GetCurrent() ?? throw new InvalidOperationException("Host context provider returned no context.");
        if (!context.IsSignedIn) throw new UnauthorizedAccessException("A signed-in host session is required.");
        if (!StringComparer.Ordinal.Equals(context.Installation.App.ProductId, _installation.App.ProductId)
            || context.Installation.DeviceId != _installation.DeviceId
            || context.Installation.InstallationId != _installation.InstallationId
            || context.ActorChain.Session != context.Session
            || context.ActorChain.Device != _installation.DeviceId
            || context.ActorChain.Installation != _installation.InstallationId)
        {
            throw new UnauthorizedAccessException("Host identity does not match this application's bound installation.");
        }

        return context;
    }

    private static void EnsureSameNamespace(SecretRef reference, SecretHostContext context)
    {
        var expected = SecretLocation.Create(context, new SecretPartitionProxy(reference.Location.IsWorkspace, reference.Location.Workspace).Partition, reference.Id);
        if (expected != reference.Location)
        {
            throw new UnauthorizedAccessException("Secret reference belongs to another realm, account, product or installation.");
        }
    }

    private void UseCore(SecretRef reference, Action<byte[]> operation)
    {
        byte[]? secret = _store.Read(Target(reference.Location));
        if (secret is null) throw new KeyNotFoundException("Secret reference is not present in this application's protected store.");
        try
        {
            ValidateSecret(secret);
            operation(secret);
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static string Target(SecretLocation location)
    {
        string canonical = string.Join('|', location.Realm.ToString("N"), location.Account.ToString("N"),
            location.ProductId, location.Device.ToString("N"), location.Installation.ToString("N"),
            location.IsWorkspace ? "workspace" : "personal", location.Workspace.ToString("N"), location.Secret.ToString("N"));
        return TargetPrefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static void ValidateSecret(ReadOnlySpan<byte> secret)
    {
        if (secret.IsEmpty || secret.Length > MaximumSecretBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secret), "Secret values must be non-empty and within the OS credential-store bound.");
        }
    }

    private static void ValidateDefinitionId(string definitionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(definitionId);
        if (definitionId.Length > 256 || definitionId.Any(character =>
                character is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-' or ':')))
        {
            throw new ArgumentException("Connector definition identity must be a bounded ASCII token.", nameof(definitionId));
        }
    }

    private readonly record struct SecretPartitionProxy(bool IsWorkspace, Guid Workspace)
    {
        public SecretPartition Partition => IsWorkspace
            ? SecretPartition.ForWorkspace(new ArcForges.Contracts.Foundation.Values.WorkspaceId(Workspace))
            : SecretPartition.Personal();
    }
}

/// <summary>Backing-store contract for platform credential-store adapters; implementations are host-trusted.</summary>
public interface ISecretBackingStore
{
    /// <summary>The isolation class the store itself enforces; it must never overstate what the OS provides.</summary>
    SecretStoreIsolation Isolation { get; }

    void Write(string opaqueTarget, ReadOnlySpan<byte> secret);
    byte[]? Read(string opaqueTarget);
    bool Delete(string opaqueTarget);
}
