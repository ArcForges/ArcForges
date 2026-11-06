// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Node.Store;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// The node credential as the node keeps it (AF-CTR-04 CTR4-NODE-05 as amended): bound to the node ID and the full canonical center URL
/// it was issued for, with the lifetimes the center stated. At most <see cref="TestDataRootSecretStore.MaximumSecretBytes"/> serialized.
/// </summary>
internal sealed class CloudCredentialRecord
{
    /// <summary>The record format.</summary>
    public int Version { get; set; } = 1;

    /// <summary>The node ID (lower-case hex).</summary>
    public required string NodeId { get; set; }

    /// <summary>The canonical center URL the credential belongs to.</summary>
    public required string CenterUrl { get; set; }

    /// <summary>The account ID (lower-case hex).</summary>
    public string? AccountId { get; set; }

    /// <summary>The account's display name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>The account's masked e-mail address.</summary>
    public string? EmailMasked { get; set; }

    /// <summary>The node's installation ID at the center (lower-case hex).</summary>
    public required string InstallationId { get; set; }

    /// <summary>The access token (<c>afa1.</c>).</summary>
    public required string AccessToken { get; set; }

    /// <summary>When the access token expires by the center's clock (Unix milliseconds).</summary>
    public long AccessExpiresAtMs { get; set; }

    /// <summary>The access token's lifetime as issued (<c>access_lifetime_ms</c>); 0 when the center did not say.</summary>
    public long AccessLifetimeMs { get; set; }

    /// <summary>The refresh token (<c>afr1.</c>).</summary>
    public required string RefreshToken { get; set; }

    /// <summary>The absolute end of the credential family by the center's clock (Unix milliseconds); 0 when the center did not say.</summary>
    public long SessionExpiresAtMs { get; set; }

    /// <summary>
    /// The family's total lifetime, from the center's values at sign-in (<c>session_expires_at</c> minus the issue instant implied by
    /// <c>access_expires_at - access_lifetime_ms</c>; N1 decision R-8/N-16), for the expiry warning.
    /// </summary>
    public long FamilyLifetimeMs { get; set; }

    /// <summary>When this record was written (the node's wall clock, Unix milliseconds).</summary>
    public long WrittenAtMs { get; set; }

    /// <summary>The serialized record.</summary>
    public byte[] Serialize()
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(this, CloudLinkJsonContext.Default.CloudCredentialRecord);
        if (bytes.Length > TestDataRootSecretStore.MaximumSecretBytes)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidOperationException("The credential record exceeds the secret-store bound of 2,560 bytes.");
        }

        return bytes;
    }

    /// <summary>Parses a stored record; <see langword="null"/> when it is not one.</summary>
    public static CloudCredentialRecord? Parse(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return JsonSerializer.Deserialize(bytes, CloudLinkJsonContext.Default.CloudCredentialRecord);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>A copy (the in-memory record is replaced, never mutated in place, after it was stored).</summary>
    public CloudCredentialRecord Clone() => (CloudCredentialRecord)MemberwiseClone();
}

/// <summary>The states of <c>run/cloud-link.json</c> (N1 decision R-1: a two-phase adoption and ending).</summary>
internal static class LinkStates
{
    /// <summary>Written before the record when a credential is adopted.</summary>
    public const string Committing = "committing";

    /// <summary>The record is stored and in use.</summary>
    public const string SignedIn = "signed_in";

    /// <summary>Written before anything is deleted when the credential ends; a restart finishes the ending.</summary>
    public const string Ending = "ending";
}

/// <summary>
/// <c>run/cloud-link.json</c> (non-secret): where the credential is (the secret-store backend, protection and whether it is isolated, as
/// the store does not remember where a value was written), which center and node it belongs to, and the state of its two-phase writes.
/// </summary>
internal sealed class CloudLinkFile
{
    /// <summary><see cref="LinkStates"/>.</summary>
    public required string State { get; set; }

    /// <summary>The <c>SecretStoreBackend</c> that holds the record.</summary>
    public required string Backend { get; set; }

    /// <summary>The <c>SecretStoreProtection</c> of that backend.</summary>
    public required string Protection { get; set; }

    /// <summary>Whether that backend is an isolated test backend.</summary>
    public bool Isolated { get; set; }

    /// <summary>The record's secret-store target.</summary>
    public required string Target { get; set; }

    /// <summary>The canonical center URL.</summary>
    public required string CenterUrl { get; set; }

    /// <summary>The node ID (lower-case hex).</summary>
    public required string NodeId { get; set; }

    /// <summary>The last node name reported to the center.</summary>
    public string? ReportedName { get; set; }

    /// <summary>The last node version reported to the center.</summary>
    public string? ReportedVersion { get; set; }

    /// <summary>
    /// True after <c>SetCloudLink(false)</c> (AF-CTR-05 E.3); absent means on: the cloud link defaults to on after sign-in (Plan decision Q19),
    /// and a node signed in before AF-CTR-05 connects after the upgrade.
    /// </summary>
    public bool? ChannelDisabled { get; set; }
}

/// <summary>One center public key as <c>run/cloud-keys.json</c> keeps it.</summary>
internal sealed class CloudKeyEntry
{
    /// <summary>The key ID.</summary>
    public string? Kid { get; set; }

    /// <summary>The algorithm (<c>ES256</c>).</summary>
    public string? Algorithm { get; set; }

    /// <summary>The PKIX DER, base64.</summary>
    public string? Key { get; set; }

    /// <summary>Valid from (Unix milliseconds).</summary>
    public long NotBeforeMs { get; set; }

    /// <summary>Valid until (Unix milliseconds).</summary>
    public long NotAfterMs { get; set; }
}

/// <summary>
/// <c>run/cloud-keys.json</c> (AF-CTR-04 CTR4-NODE-07 as amended by node-5 and cluster H): the center's command and entitlement key sets,
/// bound to the center and the credential's installation, replaced as received, pruned by expiry only.
/// </summary>
internal sealed class CloudKeySetFile
{
    /// <summary>The canonical center URL the sets came from.</summary>
    public required string CenterUrl { get; set; }

    /// <summary>The credential's installation ID (lower-case hex).</summary>
    public required string InstallationId { get; set; }

    /// <summary>The command keys.</summary>
    public List<CloudKeyEntry> CommandKeys { get; set; } = [];

    /// <summary>The entitlement keys.</summary>
    public List<CloudKeyEntry> EntitlementKeys { get; set; } = [];
}

/// <summary>
/// The cloud link's storage: the credential record in the node's injected secret store, <c>run/cloud-link.json</c> and
/// <c>run/cloud-keys.json</c>. No path enters a secret-store target, so a data-root relocation keeps the credential reachable.
/// </summary>
internal sealed class CloudCredentialStore
{
    private readonly string _linkPath;
    private readonly string _keysPath;

    /// <summary>Creates the storage of a data root over the node's secret store.</summary>
    public CloudCredentialStore(string dataRoot, NodeSecretStore secrets)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        Secrets = secrets ?? throw new ArgumentNullException(nameof(secrets));
        _linkPath = Path.Combine(dataRoot, "run", "cloud-link.json");
        _keysPath = Path.Combine(dataRoot, "run", "cloud-keys.json");
    }

    /// <summary>The node's secret store.</summary>
    public NodeSecretStore Secrets { get; }

    /// <summary>The link file's path.</summary>
    public string LinkPath => _linkPath;

    /// <summary>The key-set file's path.</summary>
    public string KeysPath => _keysPath;

    /// <summary>
    /// The secret-store target of the credential of (node ID, origin): <c>ArcForges.Secrets.v1.</c> + HEX(SHA-256(
    /// <c>"arcforges.node-cloud-credential.v1|" + lower-hex(nodeId) + "|" + origin</c>)), the <c>NodeDataKeyRing.TargetName</c> construction.
    /// </summary>
    public static string Target(ReadOnlySpan<byte> nodeId, string origin)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(origin);
        if (nodeId.Length != 16)
        {
            throw new ArgumentException("A node ID is 16 bytes.", nameof(nodeId));
        }

        var identity = Encoding.UTF8.GetBytes("arcforges.node-cloud-credential.v1|" + Convert.ToHexStringLower(nodeId) + "|" + origin);
        return NodeSecretStores.TargetPrefix + Convert.ToHexString(SHA256.HashData(identity));
    }

    /// <summary>
    /// The link file, or <see langword="null"/> when there is none. A file that cannot be read or parsed throws (an <see cref="IOException"/>
    /// or <see cref="InvalidDataException"/>): it is never read as "absent", which would leave the record without its pointer.
    /// </summary>
    public CloudLinkFile? ReadLink()
    {
        var bytes = PrivateFiles.ReadOrNull(_linkPath);
        if (bytes is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(bytes, CloudLinkJsonContext.Default.CloudLinkFile)
                ?? throw new InvalidDataException("run/cloud-link.json holds no link.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("run/cloud-link.json is not a link file.", exception);
        }
    }

    /// <summary>Writes the link file atomically.</summary>
    public void WriteLink(CloudLinkFile link) =>
        PrivateFiles.WriteAtomic(_linkPath, JsonSerializer.SerializeToUtf8Bytes(link, CloudLinkJsonContext.Default.CloudLinkFile));

    /// <summary>Deletes the link file.</summary>
    public bool DeleteLink() => PrivateFiles.Delete(_linkPath);

    /// <summary>
    /// Reads the record at <paramref name="target"/>: <see langword="null"/> when the store holds none. A store failure (a locked keyring,
    /// an unavailable Secret Service) throws: it is never read as "absent" (N1 decision R-1).
    /// </summary>
    public CloudCredentialRecord? ReadRecord(string target)
    {
        var bytes = Secrets.Store.Read(target);
        if (bytes is null)
        {
            return null;
        }

        try
        {
            return CloudCredentialRecord.Parse(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Writes the record at <paramref name="target"/> (a failure throws).</summary>
    public void WriteRecord(string target, CloudCredentialRecord record)
    {
        var bytes = record.Serialize();
        try
        {
            Secrets.Store.Write(target, bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Deletes the record at <paramref name="target"/> (a failure throws).</summary>
    public bool DeleteRecord(string target) => Secrets.Store.Delete(target);

    /// <summary>The key-set file, or <see langword="null"/>.</summary>
    public CloudKeySetFile? ReadKeys()
    {
        var bytes = PrivateFiles.ReadOrNull(_keysPath);
        if (bytes is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(bytes, CloudLinkJsonContext.Default.CloudKeySetFile);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Writes the key-set file atomically.</summary>
    public void WriteKeys(CloudKeySetFile keys) =>
        PrivateFiles.WriteAtomic(_keysPath, JsonSerializer.SerializeToUtf8Bytes(keys, CloudLinkJsonContext.Default.CloudKeySetFile));

    /// <summary>Deletes the key-set file.</summary>
    public bool DeleteKeys() => PrivateFiles.Delete(_keysPath);
}
