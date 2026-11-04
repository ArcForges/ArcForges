// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

/// <summary>A node key the node can sign with: ECDSA P-256, its private half never leaving its backend.</summary>
internal interface INodeKey : IDisposable
{
    /// <summary>The PKIX SubjectPublicKeyInfo DER (91 bytes).</summary>
    byte[] PublicKey { get; }

    /// <summary>An ES256 signature over SHA-256 of <paramref name="message"/>, IEEE P1363, low-S (CloudIdentity).</summary>
    byte[] Sign(ReadOnlySpan<byte> message);
}

/// <summary>Where node keys live: a CNG user key store (Windows production) or owner-only PKCS#8 files.</summary>
internal interface INodeKeyBackend
{
    /// <summary>The backend's name in logs and in <c>run/node-key.json</c> (<c>cng</c> or <c>file</c>).</summary>
    string Kind { get; }

    /// <summary>Opens the key of <paramref name="name"/>, or <see langword="null"/> when it does not exist.</summary>
    INodeKey? Open(string name);

    /// <summary>Creates and persists a new key under <paramref name="name"/> (replacing nothing: the name must be free).</summary>
    INodeKey Create(string name);

    /// <summary>Deletes the key of <paramref name="name"/>; false when it did not exist.</summary>
    bool Delete(string name);

    /// <summary>The names this backend can enumerate in the node's data root (file keys; a CNG store is not enumerated).</summary>
    IReadOnlyList<string> Names();
}

/// <summary>What a node key deletion found.</summary>
internal enum NodeKeyDeletion
{
    /// <summary>No key and no record.</summary>
    None,

    /// <summary>Keys or the record were deleted.</summary>
    Deleted,

    /// <summary>The record names a key in another backend than this store's, which this run cannot reach: the record is kept.</summary>
    OtherBackend,
}

/// <summary>What <c>run/node-key.json</c> records about the node key (non-secret).</summary>
internal sealed class NodeKeyRecord
{
    /// <summary>The backend kind.</summary>
    public required string Backend { get; init; }

    /// <summary>The exact key name (deletion is by this name only).</summary>
    public required string Name { get; init; }

    /// <summary>The node ID (lower-case hex) the key was made for.</summary>
    public required string NodeId { get; init; }

    /// <summary>The canonical center origin the key was made for.</summary>
    public required string Origin { get; init; }

    /// <summary>The key's fingerprint.</summary>
    public required string Fingerprint { get; init; }

    /// <summary>When the key was created (Unix milliseconds).</summary>
    public required long CreatedAtMs { get; init; }
}

/// <summary>
/// The node key (AF-CTR-04 CTR4-NODE-06 as amended): ECDSA P-256, named from the node ID and the canonical center origin (cluster A;
/// fleet.proto "Key and credential names on the node derive from the node ID and the canonical center origin"), never from a path, so a
/// data-root relocation keeps it and a store reset (a new node ID) gets a fresh one. <c>run/node-key.json</c> records the exact name, so
/// deletion is by name. Lifetime (N1 decision G-1): created before any request carries its public half; kept across restarts; deleted
/// whenever the node's credential ends and on a center change, because the center refuses a key an installation holds or held.
/// </summary>
internal sealed class NodeKeyStore
{
    /// <summary>The prefix of every key name.</summary>
    public const string NamePrefix = "ArcForges.NodeKey.v1.";

    private const string RecordFile = "node-key.json";
    private readonly string _recordPath;
    private readonly Lock _gate = new();

    /// <summary>Creates the store for a data root over <paramref name="backend"/>.</summary>
    public NodeKeyStore(string dataRoot, INodeKeyBackend backend)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        Backend = backend ?? throw new ArgumentNullException(nameof(backend));
        _recordPath = Path.Combine(dataRoot, "run", RecordFile);
    }

    /// <summary>The backend.</summary>
    public INodeKeyBackend Backend { get; }

    /// <summary>The key name of (node ID, origin): <c>ArcForges.NodeKey.v1.</c> and 64 upper-case hexadecimal digits.</summary>
    public static string KeyName(ReadOnlySpan<byte> nodeId, string origin)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(origin);
        if (nodeId.Length != 16)
        {
            throw new ArgumentException("A node ID is 16 bytes.", nameof(nodeId));
        }

        var identity = Encoding.UTF8.GetBytes("arcforges.node-key.v1|" + Convert.ToHexStringLower(nodeId) + "|" + origin);
        return NamePrefix + Convert.ToHexString(SHA256.HashData(identity));
    }

    /// <summary>The recorded key, or <see langword="null"/>.</summary>
    public NodeKeyRecord? Recorded()
    {
        lock (_gate)
        {
            return ReadRecord();
        }
    }

    /// <summary>Opens the key of (node ID, origin) when it is the recorded one and exists; otherwise <see langword="null"/>.</summary>
    public INodeKey? Load(ReadOnlySpan<byte> nodeId, string origin)
    {
        var name = KeyName(nodeId, origin);
        lock (_gate)
        {
            return ReadRecord() is { } record && record.Name == name && record.Backend == Backend.Kind ? Backend.Open(name) : null;
        }
    }

    /// <summary>
    /// Creates the key of (node ID, origin), persisted before it is returned (so before any request carries its public half), and records
    /// it. The previously recorded key, any file key of another name (stale keys of another node ID after a store reset) and an existing
    /// key of the same name are deleted first.
    /// </summary>
    public INodeKey Create(ReadOnlySpan<byte> nodeId, string origin, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        var name = KeyName(nodeId, origin);
        var nodeHex = Convert.ToHexStringLower(nodeId);
        lock (_gate)
        {
            if (ReadRecord() is { } previous && previous.Backend == Backend.Kind)
            {
                Backend.Delete(previous.Name);
            }

            foreach (var stale in Backend.Names())
            {
                Backend.Delete(stale);
            }

            Backend.Delete(name);
            var key = Backend.Create(name);
            try
            {
                var record = new NodeKeyRecord
                {
                    Backend = Backend.Kind,
                    Name = name,
                    NodeId = nodeHex,
                    Origin = origin,
                    Fingerprint = CloudIdentity.Fingerprint(key.PublicKey),
                    CreatedAtMs = clock.GetUtcNow().ToUnixTimeMilliseconds(),
                };
                PrivateFiles.WriteAtomic(_recordPath, JsonSerializer.SerializeToUtf8Bytes(record, CloudLinkJsonContext.Default.NodeKeyRecord));
                return key;
            }
            catch
            {
                key.Dispose();
                Backend.Delete(name);
                throw;
            }
        }
    }

    /// <summary>Deletes the recorded key (by its exact name) and the record; false when there was none.</summary>
    public bool Delete() => Delete(ReadOnlySpan<byte>.Empty, []) == NodeKeyDeletion.Deleted;

    /// <summary>
    /// Deletes the node key wherever this store can find it (sec NB-8): the recorded name, the names derived from
    /// <paramref name="nodeId"/> and each of <paramref name="origins"/> (so a missing or unparsable <c>run/node-key.json</c> leaves no key
    /// behind), and every key file of the data root; then the record. Only names of the node key's shape are ever deleted. A record that
    /// names another backend is kept and reported (<see cref="NodeKeyDeletion.OtherBackend"/>). A failed deletion throws, leaving the record.
    /// </summary>
    public NodeKeyDeletion Delete(ReadOnlySpan<byte> nodeId, IEnumerable<string> origins)
    {
        ArgumentNullException.ThrowIfNull(origins);
        lock (_gate)
        {
            var bytes = PrivateFiles.ReadOrNull(_recordPath);
            NodeKeyRecord? record = null;
            if (bytes is not null)
            {
                try
                {
                    record = JsonSerializer.Deserialize(bytes, CloudLinkJsonContext.Default.NodeKeyRecord);
                }
                catch (JsonException)
                {
                    // Unparsable: the derived names below still find the key.
                }
            }

            var otherBackend = record is not null && record.Backend != Backend.Kind;
            var names = new List<string>();
            if (record is not null && !otherBackend && IsKeyName(record.Name))
            {
                names.Add(record.Name);
            }

            if (nodeId.Length == 16)
            {
                foreach (var origin in origins)
                {
                    names.Add(KeyName(nodeId, origin));
                }
            }

            names.AddRange(Backend.Names());
            var deleted = false;
            foreach (var name in names.Distinct(StringComparer.Ordinal))
            {
                deleted |= Backend.Delete(name);
            }

            if (bytes is not null && !otherBackend)
            {
                PrivateFiles.Delete(_recordPath);
                deleted = true;
            }

            return otherBackend ? NodeKeyDeletion.OtherBackend : deleted ? NodeKeyDeletion.Deleted : NodeKeyDeletion.None;
        }
    }

    /// <summary>Whether <paramref name="name"/> has the node key's shape: the prefix and 64 upper-case hexadecimal digits.</summary>
    public static bool IsKeyName(string? name) =>
        name is not null && name.Length == NamePrefix.Length + 64 && name.StartsWith(NamePrefix, StringComparison.Ordinal)
        && name[NamePrefix.Length..].All(char.IsAsciiHexDigitUpper);

    private NodeKeyRecord? ReadRecord()
    {
        var bytes = PrivateFiles.ReadOrNull(_recordPath);
        if (bytes is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(bytes, CloudLinkJsonContext.Default.NodeKeyRecord);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// Node keys as owner-only PKCS#8 files in <c>&lt;data root&gt;/run/node-key/</c> (0600 in a 0700 directory, written by temporary file,
/// flush and rename): the Linux node's key, and every <c>--test-mode</c> node's key on both systems (02-node-service section 4).
/// </summary>
internal sealed class FileNodeKeyBackend : INodeKeyBackend
{
    private const string Extension = ".pk8";
    private readonly string _directory;

    /// <summary>Creates the backend for a data root (nothing is created until the first key).</summary>
    public FileNodeKeyBackend(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        _directory = Path.Combine(dataRoot, "run", "node-key");
    }

    /// <summary>The directory of the key files.</summary>
    public string Directory => _directory;

    /// <inheritdoc />
    public string Kind => "file";

    /// <inheritdoc />
    public INodeKey? Open(string name)
    {
        var bytes = PrivateFiles.ReadOrNull(PathOf(name));
        if (bytes is null)
        {
            return null;
        }

        var key = ECDsa.Create();
        try
        {
            key.ImportPkcs8PrivateKey(bytes, out _);
            return new SoftwareNodeKey(key);
        }
        catch (CryptographicException)
        {
            key.Dispose();
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <inheritdoc />
    public INodeKey Create(string name)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pkcs8 = key.ExportPkcs8PrivateKey();
        try
        {
            PrivateFiles.WriteAtomic(PathOf(name), pkcs8);
            return new SoftwareNodeKey(key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    /// <inheritdoc />
    public bool Delete(string name) => PrivateFiles.Delete(PathOf(name));

    /// <inheritdoc />
    public IReadOnlyList<string> Names() => System.IO.Directory.Exists(_directory)
        ? [.. System.IO.Directory.EnumerateFiles(_directory, "*" + Extension).Select(path => NodeKeyStore.NamePrefix + Path.GetFileNameWithoutExtension(path))]
        : [];

    private string PathOf(string name)
    {
        if (!NodeKeyStore.IsKeyName(name))
        {
            throw new ArgumentException("A node key name is 'ArcForges.NodeKey.v1.' and 64 upper-case hexadecimal digits.", nameof(name));
        }

        return Path.Combine(_directory, name[NodeKeyStore.NamePrefix.Length..] + Extension);
    }
}

/// <summary>A key held in process memory (from a PKCS#8 file).</summary>
internal sealed class SoftwareNodeKey(ECDsa key) : INodeKey
{
    /// <inheritdoc />
    public byte[] PublicKey { get; } = key.ExportSubjectPublicKeyInfo();

    /// <inheritdoc />
    public byte[] Sign(ReadOnlySpan<byte> message) =>
        CloudIdentity.NormalizeLowS(key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    /// <inheritdoc />
    public void Dispose() => key.Dispose();
}

/// <summary>Owner-only files of the cloud link under <c>run/</c>: 0600 at creation, flushed, then renamed into place.</summary>
internal static class PrivateFiles
{
    private static readonly Lock Gate = new();

    /// <summary>Writes <paramref name="path"/> atomically (0600 on Unix, in a 0700 directory).</summary>
    public static void WriteAtomic(string path, ReadOnlySpan<byte> content)
    {
        var directory = Path.GetDirectoryName(path)!;
        lock (Gate)
        {
            ArcForges.Node.Store.StorePaths.CreatePrivateDirectory(directory);
            var temporary = Path.Combine(directory, "." + Path.GetFileName(path) + "." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)) + ".tmp");
            var renamed = false;
            try
            {
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, BufferSize = 0 };
                if (!OperatingSystem.IsWindows())
                {
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                }

                using (var stream = new FileStream(temporary, options))
                {
                    stream.Write(content);
                    stream.Flush(flushToDisk: true);
                }

                File.Move(temporary, path, overwrite: true);
                renamed = true;
            }
            finally
            {
                if (!renamed)
                {
                    try
                    {
                        File.Delete(temporary);
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                    }
                }
            }
        }
    }

    /// <summary>The file's bytes, or <see langword="null"/> when it does not exist.</summary>
    public static byte[]? ReadOrNull(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>Deletes the file; false when it did not exist.</summary>
    public static bool Delete(string path)
    {
        lock (Gate)
        {
            if (!File.Exists(path))
            {
                return false;
            }

            File.Delete(path);
            return true;
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(NodeKeyRecord))]
[JsonSerializable(typeof(CloudCredentialRecord))]
[JsonSerializable(typeof(CloudLinkFile))]
[JsonSerializable(typeof(CloudKeySetFile))]
internal sealed partial class CloudLinkJsonContext : JsonSerializerContext;
