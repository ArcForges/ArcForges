// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;

namespace ArcForges.Persistence.Resources;

/// <summary>
/// Stores immutable content-addressed objects and resolves opaque BlobIds without exposing a path.
/// A single process owns a store root at a time; operations serialize metadata publication while
/// reads within that process may run concurrently.
/// </summary>
public sealed class ManagedResourceStore : IDisposable
{
    private const int IdentityRecordLength = 96;
    private const int ReferenceHeaderLength = 28;
    private const int ChecksumLength = 32;
    private const int MaximumReferrerBytes = 1024;
    private static readonly byte[] IdentityMagic = "AFMAP001"u8.ToArray();
    private static readonly byte[] ReferenceMagic = "AFREF001"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly string _root;
    private readonly string _objects;
    private readonly string _identities;
    private readonly string _references;
    private readonly FileStream _processLock;
    private readonly ReaderWriterLockSlim _gate = new(LockRecursionPolicy.NoRecursion);
    private readonly Action<ResourceStoreFaultPoint, BlobId>? _fault;
    private bool _disposed;
    private int _disposeStarted;

    private ManagedResourceStore(string root, Action<ResourceStoreFaultPoint, BlobId>? fault)
    {
        _root = root;
        _objects = Path.Combine(root, "objects");
        _identities = Path.Combine(root, "identities");
        _references = Path.Combine(root, "references");
        Directory.CreateDirectory(_objects);
        Directory.CreateDirectory(_identities);
        Directory.CreateDirectory(_references);

        // The lock file is a process-wide single-writer guard. It is deliberately independent
        // of the logical BlobId and stays open for this store's lifetime.
        _processLock = new FileStream(Path.Combine(root, ".resource-store.lock"), FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
        _fault = fault;

        try
        {
            _ = LoadState();
        }
        catch
        {
            _processLock.Dispose();
            throw;
        }
    }

    /// <summary>Opens or creates the root directory and validates its durable metadata before use.</summary>
    public static ManagedResourceStore Open(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        return new ManagedResourceStore(Path.GetFullPath(root), null);
    }

    /// <summary>
    /// Stores bytes under a new opaque identity. If <paramref name="initialReferrer"/> is supplied,
    /// the durable object and identity mapping are published before the reference row.
    /// </summary>
    public BlobId Store(ReadOnlySpan<byte> content, string? initialReferrer = null)
    {
        byte[]? referrerBytes = initialReferrer is null ? null : EncodeReferrer(initialReferrer);
        _gate.EnterWriteLock();
        try
        {
            EnsureOpen();
            BlobId id = IdentityGeneration.NewBlob();
            byte[] hash = SHA256.HashData(content);
            string hashText = ToHashText(hash);

            EnsureObject(hashText, hash, content);
            _fault?.Invoke(ResourceStoreFaultPoint.ObjectCommitted, id);

            var identity = new IdentityRecord(id, hashText, content.Length);
            WriteIdentity(identity);
            _fault?.Invoke(ResourceStoreFaultPoint.IdentityCommitted, id);

            if (referrerBytes is not null)
            {
                AddReferenceCore(initialReferrer!, referrerBytes, identity);
                _fault?.Invoke(ResourceStoreFaultPoint.ReferenceCommitted, id);
            }

            return id;
        }
        finally { _gate.ExitWriteLock(); }
    }

    /// <summary>Returns content only after its complete length and SHA-256 digest have been verified.</summary>
    public byte[] Read(BlobId id)
    {
        _gate.EnterReadLock();
        try
        {
            EnsureOpen();
            var state = LoadState();
            if (!state.Identities.TryGetValue(id, out var identity))
                throw new KeyNotFoundException("The BlobId is not present in this store.");
            return ReadVerifiedObject(identity);
        }
        finally { _gate.ExitReadLock(); }
    }

    /// <summary>Adds an idempotent logical referrer row after verifying the referenced object.</summary>
    public void AddReference(string referrer, BlobId id)
    {
        byte[] referrerBytes = EncodeReferrer(referrer);
        _gate.EnterWriteLock();
        try
        {
            EnsureOpen();
            var state = LoadState();
            if (!state.Identities.TryGetValue(id, out var identity))
                throw new KeyNotFoundException("A reference cannot be added before the BlobId is stored.");
            _ = ReadVerifiedObject(identity);
            AddReferenceCore(referrer, referrerBytes, identity);
        }
        finally { _gate.ExitWriteLock(); }
    }

    /// <summary>Removes one referrer row; returns false when that exact row did not exist.</summary>
    public bool RemoveReference(string referrer, BlobId id)
    {
        byte[] referrerBytes = EncodeReferrer(referrer);
        _gate.EnterWriteLock();
        try
        {
            EnsureOpen();
            string path = ReferencePath(referrerBytes, id);
            if (!File.Exists(path)) return false;
            var row = ReadReference(path);
            if (row.Id != id || row.Referrer != referrer)
                throw new InvalidDataException("Reference row does not match its path identity.");
            File.Delete(path);
            return true;
        }
        finally { _gate.ExitWriteLock(); }
    }

    /// <summary>Derives a count from the durable referrer table; no stored count is authoritative.</summary>
    public int ReferenceCount(BlobId id)
    {
        _gate.EnterReadLock();
        try
        {
            EnsureOpen();
            var state = LoadState();
            if (!state.Identities.ContainsKey(id)) throw new KeyNotFoundException("The BlobId is not present in this store.");
            return state.References.Count(row => row.Id == id);
        }
        finally { _gate.ExitReadLock(); }
    }

    /// <summary>
    /// Collects identities with no referrer rows, then removes objects unreachable from every
    /// remaining identity. The ordering makes each interruption leave only reclaimable orphans.
    /// </summary>
    public GarbageCollectionResult CollectGarbage()
    {
        _gate.EnterWriteLock();
        try
        {
            EnsureOpen();
            var state = LoadState();
            var referenced = state.References.Select(row => row.Id).ToHashSet();
            int removedIdentities = 0;
            foreach (var identity in state.Identities.Values)
            {
                if (referenced.Contains(identity.Id)) continue;
                File.Delete(IdentityPath(identity.Id));
                removedIdentities++;
            }

            // A crash here leaves unreferenced objects behind, never a referenced object missing.
            _fault?.Invoke(ResourceStoreFaultPoint.GarbageCollectionMappingsRemoved, default);

            var stillMappedHashes = LoadIdentities().Values.Select(identity => identity.Hash).ToHashSet(StringComparer.Ordinal);
            int removedObjects = 0;
            foreach (string path in Directory.EnumerateFiles(_objects, "*.blob", SearchOption.AllDirectories))
            {
                string hash = Path.GetFileNameWithoutExtension(path);
                if (!IsCanonicalHash(hash) || stillMappedHashes.Contains(hash)) continue;
                File.Delete(path);
                removedObjects++;
            }

            // Pending object files can only be abandoned writes: the process lock excludes a live
            // writer while collection runs, and no identity points at a pending filename.
            foreach (string pending in Directory.EnumerateFiles(_objects, "*.blob.pending-*", SearchOption.AllDirectories))
                File.Delete(pending);

            return new GarbageCollectionResult(removedIdentities, removedObjects);
        }
        finally { _gate.ExitWriteLock(); }
    }

    private void EnsureObject(string hashText, byte[] expectedHash, ReadOnlySpan<byte> content)
    {
        string path = ObjectPath(hashText);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path))
        {
            if (ObjectMatches(path, content.Length, expectedHash)) return;

            if (LoadIdentities().Values.Any(identity => identity.Hash == hashText))
                throw new InvalidDataException("A mapped content-addressed object is corrupt; refusing to replace it.");
            File.Delete(path); // An unmapped corrupt object is an orphan, not canonical data.
        }

        string pending = path + ".pending-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                output.Write(content);
                output.Flush(flushToDisk: true);
            }
            try { File.Move(pending, path, overwrite: false); }
            catch (IOException) when (File.Exists(path))
            {
                File.Delete(pending);
                if (!ObjectMatches(path, content.Length, expectedHash))
                    throw new InvalidDataException("A conflicting object occupies the content address.");
            }
        }
        catch
        {
            if (File.Exists(pending)) File.Delete(pending);
            throw;
        }
    }

    private void WriteIdentity(IdentityRecord identity)
    {
        byte[] record = new byte[IdentityRecordLength];
        IdentityMagic.CopyTo(record, 0);
        identity.Id.Value.TryWriteBytes(record.AsSpan(8, 16));
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(24, 8), identity.Length);
        Convert.FromHexString(identity.Hash).CopyTo(record, 32);
        SHA256.HashData(record.AsSpan(0, 64), record.AsSpan(64, ChecksumLength));
        WriteCreateNewAtomic(IdentityPath(identity.Id), record);
    }

    private void AddReferenceCore(string referrer, byte[] referrerBytes, IdentityRecord identity)
    {
        string path = ReferencePath(referrerBytes, identity.Id);
        if (File.Exists(path))
        {
            var existing = ReadReference(path);
            if (existing.Id == identity.Id && existing.Referrer == referrer) return;
            throw new InvalidDataException("A conflicting reference occupies this reference-table key.");
        }

        byte[] record = new byte[ReferenceHeaderLength + referrerBytes.Length + ChecksumLength];
        ReferenceMagic.CopyTo(record, 0);
        identity.Id.Value.TryWriteBytes(record.AsSpan(8, 16));
        BinaryPrimitives.WriteInt32LittleEndian(record.AsSpan(24, 4), referrerBytes.Length);
        referrerBytes.CopyTo(record, ReferenceHeaderLength);
        SHA256.HashData(record.AsSpan(0, record.Length - ChecksumLength), record.AsSpan(record.Length - ChecksumLength));
        WriteCreateNewAtomic(path, record);
    }

    private static void WriteCreateNewAtomic(string path, ReadOnlySpan<byte> record)
    {
        string pending = path + ".pending-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                output.Write(record);
                output.Flush(flushToDisk: true);
            }
            File.Move(pending, path, overwrite: false);
        }
        catch
        {
            if (File.Exists(pending)) File.Delete(pending);
            throw;
        }
    }

    private StoreState LoadState()
    {
        var identities = LoadIdentities();
        var references = new List<ReferenceRecord>();
        foreach (string path in Directory.EnumerateFiles(_references, "*.ref", SearchOption.TopDirectoryOnly))
        {
            var row = ReadReference(path);
            if (!identities.ContainsKey(row.Id))
                throw new InvalidDataException("A referrer row points to a missing identity mapping.");
            if (Path.GetFileName(path) != ReferenceFileName(EncodeReferrer(row.Referrer), row.Id))
                throw new InvalidDataException("A referrer row is stored under the wrong key.");
            references.Add(row);
        }
        return new StoreState(identities, references);
    }

    private Dictionary<BlobId, IdentityRecord> LoadIdentities()
    {
        var identities = new Dictionary<BlobId, IdentityRecord>();
        foreach (string path in Directory.EnumerateFiles(_identities, "*.map", SearchOption.TopDirectoryOnly))
        {
            var identity = ReadIdentity(path);
            if (Path.GetFileName(path) != IdentityFileName(identity.Id) || !identities.TryAdd(identity.Id, identity))
                throw new InvalidDataException("Identity mapping filename or key is invalid.");
        }
        return identities;
    }

    private static IdentityRecord ReadIdentity(string path)
    {
        var info = new FileInfo(path);
        if (info.Length != IdentityRecordLength) throw new InvalidDataException("Identity mapping length is invalid.");
        byte[] bytes = File.ReadAllBytes(path);
        if (!bytes.AsSpan(0, 8).SequenceEqual(IdentityMagic)
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes.AsSpan(0, 64)), bytes.AsSpan(64, ChecksumLength)))
            throw new InvalidDataException("Identity mapping checksum or header is invalid.");
        var id = new BlobId(new Guid(bytes.AsSpan(8, 16)));
        long length = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(24, 8));
        string hash = Convert.ToHexString(bytes.AsSpan(32, 32));
        if (id.Value == Guid.Empty || length < 0) throw new InvalidDataException("Identity mapping values are invalid.");
        return new IdentityRecord(id, hash, length);
    }

    private static ReferenceRecord ReadReference(string path)
    {
        var info = new FileInfo(path);
        if (info.Length < ReferenceHeaderLength + ChecksumLength || info.Length > ReferenceHeaderLength + MaximumReferrerBytes + ChecksumLength)
            throw new InvalidDataException("Referrer row length is invalid.");
        byte[] bytes = File.ReadAllBytes(path);
        int referrerLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(24, 4));
        if (!bytes.AsSpan(0, 8).SequenceEqual(ReferenceMagic)
            || referrerLength <= 0 || referrerLength > MaximumReferrerBytes
            || bytes.Length != ReferenceHeaderLength + referrerLength + ChecksumLength
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes.AsSpan(0, bytes.Length - ChecksumLength)), bytes.AsSpan(bytes.Length - ChecksumLength)))
            throw new InvalidDataException("Referrer row checksum or header is invalid.");
        var id = new BlobId(new Guid(bytes.AsSpan(8, 16)));
        string referrer;
        try { referrer = StrictUtf8.GetString(bytes, ReferenceHeaderLength, referrerLength); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("Referrer row is not valid UTF-8.", error); }
        _ = EncodeReferrer(referrer);
        if (id.Value == Guid.Empty) throw new InvalidDataException("Referrer row BlobId is invalid.");
        return new ReferenceRecord(id, referrer);
    }

    private byte[] ReadVerifiedObject(IdentityRecord identity)
    {
        string path = ObjectPath(identity.Hash);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        if (input.Length != identity.Length || input.Length > int.MaxValue)
            throw new InvalidDataException("Stored object length does not match its identity mapping.");
        byte[] bytes = new byte[(int)input.Length];
        input.ReadExactly(bytes);
        byte[] actual = SHA256.HashData(bytes);
        if (!CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(identity.Hash)))
            throw new InvalidDataException("Stored object failed SHA-256 integrity verification.");
        return bytes;
    }

    private static bool ObjectMatches(string path, long expectedLength, byte[] expectedHash)
    {
        try
        {
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
            return input.Length == expectedLength
                && CryptographicOperations.FixedTimeEquals(SHA256.HashData(input), expectedHash);
        }
        catch (IOException) { return false; }
    }

    private static byte[] EncodeReferrer(string referrer)
    {
        ArgumentNullException.ThrowIfNull(referrer);
        if (string.IsNullOrWhiteSpace(referrer) || referrer.Contains('\0', StringComparison.Ordinal))
            throw new ArgumentException("Referrer must be a nonempty logical key.", nameof(referrer));
        byte[] bytes = StrictUtf8.GetBytes(referrer);
        if (bytes.Length > MaximumReferrerBytes) throw new ArgumentOutOfRangeException(nameof(referrer));
        return bytes;
    }

    private string IdentityPath(BlobId id) => Path.Combine(_identities, IdentityFileName(id));
    private static string IdentityFileName(BlobId id) => id.Value.ToString("N") + ".map";
    private string ObjectPath(string hash) => Path.Combine(_objects, hash[..2], hash + ".blob");
    private string ReferencePath(byte[] referrerBytes, BlobId id) => Path.Combine(_references, ReferenceFileName(referrerBytes, id));
    private static string ReferenceFileName(byte[] referrerBytes, BlobId id) => ToHashText(SHA256.HashData(referrerBytes)) + "-" + id.Value.ToString("N") + ".ref";
    private static string ToHashText(byte[] hash) => Convert.ToHexString(hash);
    private static bool IsCanonicalHash(string value) => value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private void EnsureOpen() => ObjectDisposedException.ThrowIf(_disposed, this);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0) return;
        _gate.EnterWriteLock();
        try
        {
            _disposed = true;
            _processLock.Dispose();
        }
        finally { _gate.ExitWriteLock(); }
        _gate.Dispose();
    }

    private sealed record IdentityRecord(BlobId Id, string Hash, long Length);
    private sealed record ReferenceRecord(BlobId Id, string Referrer);
    private sealed record StoreState(Dictionary<BlobId, IdentityRecord> Identities, List<ReferenceRecord> References);

    internal static ManagedResourceStore OpenForTesting(string root, Action<ResourceStoreFaultPoint, BlobId>? fault) =>
        new(Path.GetFullPath(root), fault);
}

/// <summary>Internal deterministic interruption points used only by offline crash-safety tests.</summary>
internal enum ResourceStoreFaultPoint
{
    ObjectCommitted,
    IdentityCommitted,
    ReferenceCommitted,
    GarbageCollectionMappingsRemoved
}

public sealed record GarbageCollectionResult(int RemovedIdentities, int RemovedObjects);
