// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;

namespace ArcForges.Node.Store;

/// <summary>
/// <c>env_snapshot</c>: content-addressed caller environments without secret-shaped values (R-EXE-017). An environment is
/// stored once however many tasks reference it; <c>ref_count</c> counts the referencing tasks, and an unreferenced snapshot
/// is deleted 24 hours after its last use.
/// </summary>
/// <remarks>
/// The digest is SHA-256 over the canonical entries: the domain <c>arcforges.env-snapshot.v1</c>, then the entry count and
/// each entry (name, value) sorted by the UTF-8 bytes of the name, then the count and the sealed names in the same order;
/// every count and length is a 32-bit little-endian prefix and every string is UTF-8. <c>entries</c> holds the serialized
/// canonical <see cref="EnvSnapshot"/>, Brotli-compressed behind a one-byte codec marker.
/// </remarks>
public sealed class EnvSnapshots
{
    /// <summary>The most entries a snapshot holds (TaskSpec validation: at most 4,096 caller variables).</summary>
    public const int MaxEntries = 4096;

    /// <summary>The largest uncompressed snapshot (1 MiB).</summary>
    public const int MaxBytes = 1024 * 1024;

    /// <summary>How long an unreferenced snapshot is kept after its last use.</summary>
    public static readonly TimeSpan UnreferencedRetention = TimeSpan.FromHours(24);

    private const byte BrotliCodec = 1;
    private static readonly byte[] Domain = Encoding.UTF8.GetBytes("arcforges.env-snapshot.v1");
    private readonly NodeStore _store;

    internal EnvSnapshots(NodeStore store) => _store = store;

    /// <summary>A copy of <paramref name="snapshot"/> with entries and sealed names in canonical order.</summary>
    public static EnvSnapshot Canonicalize(EnvSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var canonical = new EnvSnapshot();
        canonical.Entries.AddRange(snapshot.Entries.OrderBy(entry => entry.Name, Utf8Order.Instance).Select(entry => entry.Clone()));
        canonical.SealedNames.AddRange(snapshot.SealedNames.Order(Utf8Order.Instance));
        for (var index = 1; index < canonical.Entries.Count; index++)
        {
            if (string.Equals(canonical.Entries[index - 1].Name, canonical.Entries[index].Name, StringComparison.Ordinal))
            {
                throw new ArgumentException($"The environment names the variable {canonical.Entries[index].Name} twice.", nameof(snapshot));
            }
        }

        return canonical;
    }

    /// <summary>The content address of <paramref name="snapshot"/>.</summary>
    public static byte[] Digest(EnvSnapshot snapshot)
    {
        var canonical = Canonicalize(snapshot);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        AppendCount(hash, canonical.Entries.Count);
        foreach (var entry in canonical.Entries)
        {
            AppendString(hash, entry.Name);
            AppendString(hash, entry.Value);
        }

        AppendCount(hash, canonical.SealedNames.Count);
        foreach (var name in canonical.SealedNames)
        {
            AppendString(hash, name);
        }

        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Stores <paramref name="snapshot"/> if it is new, adds one task reference and returns its digest
    /// (the task's <c>env_digest</c>).
    /// </summary>
    public static byte[] Reference(StoreTransaction transaction, EnvSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        var canonical = Canonicalize(snapshot);
        if (canonical.Entries.Count > MaxEntries)
        {
            throw new ArgumentException($"A caller environment holds at most {MaxEntries} variables.", nameof(snapshot));
        }

        var digest = Digest(canonical);
        var now = transaction.NowMicroseconds;
        var touched = transaction.Execute(
            "UPDATE env_snapshot SET ref_count = ref_count + 1, last_used_at = $now WHERE env_digest = $digest;",
            ("$now", now),
            ("$digest", digest));
        if (touched == 0)
        {
            var bytes = canonical.ToByteArray();
            if (bytes.Length > MaxBytes)
            {
                throw new ArgumentException("A caller environment is at most 1 MiB.", nameof(snapshot));
            }

            transaction.Execute(
                """
                INSERT INTO env_snapshot (env_digest, entries, entry_count, byte_size, ref_count, created_at, last_used_at)
                VALUES ($digest, $entries, $count, $size, 1, $now, $now);
                """,
                ("$digest", digest),
                ("$entries", Compress(bytes)),
                ("$count", canonical.Entries.Count),
                ("$size", bytes.Length),
                ("$now", now));
        }

        return digest;
    }

    /// <summary>Removes one task reference (the task was purged); the snapshot stays for 24 hours after its last use.</summary>
    public static void Release(StoreTransaction transaction, ReadOnlySpan<byte> digest)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        var changed = transaction.Execute(
            "UPDATE env_snapshot SET ref_count = ref_count - 1, last_used_at = $now WHERE env_digest = $digest AND ref_count > 0;",
            ("$now", transaction.NowMicroseconds),
            ("$digest", digest.ToArray()));
        if (changed != 1)
        {
            throw new InvalidOperationException("The environment snapshot is unknown or has no references.");
        }
    }

    /// <summary>Reads a snapshot by digest, or <see langword="null"/>.</summary>
    public static EnvSnapshot? Get(StoreReader reader, ReadOnlySpan<byte> digest)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand("SELECT entries, byte_size FROM env_snapshot WHERE env_digest = $digest;");
        command.Parameters.AddWithValue("$digest", digest.ToArray());
        using var row = command.ExecuteReader();
        return row.Read() ? EnvSnapshot.Parser.ParseFrom(Decompress((byte[])row.GetValue(0), checked((int)row.GetInt64(1)))) : null;
    }

    /// <summary>Reads a snapshot by digest on a read-only connection, or <see langword="null"/>.</summary>
    public EnvSnapshot? Get(ReadOnlySpan<byte> digest)
    {
        var copy = digest.ToArray();
        return _store.Read(reader => Get(reader, copy));
    }

    /// <summary>Housekeeping: deletes snapshots without references whose last use is 24 hours old. Returns the number deleted.</summary>
    public int DeleteUnreferenced() => _store.Write(transaction => transaction.Execute(
        "DELETE FROM env_snapshot WHERE ref_count = 0 AND last_used_at <= $cutoff;",
        ("$cutoff", transaction.NowMicroseconds - (long)UnreferencedRetention.TotalMicroseconds)));

    private static byte[] Compress(byte[] bytes)
    {
        var buffer = new byte[BrotliEncoder.GetMaxCompressedLength(bytes.Length) + 1];
        buffer[0] = BrotliCodec;
        if (!BrotliEncoder.TryCompress(bytes, buffer.AsSpan(1), out var written, quality: 9, window: 22))
        {
            throw new InvalidOperationException("Brotli could not compress the environment snapshot.");
        }

        return buffer.AsSpan(0, written + 1).ToArray();
    }

    private static byte[] Decompress(byte[] stored, int size)
    {
        if (stored.Length == 0 || stored[0] != BrotliCodec)
        {
            throw new InvalidDataException("The environment snapshot has an unknown encoding.");
        }

        var bytes = new byte[size];
        if (!BrotliDecoder.TryDecompress(stored.AsSpan(1), bytes, out var written) || written != size)
        {
            throw new InvalidDataException("The environment snapshot does not decompress to its recorded size.");
        }

        return bytes;
    }

    private static void AppendCount(IncrementalHash hash, int count)
    {
        Span<byte> prefix = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(prefix, checked((uint)count));
        hash.AppendData(prefix);
    }

    private static void AppendString(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        AppendCount(hash, bytes.Length);
        hash.AppendData(bytes);
    }
}

/// <summary>Orders strings by their UTF-8 bytes (Unicode code point order).</summary>
public sealed class Utf8Order : IComparer<string>
{
    /// <summary>The comparer.</summary>
    public static Utf8Order Instance { get; } = new();

    /// <inheritdoc />
    public int Compare(string? x, string? y)
    {
        if (ReferenceEquals(x, y))
        {
            return 0;
        }

        if (x is null)
        {
            return -1;
        }

        if (y is null)
        {
            return 1;
        }

        return Encoding.UTF8.GetBytes(x).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(y));
    }
}
