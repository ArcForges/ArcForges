// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Sqlite;

internal interface IJournalWriter
{
    void Initialize(SqliteCommitContext context);
    JournalSequence GetNextSequence(SqliteCommitContext context);
    void Append(SqliteCommitContext context, JournalEntry entry);
}

internal interface IJournalReader
{
    IReadOnlyList<JournalEntry> Read(SqliteReadContext context, JournalSequence? after, int limit);
}

internal interface IJournalRetention
{
    void Truncate(SqliteCommitContext context, VerifiedSnapshotBoundary boundary);
}

/// <summary>The snapshot owner must verify the actual durable snapshot before authorizing truncation.</summary>
internal interface IJournalSnapshotVerifier
{
    bool IsVerified(VerifiedSnapshotBoundary boundary);
}

internal sealed class VerifiedSnapshotBoundary
{
    private readonly byte[] journalChecksum;
    private readonly byte[] snapshotChecksum;

    internal VerifiedSnapshotBoundary(JournalSequence through, ReadOnlySpan<byte> journalChecksum,
        ReadOnlySpan<byte> snapshotChecksum)
    {
        through.RequireStore(through.StoreId);
        if (journalChecksum.Length != 32 || snapshotChecksum.Length != 32)
            throw new ArgumentException("Both snapshot and journal checksums must be SHA256.");
        Through = through;
        this.journalChecksum = journalChecksum.ToArray();
        this.snapshotChecksum = snapshotChecksum.ToArray();
    }

    internal JournalSequence Through { get; }
    internal ReadOnlyMemory<byte> JournalChecksum => journalChecksum.ToArray();
    internal ReadOnlyMemory<byte> SnapshotChecksum => snapshotChecksum.ToArray();
}
