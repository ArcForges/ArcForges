// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Versions;

namespace ArcForges.Persistence.Sqlite;

/// <summary>Outcome of opening an owner store and validating its snapshot/journal boundary.</summary>
public enum StoreRecoveryOutcome
{
    Clean,
    RecoveredWithLossOfUncommittedWork,
    UnrecoverableWithPreservedEvidence
}

/// <summary>Durable recovery evidence for owners deciding whether to enter read-first safe start.</summary>
public sealed record StoreRecoveryReport(StoreRecoveryOutcome Outcome, long VerifiedThrough,
    long RecoveredThrough, string? EvidencePath, string Detail)
{
    public bool RequiresSafeStart => Outcome != StoreRecoveryOutcome.Clean;
}

/// <summary>Thrown when a store cannot safely open; the original database remains available as evidence.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1032:Implement standard exception constructors",
    Justification = "Recovery failures are created by the store so every exception carries its typed recovery report.")]
public sealed class StoreRecoveryException : IOException
{
    internal StoreRecoveryException(StoreRecoveryReport report, Exception? innerException = null)
        : base(report.Detail, innerException) => Report = report;

    public StoreRecoveryReport Report { get; }
}

/// <summary>Receipt for one checksummed, self-describing SQLite snapshot.</summary>
public sealed record JournalSnapshotReceipt(long ThroughSequence, StorageSchemaVersion SchemaVersion, string Path);
