// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store;

namespace ArcForges.Node.Core;

/// <summary>What the node found about its previous run when it started (architecture 02 section 2 steps 3-5).</summary>
/// <param name="UncleanShutdown">The previous run did not close the store cleanly (a crash, a kill or a power loss).</param>
/// <param name="BootChanged">The machine rebooted since the previous run (AD-0006 section 3).</param>
/// <param name="IntegrityCheck"><c>PRAGMA quick_check</c> after an unclean shutdown (<c>ok</c>), or <see langword="null"/> when not needed.</param>
/// <param name="StoreOpening">What opening did to the store (created, migrated with a backup, or opened).</param>
public sealed record RecoveryReport(bool UncleanShutdown, bool BootChanged, string? IntegrityCheck, StoreOpening StoreOpening);

/// <summary>
/// A crash recovery hook (02 section 2 step 5): a subsystem that holds durable work across node runs re-attaches it, or finalizes
/// it, while the node is RECOVERING and before the API listens. The execution supervisor registers here when execution exists
/// (re-attach running attempts, finalize from exit records, mark LOST); recovery reads the store and writes only through the
/// command processor.
/// </summary>
public interface INodeRecoveryParticipant
{
    /// <summary>A short name for the log (for example <c>attempts</c>).</summary>
    string Name { get; }

    /// <summary>Recovers this subsystem's durable work.</summary>
    Task RecoverAsync(RecoveryReport report, CommandProcessor processor, CancellationToken cancellationToken);
}

/// <summary>The store's crash checks.</summary>
public static class StoreRecovery
{
    /// <summary>
    /// <c>PRAGMA quick_check</c> on a read-only connection (02 section 2 step 3: after an unclean shutdown). Returns <c>ok</c> for an
    /// intact store, otherwise the first problem SQLite reports.
    /// </summary>
    public static string QuickCheck(NodeStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        return store.Read(reader => reader.Scalar("PRAGMA quick_check;") as string ?? "no result");
    }
}
