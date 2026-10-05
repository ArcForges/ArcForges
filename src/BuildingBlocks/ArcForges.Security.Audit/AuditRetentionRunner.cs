// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Security;

namespace ArcForges.Security.Audit;

/// <summary>What the retention runner did with one complete UTC month.</summary>
public enum AuditRetentionOutcome
{
    None = 0,

    /// <summary>The expired month was purged and its authority and purge receipts were committed with the deletion.</summary>
    Purged = 1,

    /// <summary>An active legal hold covers the month, so it was left untouched.</summary>
    SkippedHeld = 2,

    /// <summary>A stored row of the month failed verification (digest, owner, policy, partition, executor or closed shape); the month was left untouched.</summary>
    FailedVerification = 3,

    /// <summary>The store refused the purge (a hold placed meanwhile, a month emptied or purged by a concurrent run, or the policy no longer permitting it); the month was left untouched.</summary>
    Refused = 4,
}

/// <summary>The result for one month: the month, what happened, and the purge receipt when it was purged.</summary>
public sealed record AuditRetentionPartitionResult(AuditPartition Partition, AuditRetentionOutcome Outcome, AuditPurgeReceipt? Receipt);

/// <summary>The complete result of one retention run, oldest month first. It carries no event content.</summary>
public sealed class AuditRetentionRunResult
{
    internal AuditRetentionRunResult(IReadOnlyList<AuditRetentionPartitionResult> partitions, bool moreExpiredMonthsRemain)
    {
        Partitions = partitions;
        MoreExpiredMonthsRemain = moreExpiredMonthsRemain;
    }

    public IReadOnlyList<AuditRetentionPartitionResult> Partitions { get; }

    /// <summary>True when the run reached its bound and further expired months may exist; run again.</summary>
    public bool MoreExpiredMonthsRemain { get; }

    public int PurgedCount => Partitions.Count(static result => result.Outcome == AuditRetentionOutcome.Purged);
}

/// <summary>
/// The production entry to policy-governed audit retention. One run purges the expired, unheld, complete UTC months of its own store
/// under the retention policy that file declared at creation, and nothing else: the caller chooses neither a month nor a time (the
/// store's own clock decides what has expired), cannot mint or hold a maintenance capability, and cannot reach the hold-release
/// authority. For every month the runner asks the store's internal authority for a fresh single-use capability bound to exactly that
/// month, so a purge is always audited by its authority and purge receipts and committed with the deletion. A month with an active
/// legal hold is skipped; a month that fails verification is left untouched and reported without stopping the other months; a month the
/// store refuses (a hold placed meanwhile, a concurrent purge) is reported as refused. A maintenance chain of another realm or owner is
/// refused at construction and nothing is ever deleted for it. Appends by other writers continue throughout: each purge is one
/// serialized store transaction.
/// </summary>
/// <remarks>
/// The runner purges nothing the declared policy has not expired, never edits an event, and cannot shorten retention: expiry is the
/// end of the month plus the stored retention days. It does not schedule itself; the host composes and calls it. It is proved offline
/// against a real store; no host composition root calls it yet.
/// </remarks>
public sealed class AuditRetentionRunner
{
    /// <summary>The most expired months one run examines; a larger backlog is finished by further runs.</summary>
    public const int MaximumMonthsPerRun = 240;

    private static readonly TimeSpan CapabilityLifetime = TimeSpan.FromMinutes(1);

    private readonly AuditStore store;
    private readonly ActorChain maintenanceActor;
    private readonly AuditSoftwareIdentity softwareIdentity;

    /// <param name="store">The owner-scoped audit store whose declared policy governs the run.</param>
    /// <param name="maintenanceActor">The actor chain recorded as the retention authority; it must belong to the store's realm and owner.</param>
    /// <param name="softwareIdentity">The software identity recorded with every authority receipt; it must match the chain's final delegated actor.</param>
    public AuditRetentionRunner(AuditStore store, ActorChain maintenanceActor, AuditSoftwareIdentity softwareIdentity)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        ArgumentNullException.ThrowIfNull(maintenanceActor);
        ArgumentNullException.ThrowIfNull(softwareIdentity);
        if (maintenanceActor.Actors.Count > 0 && !StringComparer.Ordinal.Equals(maintenanceActor.Actors[^1].SoftwareIdentity, softwareIdentity.Value))
        {
            throw new ArgumentException("Software identity must match the final delegated actor.", nameof(softwareIdentity));
        }

        store.RequireOwner(maintenanceActor);
        this.maintenanceActor = maintenanceActor;
        this.softwareIdentity = softwareIdentity;
    }

    /// <summary>
    /// Purges every expired, unheld month of the store (at most <see cref="MaximumMonthsPerRun"/>) and reports each. A cancelled token
    /// stops before the next month; a month already purged stays purged and its receipts stay committed.
    /// </summary>
    public AuditRetentionRunResult RunOnce(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var expired = store.ListExpiredPartitions(MaximumMonthsPerRun + 1);
        var results = new List<AuditRetentionPartitionResult>(Math.Min(expired.Count, MaximumMonthsPerRun));
        foreach (var partition in expired.Take(MaximumMonthsPerRun))
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(Purge(partition));
        }

        return new AuditRetentionRunResult(results.AsReadOnly(), expired.Count > MaximumMonthsPerRun);
    }

    private AuditRetentionPartitionResult Purge(AuditPartition partition)
    {
        if (store.ReadActiveLegalHolds(partition, 1).Count > 0)
        {
            return new AuditRetentionPartitionResult(partition, AuditRetentionOutcome.SkippedHeld, null);
        }

        try
        {
            var capability = store.CreateMaintenanceCapability(
                AuditMaintenanceAction.PurgeExpiredPartition, partition, maintenanceActor, softwareIdentity, CapabilityLifetime);
            return new AuditRetentionPartitionResult(partition, AuditRetentionOutcome.Purged, store.PurgeExpiredPartition(capability));
        }
        catch (InvalidDataException)
        {
            return new AuditRetentionPartitionResult(partition, AuditRetentionOutcome.FailedVerification, null);
        }
        catch (ObjectDisposedException)
        {
            // A disposed store is not a refusal of one month: it propagates so the run stops.
            throw;
        }
        catch (InvalidOperationException)
        {
            return new AuditRetentionPartitionResult(partition, AuditRetentionOutcome.Refused, null);
        }
    }
}
