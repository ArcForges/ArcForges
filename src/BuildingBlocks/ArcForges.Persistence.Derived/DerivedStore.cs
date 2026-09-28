// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Derived;

using System.Runtime.CompilerServices;

/// <summary>Opaque identity and exact revision of one canonical source record.</summary>
public readonly record struct CanonicalSourceIdentity
{
    public CanonicalSourceIdentity(string kind, string id, string revision)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(revision);

        Kind = kind;
        Id = id;
        Revision = revision;
    }

    public string Kind { get; }

    public string Id { get; }

    public string Revision { get; }

    internal bool IsValid =>
        !string.IsNullOrWhiteSpace(Kind) &&
        !string.IsNullOrWhiteSpace(Id) &&
        !string.IsNullOrWhiteSpace(Revision);
}

/// <summary>A canonical value read from a fixed, read-only snapshot.</summary>
public sealed record CanonicalSourceRecord<TValue>
{
    public CanonicalSourceRecord(CanonicalSourceIdentity identity, TValue value)
    {
        if (!identity.IsValid)
        {
            throw new ArgumentException("A canonical source record requires a complete source identity and revision.", nameof(identity));
        }

        Identity = identity;
        Value = value;
    }

    public CanonicalSourceIdentity Identity { get; }

    public TValue Value { get; }
}

/// <summary>
/// A stable, read-only view of canonical records. Implementations hold one source snapshot for the
/// lifetime of this object; callers cannot write through this boundary.
/// </summary>
public interface ICanonicalSnapshot<TValue> : IAsyncDisposable
{
    IAsyncEnumerable<CanonicalSourceRecord<TValue>> ReadAllAsync(CancellationToken cancellationToken = default);
}

/// <summary>Opens read-only snapshots of the canonical owner data from which a derived store rebuilds.</summary>
public interface ICanonicalSnapshotSource<TValue>
{
    ValueTask<ICanonicalSnapshot<TValue>> OpenSnapshotAsync(CancellationToken cancellationToken = default);
}

/// <summary>A value in a derived store, bound to its exact source revision and pipeline version.</summary>
public sealed record DerivedRecord<TValue>
{
    public DerivedRecord(CanonicalSourceIdentity source, string pipelineVersion, TValue value)
    {
        if (!source.IsValid)
        {
            throw new ArgumentException("A derived record must retain its canonical source identity and revision.", nameof(source));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(pipelineVersion);

        Source = source;
        PipelineVersion = pipelineVersion;
        Value = value;
    }

    public CanonicalSourceIdentity Source { get; }

    public string PipelineVersion { get; }

    public TValue Value { get; }
}

/// <summary>Declared relative cost used to order safe derived-store eviction.</summary>
public enum DerivedRebuildCost
{
    Cheap = 0,
    Moderate = 1,
    Expensive = 2,
}

/// <summary>Describes one independently deletable and rebuildable derived store.</summary>
public sealed record DerivedStoreDescriptor
{
    public DerivedStoreDescriptor(
        string storeId,
        string kind,
        string pipelineVersion,
        DerivedRebuildCost rebuildCost,
        long estimatedBytes,
        DateTimeOffset lastUsedUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storeId);
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(pipelineVersion);
        if (!Enum.IsDefined(rebuildCost))
        {
            throw new ArgumentOutOfRangeException(nameof(rebuildCost));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(estimatedBytes);
        if (lastUsedUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Last-use timestamps must be expressed in UTC.", nameof(lastUsedUtc));
        }

        StoreId = storeId;
        Kind = kind;
        PipelineVersion = pipelineVersion;
        RebuildCost = rebuildCost;
        EstimatedBytes = estimatedBytes;
        LastUsedUtc = lastUsedUtc;
    }

    public string StoreId { get; }

    public string Kind { get; }

    public string PipelineVersion { get; }

    public DerivedRebuildCost RebuildCost { get; }

    public long EstimatedBytes { get; }

    public DateTimeOffset LastUsedUtc { get; }
}

/// <summary>
/// Base type accepted by the eviction policy. Its public mutation surface is restricted to deleting
/// the derived store itself; canonical data is only available to generic stores through a read-only
/// snapshot source.
/// </summary>
public abstract class DerivedStore
{
    private static readonly AsyncLocal<MutationContext?> ActiveMutationContext = new();

    private readonly AsyncMutationGate mutationGate = new();
    private DerivedStoreDescriptor descriptor;

    protected DerivedStore(DerivedStoreDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        this.descriptor = descriptor;
    }

    public DerivedStoreDescriptor Descriptor => Volatile.Read(ref descriptor);

    public async ValueTask DeleteAllAsync(CancellationToken cancellationToken = default)
    {
        await RunMutationAsync(
            () => DeleteDerivedContentsAsync(cancellationToken),
            cancellationToken).ConfigureAwait(false);
    }

    public abstract ValueTask RebuildAsync(CancellationToken cancellationToken = default);

    /// <summary>Deletes only this store's derived rows or files, never canonical owner data.</summary>
    protected abstract ValueTask DeleteDerivedContentsAsync(CancellationToken cancellationToken);

    /// <summary>Publishes this store's current size estimate and last-use time after a successful operation.</summary>
    protected async ValueTask UpdateUsageAsync(long estimatedBytes, DateTimeOffset lastUsedUtc)
    {
        var activeContext = ActiveMutationContext.Value;
        if (activeContext is { IsActive: true } && activeContext.Stores.Contains(this))
        {
            UpdateUsageCore(estimatedBytes, lastUsedUtc);
            return;
        }

        await mutationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            UpdateUsageCore(estimatedBytes, lastUsedUtc);
        }
        finally
        {
            mutationGate.Release();
        }
    }

    /// <summary>Runs an operation that may change this store while excluding eviction and usage updates.</summary>
    protected async ValueTask RunMutationAsync(Func<ValueTask> operation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var scope = EnterMutationScope([this]);
            await operation().ConfigureAwait(false);
        }
        finally
        {
            mutationGate.Release();
        }
    }

    internal static async ValueTask<MutationLease> AcquireMutationLocksAsync(
        IEnumerable<DerivedStore> stores,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stores);
        var orderedStores = stores
            .Distinct()
            .OrderBy(static store => store.Descriptor.StoreId, StringComparer.Ordinal)
            .ToArray();
        var acquiredStores = new List<DerivedStore>(orderedStores.Length);

        try
        {
            foreach (var store in orderedStores)
            {
                await store.mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquiredStores.Add(store);
            }

            return new MutationLease(acquiredStores.ToArray());
        }
        catch
        {
            for (var index = acquiredStores.Count - 1; index >= 0; index--)
            {
                acquiredStores[index].mutationGate.Release();
            }

            throw;
        }
    }

    internal static IDisposable EnterMutationScope(IEnumerable<DerivedStore> stores)
    {
        ArgumentNullException.ThrowIfNull(stores);
        var previous = ActiveMutationContext.Value;
        var active = previous is null
            ? new HashSet<DerivedStore>()
            : new HashSet<DerivedStore>(previous.Stores);
        active.UnionWith(stores);
        var context = new MutationContext(active);
        ActiveMutationContext.Value = context;
        return new MutationScope(previous, context);
    }

    internal async ValueTask DeleteUnderMutationLockAsync(CancellationToken cancellationToken)
    {
        var activeContext = ActiveMutationContext.Value;
        if (activeContext is not { IsActive: true } || !activeContext.Stores.Contains(this))
        {
            throw new InvalidOperationException("Derived-store deletion requires its mutation lock.");
        }

        await DeleteDerivedContentsAsync(cancellationToken).ConfigureAwait(false);
    }

    private void UpdateUsageCore(long estimatedBytes, DateTimeOffset lastUsedUtc)
    {
        var current = Descriptor;
        var updated = new DerivedStoreDescriptor(
            current.StoreId,
            current.Kind,
            current.PipelineVersion,
            current.RebuildCost,
            estimatedBytes,
            lastUsedUtc);
        Interlocked.Exchange(ref descriptor, updated);
    }

    internal sealed class MutationLease(DerivedStore[] stores) : IDisposable
    {
        private DerivedStore[]? heldStores = stores;

        public void Dispose()
        {
            var releasing = Interlocked.Exchange(ref heldStores, null);
            if (releasing is null)
            {
                return;
            }

            for (var index = releasing.Length - 1; index >= 0; index--)
            {
                releasing[index].mutationGate.Release();
            }
        }
    }

    private sealed class MutationContext(HashSet<DerivedStore> stores)
    {
        private int isActive = 1;

        public HashSet<DerivedStore> Stores { get; } = stores;

        public bool IsActive => Volatile.Read(ref isActive) != 0;

        public void Close() => Volatile.Write(ref isActive, 0);
    }

    private sealed class MutationScope(MutationContext? previous, MutationContext context) : IDisposable
    {
        private int disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            context.Close();
            ActiveMutationContext.Value = previous;
        }
    }

    private sealed class AsyncMutationGate
    {
        private const int Waiting = 0;
        private const int Granted = 1;
        private const int Cancelled = 2;

        private readonly object syncRoot = new();
        private readonly Queue<Waiter> waiters = new();
        private bool held;

        public ValueTask WaitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (syncRoot)
            {
                if (!held)
                {
                    held = true;
                    return ValueTask.CompletedTask;
                }

                var waiter = new Waiter();
                waiters.Enqueue(waiter);
                return new ValueTask(WaitForTurnAsync(waiter, cancellationToken));
            }
        }

        public void Release()
        {
            lock (syncRoot)
            {
                if (!held)
                {
                    throw new SemaphoreFullException("The derived-store mutation gate was released without being acquired.");
                }

                while (waiters.TryDequeue(out var waiter))
                {
                    if (waiter.State != Waiting)
                    {
                        continue;
                    }

                    waiter.State = Granted;
                    waiter.Completion.TrySetResult(true);
                    return;
                }

                held = false;
            }
        }

        private async Task WaitForTurnAsync(Waiter waiter, CancellationToken cancellationToken)
        {
            if (cancellationToken.CanBeCanceled)
            {
                using var registration = cancellationToken.Register(
                    static state =>
                    {
                        var cancellation = ((AsyncMutationGate Gate, Waiter Waiter, CancellationToken Token))state!;
                        cancellation.Gate.Cancel(cancellation.Waiter, cancellation.Token);
                    },
                    (this, waiter, cancellationToken));
                await waiter.Completion.Task.ConfigureAwait(false);
            }
            else
            {
                await waiter.Completion.Task.ConfigureAwait(false);
            }
        }

        private void Cancel(Waiter waiter, CancellationToken cancellationToken)
        {
            lock (syncRoot)
            {
                if (waiter.State != Waiting)
                {
                    return;
                }

                waiter.State = Cancelled;
                waiter.Completion.TrySetCanceled(cancellationToken);
            }
        }

        private sealed class Waiter
        {
            public TaskCompletionSource<bool> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

            public int State { get; set; } = Waiting;
        }
    }
}

/// <summary>
/// Implements rebuilds from an owner-provided canonical snapshot. A concrete store projects each
/// canonical record and atomically replaces only its own derived contents; it receives no canonical
/// write API through this abstraction.
/// </summary>
public abstract class DerivedStore<TCanonical, TDerived> : DerivedStore
{
    private readonly ICanonicalSnapshotSource<TCanonical> canonicalSource;

    protected DerivedStore(
        DerivedStoreDescriptor descriptor,
        ICanonicalSnapshotSource<TCanonical> canonicalSource)
        : base(descriptor)
    {
        ArgumentNullException.ThrowIfNull(canonicalSource);
        this.canonicalSource = canonicalSource;
    }

    public sealed override ValueTask RebuildAsync(CancellationToken cancellationToken = default) =>
        RunMutationAsync(async () =>
    {
        var snapshot = await canonicalSource.OpenSnapshotAsync(cancellationToken).ConfigureAwait(false);
        await using (snapshot.ConfigureAwait(false))
        {
            await ReplaceDerivedSnapshotAsync(ProjectSnapshotAsync(snapshot, cancellationToken), cancellationToken).ConfigureAwait(false);
        }
    }, cancellationToken);

    /// <summary>
    /// Atomically replaces this store's derived contents after consuming the projected snapshot.
    /// If projection or publication fails, the previous derived contents remain authoritative only
    /// as a cache; the implementation must never modify canonical data.
    /// </summary>
    protected abstract ValueTask ReplaceDerivedSnapshotAsync(
        IAsyncEnumerable<DerivedRecord<TDerived>> records,
        CancellationToken cancellationToken);

    /// <summary>Projects one canonical record to zero or more derived values.</summary>
    protected abstract IAsyncEnumerable<TDerived> ProjectAsync(
        CanonicalSourceRecord<TCanonical> canonicalRecord,
        CancellationToken cancellationToken);

    private async IAsyncEnumerable<DerivedRecord<TDerived>> ProjectSnapshotAsync(
        ICanonicalSnapshot<TCanonical> snapshot,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var canonicalRecord in snapshot.ReadAllAsync(cancellationToken)
            .WithCancellation(cancellationToken)
            .ConfigureAwait(false))
        {
            await foreach (var value in ProjectAsync(canonicalRecord, cancellationToken)
                .WithCancellation(cancellationToken)
                .ConfigureAwait(false))
            {
                yield return new DerivedRecord<TDerived>(canonicalRecord.Identity, Descriptor.PipelineVersion, value);
            }
        }
    }
}
