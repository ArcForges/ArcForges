// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// In-process reservations for private file staging. Real file commands combine these leases with the durable
/// named-stage and held-journal ledger inside the Node writer. A lease is released only after its owned handles close.
/// This class does not create a filesystem object, authorize a caller or perform an effect.
/// </summary>
internal sealed class FileStageBudget
{
    internal const int MaximumMutations = 64;
    internal const long MaximumBytes = 256L * 1024 * 1024;
    internal const long MaximumFileBytes = 4L * 1024 * 1024;
    private readonly object _gate = new();
    private readonly Dictionary<long, Allocation> _allocations = [];
    private long _next;
    private int _active;
    private long _bytes;

    // Isolated native component callers without command metadata keep the existing bounded in-process API.
    internal Lease? TryReserve(long originalBytes, long intendedBytes, int durableMutations = 0, long durableBytes = 0)
    {
        ValidateSizes(originalBytes, intendedBytes);
        if (durableMutations is < 0 or > MaximumMutations || durableBytes is < 0 or > MaximumBytes)
            throw new InvalidDataException("The durable stage budget is inconsistent.");
        var charge = checked(originalBytes + intendedBytes);
        lock (_gate)
        {
            if (_active >= MaximumMutations - durableMutations || _bytes > MaximumBytes - durableBytes ||
                charge > MaximumBytes - durableBytes - _bytes) return null;
            return Add(commandId: null, originalBytes, intendedBytes);
        }
    }

    /// <summary>Reserves a real command's possible native stages against the same durable writer snapshot.</summary>
    internal Lease? TryReserveCommand(StoreReader reader, ReadOnlySpan<byte> commandId, long originalBytes, long intendedBytes)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StoreIds.Validate(commandId, nameof(commandId));
        if (commandId.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("A nonzero command ID is required.", nameof(commandId));
        ValidateSizes(originalBytes, intendedBytes);
        var key = commandId.ToArray();
        var charge = checked(originalBytes + intendedBytes);
        lock (_gate)
        {
            var (active, bytes) = CombinedLocked(reader);
            var alreadyActive = FileStageCapacity.HasActiveCommand(reader, key) ||
                _allocations.Values.Any(value => value.CommandId is { } id && id.AsSpan().SequenceEqual(key));
            if ((!alreadyActive && active >= MaximumMutations) || bytes > MaximumBytes || charge > MaximumBytes - bytes) return null;
            return Add(key, originalBytes, intendedBytes);
        }
    }

    /// <summary>
    /// Counts each active command once, but adds every distinct unaccounted in-process object. Bytes are deduplicated
    /// against durable records only after command, slot, platform, native identity and length all match.
    /// </summary>
    internal (int Active, long Bytes) CombinedUsage(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        lock (_gate) return CombinedLocked(reader);
    }

    internal bool HasCommand(ReadOnlySpan<byte> commandId)
    {
        lock (_gate)
            foreach (var item in _allocations.Values)
                if (item.CommandId is { } id && id.AsSpan().SequenceEqual(commandId)) return true;
        return false;
    }

    internal (int Active, long Bytes) Snapshot()
    {
        lock (_gate) return (_active, _bytes);
    }

    private (int Active, long Bytes) CombinedLocked(StoreReader reader)
    {
        var (active, bytes) = FileStageCapacity.Durable(reader);
        var commands = new HashSet<string>(StringComparer.Ordinal);
        var stages = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in _allocations.Values)
        {
            if (item.CommandId is not { } command)
            {
                active = checked(active + 1);
                bytes = checked(bytes + item.OriginalBytes + item.IntendedBytes);
                continue;
            }
            var key = Convert.ToHexString(command);
            if (commands.Add(key) && !FileStageCapacity.HasActiveCommand(reader, command)) active = checked(active + 1);
            AddBytes(1, item.OriginalBytes, item.OriginalIdentity);
            AddBytes(2, item.IntendedBytes, item.IntendedIdentity);

            void AddBytes(int slot, long size, RegisteredWorkspaces.RootIdentity? identity)
            {
                if (identity is not null)
                {
                    if (FileStageCapacity.HasExactStage(reader, command, slot, identity, size)) return;
                    var stageKey = key + ":" + slot.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" +
                        identity.Platform.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + Convert.ToHexString(identity.Bytes) +
                        ":" + size.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    if (!stages.Add(stageKey)) return;
                }
                bytes = checked(bytes + size);
            }
        }
        if (active < 0 || bytes < 0) throw new InvalidDataException("The combined file stage capacity is inconsistent.");
        return (active, bytes);
    }

    private Lease Add(byte[]? commandId, long originalBytes, long intendedBytes)
    {
        var key = checked(++_next);
        _allocations.Add(key, new Allocation(commandId, originalBytes, intendedBytes));
        _active = checked(_active + 1);
        _bytes = checked(_bytes + originalBytes + intendedBytes);
        return new Lease(this, key);
    }

    private void Bind(long key, RegisteredWorkspaces.RootIdentity? original, RegisteredWorkspaces.RootIdentity intended)
    {
        ArgumentNullException.ThrowIfNull(intended);
        lock (_gate)
        {
            var exists = _allocations.TryGetValue(key, out var allocation);
            ObjectDisposedException.ThrowIf(!exists, this);
            if (allocation!.OriginalIdentity is not null || allocation.IntendedIdentity is not null)
                throw new InvalidOperationException("The stage reservation is already bound or invalid.");
            if (original is not null) RegisteredWorkspaces.RootIdentity.ValidateEncoding(original.Platform, original.Bytes);
            RegisteredWorkspaces.RootIdentity.ValidateEncoding(intended.Platform, intended.Bytes);
            allocation.OriginalIdentity = original is null ? null : new RegisteredWorkspaces.RootIdentity(original.Platform, original.Bytes.ToArray());
            allocation.IntendedIdentity = new RegisteredWorkspaces.RootIdentity(intended.Platform, intended.Bytes.ToArray());
        }
    }

    private void Release(long key)
    {
        lock (_gate)
        {
            if (!_allocations.Remove(key, out var allocation) || _active <= 0 || _bytes < allocation.OriginalBytes + allocation.IntendedBytes)
                throw new InvalidOperationException("The stage budget is inconsistent.");
            _active--;
            _bytes -= allocation.OriginalBytes + allocation.IntendedBytes;
        }
    }

    private static void ValidateSizes(long originalBytes, long intendedBytes)
    {
        if (originalBytes is < 0 or > MaximumFileBytes)
            throw new ArgumentOutOfRangeException(nameof(originalBytes), "Each stage must have a bounded nonnegative length.");
        if (intendedBytes is < 0 or > MaximumFileBytes)
            throw new ArgumentOutOfRangeException(nameof(intendedBytes), "Each stage must have a bounded nonnegative length.");
    }

    private sealed class Allocation(byte[]? commandId, long originalBytes, long intendedBytes)
    {
        internal byte[]? CommandId { get; } = commandId;
        internal long OriginalBytes { get; } = originalBytes;
        internal long IntendedBytes { get; } = intendedBytes;
        internal RegisteredWorkspaces.RootIdentity? OriginalIdentity { get; set; }
        internal RegisteredWorkspaces.RootIdentity? IntendedIdentity { get; set; }
    }

    internal sealed class Lease(FileStageBudget owner, long key) : IDisposable
    {
        private FileStageBudget? _owner = owner;

        internal void BindStages(RegisteredWorkspaces.RootIdentity? original, RegisteredWorkspaces.RootIdentity intended) =>
            (_owner ?? throw new ObjectDisposedException(nameof(Lease))).Bind(key, original, intended);

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release(key);
    }
}
