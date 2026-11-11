// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Files;

/// <summary>
/// In-process reservations for private file staging. A coordinator reserves before creating either stage,
/// retains the lease until its actual handles are disposed, and supplies the committed named-stage usage on restart.
/// This class neither creates nor disposes a filesystem object and is not an approval or journal implementation.
/// </summary>
internal sealed class FileStageBudget
{
    internal const int MaximumMutations = 64;
    internal const long MaximumBytes = 256L * 1024 * 1024;
    internal const long MaximumFileBytes = 4L * 1024 * 1024;
    private readonly object _gate = new();
    private int _active;
    private long _bytes;

    internal Lease? TryReserve(long originalBytes, long intendedBytes, int durableMutations = 0, long durableBytes = 0)
    {
        if (durableMutations is < 0 or > MaximumMutations || durableBytes is < 0 or > MaximumBytes)
            throw new InvalidDataException("The durable stage budget is inconsistent.");
        if (originalBytes is < 0 or > MaximumFileBytes)
            throw new ArgumentOutOfRangeException(nameof(originalBytes), "Each stage must have a bounded nonnegative length.");
        if (intendedBytes is < 0 or > MaximumFileBytes)
            throw new ArgumentOutOfRangeException(nameof(intendedBytes), "Each stage must have a bounded nonnegative length.");
        var charge = checked(originalBytes + intendedBytes);
        lock (_gate)
        {
            if (_active >= MaximumMutations - durableMutations || _bytes > MaximumBytes - durableBytes ||
                charge > MaximumBytes - durableBytes - _bytes) return null;
            _active++;
            _bytes += charge;
            return new Lease(this, charge);
        }
    }

    internal (int Active, long Bytes) Snapshot()
    {
        lock (_gate) return (_active, _bytes);
    }

    private void Release(long charge)
    {
        lock (_gate)
        {
            if (_active <= 0 || charge < 0 || _bytes < charge)
                throw new InvalidOperationException("The stage budget is inconsistent.");
            _active--;
            _bytes -= charge;
        }
    }

    internal sealed class Lease(FileStageBudget owner, long charge) : IDisposable
    {
        private FileStageBudget? _owner = owner;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release(charge);
    }
}
