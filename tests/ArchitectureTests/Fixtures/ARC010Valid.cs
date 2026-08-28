// SPDX-License-Identifier: AGPL-3.0-only
// ARC-010 compliant sample. This file participates in compilation; its violating twin is
// ARC010Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal sealed class MonotonicCounter
{
    private long _value;

    public long Next() => System.Threading.Interlocked.Increment(ref _value);
}
