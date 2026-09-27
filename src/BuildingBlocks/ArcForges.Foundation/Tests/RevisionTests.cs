// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class RevisionTests
{
    [Fact]
    public void ConcurrentWritersDetectStaleExpectedRevision()
    {
        var current = new Revision(Guid.NewGuid(), new CloudRevision(1));
        var expected = current;
        Assert.True(current.MatchesExpected(expected));
        current = current.Next();
        Assert.False(current.MatchesExpected(expected));
        Assert.True(current.CompareTo(expected) > 0);
        Assert.Throws<ArgumentException>(() => current.MatchesExpected(new Revision(Guid.NewGuid(), new CloudRevision(1))));
        Assert.Throws<ArgumentOutOfRangeException>(() => Revision.FromWire(current.ObjectId, CloudRevision.NewRootPrecondition()));
        Assert.Throws<InvalidOperationException>(() => default(Revision).ToWire());
        Assert.Throws<OverflowException>(() => new Revision(current.ObjectId, new CloudRevision(long.MaxValue)).Next());
    }

    [Fact]
    public void SequenceGapsAreScopedAndDistinctFromDuplicateAndOldDelivery()
    {
        var previous = new SequenceNumber(Guid.NewGuid(), new DeliverySequence(100));
        Assert.Equal(SequenceRelation.Duplicate, previous.RelativeTo(previous));
        Assert.Equal(SequenceRelation.Contiguous, previous.Next().RelativeTo(previous));
        Assert.Equal(SequenceRelation.Gap, new SequenceNumber(previous.ChannelId, new DeliverySequence(130)).RelativeTo(previous));
        Assert.Equal(SequenceRelation.Older, new SequenceNumber(previous.ChannelId, new DeliverySequence(99)).RelativeTo(previous));
        Assert.Throws<ArgumentException>(() => new SequenceNumber(Guid.NewGuid(), new DeliverySequence(101)).RelativeTo(previous));
        Assert.Throws<OverflowException>(() => new SequenceNumber(previous.ChannelId, new DeliverySequence(ulong.MaxValue)).Next());
    }
}
