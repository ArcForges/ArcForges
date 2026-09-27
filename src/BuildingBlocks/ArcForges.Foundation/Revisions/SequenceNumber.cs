// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Foundation;

public enum SequenceRelation
{
    None = 0,
    Duplicate = 1,
    Older = 2,
    Contiguous = 3,
    Gap = 4,
}

/// <summary>Delivery position scoped to one channel; never an owner revision.</summary>
public readonly record struct SequenceNumber
{
    public SequenceNumber(Guid channelId, DeliverySequence value)
    {
        if (channelId == Guid.Empty)
        {
            throw new ArgumentException("A channel identity is required.", nameof(channelId));
        }

        ChannelId = channelId;
        Value = value;
    }

    public Guid ChannelId { get; }
    public DeliverySequence Value { get; }
    public SequenceNumber Next() => new(ChannelId, new DeliverySequence(checked(Value.Value + 1)));

    /// <summary>Classifies delivery without treating duplicates or old values as gaps.</summary>
    public SequenceRelation RelativeTo(SequenceNumber previous)
    {
        if (ChannelId == Guid.Empty || ChannelId != previous.ChannelId)
        {
            throw new ArgumentException("Sequence ordering requires the same channel.", nameof(previous));
        }

        if (Value.Value == previous.Value.Value)
        {
            return SequenceRelation.Duplicate;
        }

        if (Value.Value < previous.Value.Value)
        {
            return SequenceRelation.Older;
        }

        return Value.Value - previous.Value.Value == 1 ? SequenceRelation.Contiguous : SequenceRelation.Gap;
    }
}
