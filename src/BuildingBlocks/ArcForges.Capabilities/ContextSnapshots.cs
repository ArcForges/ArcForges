// SPDX-License-Identifier: AGPL-3.0-only
using Google.Protobuf;
using Google.Protobuf.Reflection;

namespace ArcForges.Capabilities;

/// <summary>Explicit bounds for one invocation's context contribution and immutable snapshot.</summary>
public sealed record ContextSnapshotBudget
{
    public const int DefaultMaximumItems = 200;
    public const int DefaultMaximumBytes = 262_144;

    public ContextSnapshotBudget(uint maxItems, uint maxBytes)
    {
        if (maxItems > DefaultMaximumItems)
        {
            throw new ArgumentOutOfRangeException(nameof(maxItems), $"Context item limits cannot exceed {DefaultMaximumItems}.");
        }

        if (maxBytes > DefaultMaximumBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes), $"Context byte limits cannot exceed {DefaultMaximumBytes}.");
        }

        MaxItems = maxItems;
        MaxBytes = maxBytes;
    }

    public uint MaxItems { get; }
    public uint MaxBytes { get; }

    public static ContextSnapshotBudget Default { get; } = new(50, 65_536);
}

/// <summary>A provider contributes generated protobuf messages for its owning app instance.</summary>
public interface IContextProvider
{
    InstanceIdentity Owner { get; }
    ValueTask<IReadOnlyList<IMessage>> ProvideMessagesAsync(
        InstanceIdentity expectedOwner,
        CancellationToken cancellationToken = default);
}

public interface IContextProvider<TMessage> : IContextProvider
    where TMessage : class, IMessage<TMessage>
{
    ValueTask<IReadOnlyList<TMessage>> ProvideAsync(
        InstanceIdentity expectedOwner,
        CancellationToken cancellationToken = default);
}

/// <summary>Explicit app-instance-scoped provider; it never resolves another product or instance.</summary>
public sealed class ContextProvider<TMessage> : IContextProvider<TMessage>
    where TMessage : class, IMessage<TMessage>
{
    private readonly Func<InstanceIdentity, CancellationToken, ValueTask<IReadOnlyList<TMessage>>> _provide;

    public ContextProvider(
        InstanceIdentity owner,
        Func<InstanceIdentity, CancellationToken, ValueTask<IReadOnlyList<TMessage>>> provide)
    {
        Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        _provide = provide ?? throw new ArgumentNullException(nameof(provide));
    }

    public InstanceIdentity Owner { get; }

    public ValueTask<IReadOnlyList<TMessage>> ProvideAsync(
        InstanceIdentity expectedOwner,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedOwner);
        if (expectedOwner != Owner)
        {
            throw new ContextScopeMismatchException(Owner, expectedOwner);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return _provide(Owner, cancellationToken);
    }

    async ValueTask<IReadOnlyList<IMessage>> IContextProvider.ProvideMessagesAsync(
        InstanceIdentity expectedOwner,
        CancellationToken cancellationToken)
    {
        var messages = await ProvideAsync(expectedOwner, cancellationToken).ConfigureAwait(false);
        return messages.Cast<IMessage>().ToArray();
    }
}

/// <summary>Refusal because a provider is being read under a different captured app-instance identity.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Design",
    "CA1032:Implement standard exception constructors",
    Justification = "This domain refusal requires both owner identities; generic constructors could create an invalid diagnostic.")]
public sealed class ContextScopeMismatchException(InstanceIdentity owner, InstanceIdentity requested)
    : InvalidOperationException("Context can only be contributed to the captured owning application instance.")
{
    public InstanceIdentity Owner { get; } = owner;
    public InstanceIdentity Requested { get; } = requested;
}

public enum ContextBudgetLimit
{
    ItemCount,
    SerializedBytes,
}

/// <summary>Explicit, non-truncating refusal when contributed context exceeds invocation limits.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Design",
    "CA1032:Implement standard exception constructors",
    Justification = "This domain refusal requires the limit, actual size and maximum to preserve actionable evidence.")]
public sealed class ContextBudgetExceededException(
    ContextBudgetLimit limit,
    ulong actual,
    uint maximum)
    : InvalidOperationException($"Context {limit} limit exceeded: {actual} is greater than {maximum}.")
{
    public ContextBudgetLimit Limit { get; } = limit;
    public ulong Actual { get; } = actual;
    public uint Maximum { get; } = maximum;
}

/// <summary>An invocation-time copy of one typed protobuf message.</summary>
public interface IFrozenContextItem
{
    string TypeName { get; }
    int SerializedSize { get; }
    IMessage Deserialize();
}

public sealed class FrozenContextItem : IFrozenContextItem
{
    private readonly MessageDescriptor _descriptor;
    private readonly byte[] _serialized;

    internal FrozenContextItem(MessageDescriptor descriptor, byte[] serialized)
    {
        _descriptor = descriptor;
        _serialized = serialized;
    }

    public string TypeName => _descriptor.FullName;
    public int SerializedSize => _serialized.Length;

    /// <summary>Returns a fresh mutable message clone; no returned object can mutate the frozen bytes.</summary>
    public IMessage Deserialize() => _descriptor.Parser.ParseFrom(_serialized);
}

/// <summary>Immutable context bytes and type descriptors captured before a capability invocation.</summary>
public sealed class FrozenContextSnapshot
{
    private readonly IFrozenContextItem[] _items;

    private FrozenContextSnapshot(InstanceIdentity owner, IFrozenContextItem[] items, uint serializedBytes)
    {
        Owner = owner;
        _items = items;
        SerializedBytes = serializedBytes;
    }

    public InstanceIdentity Owner { get; }
    public IReadOnlyList<IFrozenContextItem> Items => Array.AsReadOnly(_items);
    public uint SerializedBytes { get; }

    public static FrozenContextSnapshot Freeze<TMessage>(
        InstanceIdentity owner,
        IEnumerable<TMessage> messages,
        ContextSnapshotBudget budget)
        where TMessage : class, IMessage<TMessage>
        => Freeze(owner, messages.Cast<IMessage>(), budget);

    public static FrozenContextSnapshot Freeze(
        InstanceIdentity owner,
        IEnumerable<IMessage> messages,
        ContextSnapshotBudget budget)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(budget);

        var frozen = new List<IFrozenContextItem>();
        ulong totalBytes = 0;
        foreach (var message in messages)
        {
            if (message is null)
            {
                throw new ArgumentException("A context provider cannot contribute a null protobuf message.", nameof(messages));
            }

            if ((ulong)frozen.Count >= budget.MaxItems)
            {
                throw new ContextBudgetExceededException(ContextBudgetLimit.ItemCount, (ulong)frozen.Count + 1, budget.MaxItems);
            }

            var descriptor = message.Descriptor;
            var serialized = message.ToByteArray();
            totalBytes = checked(totalBytes + (uint)serialized.Length);
            if (totalBytes > budget.MaxBytes)
            {
                throw new ContextBudgetExceededException(ContextBudgetLimit.SerializedBytes, totalBytes, budget.MaxBytes);
            }

            frozen.Add(new FrozenContextItem(descriptor, serialized));
        }

        return new FrozenContextSnapshot(owner, frozen.ToArray(), (uint)totalBytes);
    }

    public static async ValueTask<FrozenContextSnapshot> FreezeAsync<TMessage>(
        IContextProvider<TMessage> provider,
        InstanceIdentity capturedOwner,
        ContextSnapshotBudget? budget = null,
        CancellationToken cancellationToken = default)
        where TMessage : class, IMessage<TMessage>
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(capturedOwner);
        return await FreezeAsync([provider], capturedOwner, budget, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<FrozenContextSnapshot> FreezeAsync(
        IEnumerable<IContextProvider> providers,
        InstanceIdentity capturedOwner,
        ContextSnapshotBudget? budget = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(providers);
        ArgumentNullException.ThrowIfNull(capturedOwner);
        var messages = new List<IMessage>();
        foreach (var provider in providers)
        {
            ArgumentNullException.ThrowIfNull(provider);
            ArgumentNullException.ThrowIfNull(provider.Owner);
            if (provider.Owner != capturedOwner)
            {
                throw new ContextScopeMismatchException(provider.Owner, capturedOwner);
            }

            var contribution = await provider.ProvideMessagesAsync(capturedOwner, cancellationToken).ConfigureAwait(false);
            messages.AddRange(contribution);
        }

        return Freeze(capturedOwner, messages, budget ?? ContextSnapshotBudget.Default);
    }
}
