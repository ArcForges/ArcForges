// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace ArcForges.Capabilities.Tests;

public sealed class ContextSnapshotTests
{
    private static readonly InstallationIdentity Installation = new(
        AppIdentity.ArcScope,
        new DeviceId(new Guid("10000000-0000-0000-0000-000000000001")),
        new InstallationId(new Guid("20000000-0000-0000-0000-000000000001")));

    private static InstanceIdentity Owner(ulong epoch = 1) =>
        new(Installation, new InstanceId(new Guid($"30000000-0000-0000-0000-{epoch:x12}")), epoch);

    [Xunit.Fact]
    public async Task FreezeCopiesTypedProviderOutputBeforeInvocationAndEveryReadIsIsolated()
    {
        var owner = Owner();
        var live = new StringValue { Value = "captured" };
        var provider = new ContextProvider<StringValue>(owner,
            (_, _) => ValueTask.FromResult<IReadOnlyList<StringValue>>([live]));

        var snapshot = await FrozenContextSnapshot.FreezeAsync(
            provider, owner, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        live.Value = "later live value";

        Xunit.Assert.Equal(owner, snapshot.Owner);
        Xunit.Assert.Single(snapshot.Items);
        Xunit.Assert.Equal(StringValue.Descriptor.FullName, snapshot.Items[0].TypeName);
        var firstRead = Xunit.Assert.IsType<StringValue>(snapshot.Items[0].Deserialize());
        Xunit.Assert.Same(StringValue.Descriptor, ((IMessage)firstRead).Descriptor);
        Xunit.Assert.Equal("captured", firstRead.Value);

        firstRead.Value = "mutated consumer copy";
        var secondRead = Xunit.Assert.IsType<StringValue>(snapshot.Items[0].Deserialize());
        Xunit.Assert.Equal("captured", secondRead.Value);
        Xunit.Assert.True(firstRead.CalculateSize() > snapshot.Items[0].SerializedSize);
        Xunit.Assert.Equal((uint)snapshot.Items[0].SerializedSize, snapshot.SerializedBytes);
    }

    [Xunit.Fact]
    public async Task SnapshotCombinesDifferentGeneratedTypesWithoutLosingTheirDescriptors()
    {
        var owner = Owner();
        var strings = new ContextProvider<StringValue>(owner,
            (_, _) => ValueTask.FromResult<IReadOnlyList<StringValue>>([new StringValue { Value = "context" }]));
        var counts = new ContextProvider<Int32Value>(owner,
            (_, _) => ValueTask.FromResult<IReadOnlyList<Int32Value>>([new Int32Value { Value = 7 }]));

        var snapshot = await FrozenContextSnapshot.FreezeAsync(
            [strings, counts], owner, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(2, snapshot.Items.Count);
        Xunit.Assert.Same(StringValue.Descriptor, snapshot.Items[0].Deserialize().Descriptor);
        Xunit.Assert.Same(Int32Value.Descriptor, snapshot.Items[1].Deserialize().Descriptor);
        Xunit.Assert.Equal(
            (uint)(new StringValue { Value = "context" }.CalculateSize() + new Int32Value { Value = 7 }.CalculateSize()),
            snapshot.SerializedBytes);
    }

    [Xunit.Fact]
    public async Task ProviderRefusesCrossProductInstanceOrEpochBeforeInvokingOwner()
    {
        var owner = Owner();
        var called = false;
        var provider = new ContextProvider<StringValue>(owner, (_, _) =>
        {
            called = true;
            return ValueTask.FromResult<IReadOnlyList<StringValue>>([new StringValue { Value = "must not run" }]);
        });

        foreach (var foreign in new[]
        {
            new InstanceIdentity(new InstallationIdentity(AppIdentity.Companion, Installation.DeviceId, Installation.InstallationId), owner.InstanceId, owner.Epoch),
            Owner(epoch: owner.Epoch + 1),
            new InstanceIdentity(Installation, IdentityGeneration.NewInstance(), owner.Epoch),
        })
        {
            var refusal = await Xunit.Assert.ThrowsAsync<ContextScopeMismatchException>(
                async () => await FrozenContextSnapshot.FreezeAsync(
                    provider, foreign, cancellationToken: Xunit.TestContext.Current.CancellationToken).ConfigureAwait(false));
            Xunit.Assert.Equal(owner, refusal.Owner);
            Xunit.Assert.Equal(foreign, refusal.Requested);
        }

        Xunit.Assert.False(called);
    }

    [Xunit.Fact]
    public void OversizedContributionIsRefusedWithoutReturningTruncatedSnapshot()
    {
        var owner = Owner();
        var message = new StringValue { Value = "x" };
        var bytes = (uint)message.CalculateSize();

        var byteRefusal = Xunit.Assert.Throws<ContextBudgetExceededException>(() =>
            FrozenContextSnapshot.Freeze(owner, [message], new ContextSnapshotBudget(10, bytes - 1)));
        Xunit.Assert.Equal(ContextBudgetLimit.SerializedBytes, byteRefusal.Limit);
        Xunit.Assert.Equal((ulong)bytes, byteRefusal.Actual);
        Xunit.Assert.Equal(bytes - 1, byteRefusal.Maximum);

        var itemRefusal = Xunit.Assert.Throws<ContextBudgetExceededException>(() =>
            FrozenContextSnapshot.Freeze(owner, [message, new StringValue { Value = "y" }], new ContextSnapshotBudget(1, 100)));
        Xunit.Assert.Equal(ContextBudgetLimit.ItemCount, itemRefusal.Limit);
        Xunit.Assert.Equal(2ul, itemRefusal.Actual);
        Xunit.Assert.Equal(1u, itemRefusal.Maximum);

        var overMaximum = new StringValue
        {
            Value = new string('x', ContextSnapshotBudget.DefaultMaximumBytes + 1),
        };
        Xunit.Assert.True(overMaximum.CalculateSize() > ContextSnapshotBudget.DefaultMaximumBytes);
        var hardMaximumRefusal = Xunit.Assert.Throws<ContextBudgetExceededException>(() =>
            FrozenContextSnapshot.Freeze(owner, [overMaximum], new ContextSnapshotBudget(
                ContextSnapshotBudget.DefaultMaximumItems,
                ContextSnapshotBudget.DefaultMaximumBytes)));
        Xunit.Assert.Equal(ContextBudgetLimit.SerializedBytes, hardMaximumRefusal.Limit);
        Xunit.Assert.Equal((ulong)overMaximum.CalculateSize(), hardMaximumRefusal.Actual);
        Xunit.Assert.Equal((uint)ContextSnapshotBudget.DefaultMaximumBytes, hardMaximumRefusal.Maximum);
    }

    [Xunit.Fact]
    public void BudgetsCannotExceedPublishedContextBounds()
    {
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new ContextSnapshotBudget(
            ContextSnapshotBudget.DefaultMaximumItems + 1, 1));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new ContextSnapshotBudget(
            1, ContextSnapshotBudget.DefaultMaximumBytes + 1));
        Xunit.Assert.Equal(50u, ContextSnapshotBudget.Default.MaxItems);
        Xunit.Assert.Equal(65_536u, ContextSnapshotBudget.Default.MaxBytes);
    }
}
