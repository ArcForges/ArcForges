// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace ArcForges.Capabilities.Tests;

public sealed class ActionAvailabilityTests
{
    private static readonly InstallationIdentity Installation = new(
        AppIdentity.ArcScope,
        IdentityGeneration.NewDevice(),
        IdentityGeneration.NewInstallation());

    [Xunit.Fact]
    public async Task EvaluateAvailabilityAsyncReturnsEachOfTheNineAuthorizedFacts()
    {
        (AvailabilityResult Result, ActionAvailabilityRule Rule)[] expected =
        [
            (AvailabilityResult.Available, ReturnAvailable),
            (AvailabilityResult.NotApplicableToContext, ReturnNotApplicableToContext),
            (AvailabilityResult.AppNotInstalled, ReturnAppNotInstalled),
            (AvailabilityResult.AppNotRunning, ReturnAppNotRunning),
            (AvailabilityResult.IncompatibleVersion, ReturnIncompatibleVersion),
            (AvailabilityResult.PermissionRequired, ReturnPermissionRequired),
            (AvailabilityResult.EntitlementRequired, ReturnEntitlementRequired),
            (AvailabilityResult.PolicyDisabled, ReturnPolicyDisabled),
            (AvailabilityResult.TemporarilyUnavailable, ReturnTemporarilyUnavailable),
        ];

        Xunit.Assert.Equal(expected.Select(item => item.Result), System.Enum.GetValues<AvailabilityResult>());
        var actions = expected.Select((item, index) => new ActionDescriptor(
            new ActionKey($"test.action.{index:D2}"),
            ["IScopeOperations.GetSession"],
            item.Rule));
        var provider = new CapabilityAvailabilityProvider(CapabilityRegistry.CreateInitial(), actions);
        var context = Context();

        for (var index = 0; index < expected.Length; index++)
        {
            var outcome = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
                new ActionKey($"test.action.{index:D2}"),
                context,
                Xunit.TestContext.Current.CancellationToken);

            Xunit.Assert.Equal(OutcomeKind.Success, outcome.Kind);
            Xunit.Assert.True(outcome.TryGetValue(out var actual));
            Xunit.Assert.Equal(expected[index].Result, actual);
            Xunit.Assert.False(outcome.TryGetFailure(out _));
        }
    }

    [Xunit.Fact]
    public async Task EvaluationUsesOnlyBoundCapabilitiesAndFrozenContextWithoutMutatingEither()
    {
        var source = new StringValue { Value = "captured" };
        var context = Context(source);
        source.Value = "changed after freeze";
        var registry = CapabilityRegistry.CreateInitial();
        var provider = new CapabilityAvailabilityProvider(registry,
        [
            new ActionDescriptor(
                new ActionKey("test.action.context"),
                ["IScopeOperations.GetSession"],
                RequireCapturedContextAndBoundCapability),
        ]);

        var first = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
            new ActionKey("test.action.context"), context, Xunit.TestContext.Current.CancellationToken);
        var second = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
            new ActionKey("test.action.context"), context, Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.True(first.TryGetValue(out var firstResult));
        Xunit.Assert.True(second.TryGetValue(out var secondResult));
        Xunit.Assert.Equal(AvailabilityResult.Available, firstResult);
        Xunit.Assert.Equal(firstResult, secondResult);
        Xunit.Assert.Equal("captured", Xunit.Assert.IsType<StringValue>(context.Items.Single().Deserialize()).Value);
        Xunit.Assert.Equal(EffectKind.PureRead, registry.Find("IScopeOperations.GetSession")!.Descriptor.Effect);
    }

    [Xunit.Fact]
    public async Task UnknownActionsAndInvalidRuleResultsFailWithExistingTypedErrors()
    {
        var provider = new CapabilityAvailabilityProvider(CapabilityRegistry.CreateInitial(),
        [
            new ActionDescriptor(new ActionKey("test.action.invalid"), ["IScopeOperations.GetSession"], ReturnInvalidResult),
        ]);
        var context = Context();

        var unknown = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
            new ActionKey("test.action.missing"), context, Xunit.TestContext.Current.CancellationToken);
        var invalid = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
            new ActionKey("test.action.invalid"), context, Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(OutcomeKind.Failure, unknown.Kind);
        Xunit.Assert.True(unknown.TryGetFailure(out var unknownFailure));
        Xunit.Assert.Equal("validation.invalid_request", unknownFailure!.Code);
        Xunit.Assert.Equal(OutcomeKind.Failure, invalid.Kind);
        Xunit.Assert.True(invalid.TryGetFailure(out var invalidFailure));
        Xunit.Assert.Equal("internal.unexpected", invalidFailure!.Code);
        Xunit.Assert.False(System.Enum.IsDefined((AvailabilityResult)int.MaxValue));
    }

    [Xunit.Fact]
    public void StaticActionRegistrationRejectsCapturesDuplicateKeysAndUnregisteredCapabilities()
    {
        var captured = AvailabilityResult.Available;
        ActionAvailabilityRule capturingRule = (_, _) => captured;

        Xunit.Assert.Throws<ArgumentException>(() => new ActionDescriptor(
            new ActionKey("test.action.capture"), ["IScopeOperations.GetSession"], capturingRule));
        Xunit.Assert.Throws<ArgumentException>(() => new ActionDescriptor(
            new ActionKey("test.action.duplicate-capability"),
            ["IScopeOperations.GetSession", "IScopeOperations.GetSession"],
            ReturnAvailable));
        Xunit.Assert.Throws<ArgumentException>(() => new CapabilityAvailabilityProvider(
            CapabilityRegistry.CreateInitial(),
            [new ActionDescriptor(new ActionKey("test.action.unknown-capability"), ["missing.capability"], ReturnAvailable)]));
        Xunit.Assert.Throws<ArgumentException>(() => new CapabilityAvailabilityProvider(
            CapabilityRegistry.CreateInitial(),
            [
                new ActionDescriptor(new ActionKey("test.action.duplicate"), ["IScopeOperations.GetSession"], ReturnAvailable),
                new ActionDescriptor(new ActionKey("test.action.duplicate"), ["IScopeOperations.GetSession"], ReturnAvailable),
            ]));
    }

    [Xunit.Fact]
    public async Task CancellationIsObservedBeforeRunningTheAvailabilityRule()
    {
        var provider = new CapabilityAvailabilityProvider(CapabilityRegistry.CreateInitial(),
        [
            new ActionDescriptor(new ActionKey("test.action.cancel"), ["IScopeOperations.GetSession"], ReturnAvailable),
        ]);
        using var source = new CancellationTokenSource();
        await source.CancelAsync().ConfigureAwait(true);

        await Xunit.Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
                new ActionKey("test.action.cancel"), Context(), source.Token).ConfigureAwait(true));
    }

    private static FrozenContextSnapshot Context(params IMessage[] messages)
    {
        var owner = new InstanceIdentity(Installation, IdentityGeneration.NewInstance(), 1);
        return FrozenContextSnapshot.Freeze(owner, messages, ContextSnapshotBudget.Default);
    }

    private static AvailabilityResult RequireCapturedContextAndBoundCapability(
        IReadOnlyList<CapabilityRegistration> capabilities,
        FrozenContextSnapshot context)
    {
        var captured = context.Items
            .Where(item => item.TypeName == StringValue.Descriptor.FullName)
            .Select(item => item.Deserialize())
            .OfType<StringValue>()
            .SingleOrDefault();

        return capabilities.Count == 1 && capabilities[0].Key == "IScopeOperations.GetSession" &&
            captured?.Value == "captured"
            ? AvailabilityResult.Available
            : AvailabilityResult.NotApplicableToContext;
    }

    private static AvailabilityResult ReturnAvailable(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.Available;

    private static AvailabilityResult ReturnNotApplicableToContext(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.NotApplicableToContext;

    private static AvailabilityResult ReturnAppNotInstalled(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.AppNotInstalled;

    private static AvailabilityResult ReturnAppNotRunning(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.AppNotRunning;

    private static AvailabilityResult ReturnIncompatibleVersion(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.IncompatibleVersion;

    private static AvailabilityResult ReturnPermissionRequired(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.PermissionRequired;

    private static AvailabilityResult ReturnEntitlementRequired(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.EntitlementRequired;

    private static AvailabilityResult ReturnPolicyDisabled(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.PolicyDisabled;

    private static AvailabilityResult ReturnTemporarilyUnavailable(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        AvailabilityResult.TemporarilyUnavailable;

    private static AvailabilityResult ReturnInvalidResult(IReadOnlyList<CapabilityRegistration> _, FrozenContextSnapshot __) =>
        (AvailabilityResult)int.MaxValue;
}
