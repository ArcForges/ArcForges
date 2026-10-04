// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
#pragma warning disable CA1859 // Tests deliberately use the port interfaces to exercise their contracts.
using ArcForges.Assistant.Abstractions;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace AssistantAbstractionsTests;

public sealed class ActionRegistryTests
{
    private static readonly Func<FrozenHostContext?, ActionAvailability> Available = _ => new ActionAvailability(true);

    [Xunit.Fact]
    public async Task RegisteredActionIsInvokedThroughItsTypedTokenOnlyForItsOwner()
    {
        var owner = TestData.Host();
        IHostActions actions = TestData.Registry(owner);
        int calls = 0;
        var token = actions.Register<string, int>(TestData.Descriptor(),
            (request, _) =>
            {
                calls++;
                return ValueTask.FromResult(Outcome.Success(request.Length));
            }, Available);

        Xunit.Assert.Equal(owner, token.Owner);
        Xunit.Assert.Equal("measurements.read", token.Descriptor.OperationId);
        Xunit.Assert.True(actions.GetAvailability("measurements.read").TryGetValue(out var availability));
        Xunit.Assert.True(availability.IsAvailable);
        var result = await actions.InvokeAsync(token, owner, "four", cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(result.TryGetValue(out int length));
        Xunit.Assert.Equal(4, length);
        Xunit.Assert.Equal(1, calls);

        var foreignTarget = TestData.Host(TestData.Installed(AssistantProductIdentity.Companion));
        Refused(await actions.InvokeAsync(token, foreignTarget, "x", cancellationToken: Xunit.TestContext.Current.CancellationToken),
            "perm.capability_denied");
        var staleTarget = TestData.Host(epoch: 8);
        Refused(await actions.InvokeAsync(token, staleTarget, "x", cancellationToken: Xunit.TestContext.Current.CancellationToken),
            "perm.capability_denied");
        Xunit.Assert.Equal(1, calls);
        await Xunit.Assert.ThrowsAsync<ArgumentNullException>(async () => await actions.InvokeAsync(token, null!, "x",
            cancellationToken: Xunit.TestContext.Current.CancellationToken));
    }

    [Xunit.Fact]
    public void AllowlistRejectsUnlistedOperationsCapabilitiesDuplicatesAndLateRegistration()
    {
        var owner = TestData.Host();
        var registry = TestData.Registry(owner);
        Xunit.Assert.Throws<ArgumentException>(() => registry.Register<string, string>(TestData.Descriptor("other.operation"),
            (_, _) => ValueTask.FromResult(Outcome.Success("")), Available));
        Xunit.Assert.Throws<ArgumentException>(() => registry.Register<string, string>(
            TestData.Descriptor(capability: "admin.everything"), (_, _) => ValueTask.FromResult(Outcome.Success("")), Available));

        registry.Register<string, string>(TestData.Descriptor(), (_, _) => ValueTask.FromResult(Outcome.Success("")), Available);
        Xunit.Assert.Throws<ArgumentException>(() => registry.Register<string, string>(TestData.Descriptor(),
            (_, _) => ValueTask.FromResult(Outcome.Success("")), Available));
        Xunit.Assert.Throws<ArgumentNullException>(() => registry.Register<string, string>(null!,
            (_, _) => ValueTask.FromResult(Outcome.Success("")), Available));
        Xunit.Assert.Throws<ArgumentNullException>(() => registry.Register<string, string>(TestData.Descriptor("annotations.append", "annotations.write"),
            null!, Available));
        Xunit.Assert.Throws<ArgumentNullException>(() => registry.Register<string, string>(TestData.Descriptor("annotations.append", "annotations.write"),
            (_, _) => ValueTask.FromResult(Outcome.Success("")), null!));

        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantActionRegistry(owner, null!, []));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantActionRegistry(owner, [], null!));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantActionRegistry(null!, [], []));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantActionRegistry(owner, [" "], []));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantActionRegistry(owner, [], [""]));
    }

    [Xunit.Fact]
    public async Task UnavailableActionsAreRefusedBeforeTheHandlerAndExposeTheirReason()
    {
        var owner = TestData.Host();
        var registry = TestData.Registry(owner);
        int calls = 0;
        var token = registry.Register<string, string>(TestData.Descriptor(),
            (request, _) =>
            {
                calls++;
                return ValueTask.FromResult(Outcome.Success(request));
            },
            context => context is { Included.Count: > 0 }
                ? new ActionAvailability(true)
                : new ActionAvailability(false, "availability.no_selection"));

        Xunit.Assert.True(registry.GetAvailability("measurements.read").TryGetValue(out var none));
        Xunit.Assert.False(none.IsAvailable);
        Xunit.Assert.Equal("availability.no_selection", none.ReasonKey);
        Refused(await registry.InvokeAsync(token, owner, "x", cancellationToken: Xunit.TestContext.Current.CancellationToken),
            "perm.capability_denied");
        Xunit.Assert.Equal(0, calls);

        var context = new FrozenHostContext(owner, new AssistantContextBudget(2, 2048), [TestData.Selection()]);
        Xunit.Assert.True(registry.GetAvailability("measurements.read", context).TryGetValue(out var some));
        Xunit.Assert.True(some.IsAvailable);
        var ok = await registry.InvokeAsync(token, owner, "x", context, Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(ok.TryGetValue(out var echoed));
        Xunit.Assert.Equal("x", echoed);
        Xunit.Assert.Equal(1, calls);
    }

    [Xunit.Fact]
    public async Task ContextsFromAnotherHostAreRefusedForAvailabilityAndInvocation()
    {
        var owner = TestData.Host();
        var foreign = TestData.Host(TestData.Installed(AssistantProductIdentity.Companion));
        var registry = TestData.Registry(owner);
        var token = registry.Register<string, string>(TestData.Descriptor(),
            (request, _) => ValueTask.FromResult(Outcome.Success(request)), Available);
        var foreignContext = new FrozenHostContext(foreign, new AssistantContextBudget(1, 10), []);

        Xunit.Assert.True(registry.GetAvailability("measurements.read", foreignContext).TryGetFailure(out var failure));
        Xunit.Assert.Equal("perm.capability_denied", failure.Code);
        Refused(await registry.InvokeAsync(token, owner, "x", foreignContext, Xunit.TestContext.Current.CancellationToken),
            "perm.capability_denied");
    }

    [Xunit.Fact]
    public async Task UnknownOperationsAndBlankIdentifiersAreTypedRefusalsAndCancellationHappensBeforeTheHandler()
    {
        var owner = TestData.Host();
        var registry = TestData.Registry(owner);
        int calls = 0;
        var token = registry.Register<string, string>(TestData.Descriptor(),
            (request, _) =>
            {
                calls++;
                return ValueTask.FromResult(Outcome.Success(request));
            }, Available);

        Xunit.Assert.True(registry.GetAvailability("missing.operation").TryGetFailure(out var missing));
        Xunit.Assert.Equal("state.not_found", missing.Code);
        foreach (string blank in new[] { "", " ", "\t" })
        {
            Xunit.Assert.True(registry.GetAvailability(blank).TryGetFailure(out var invalid));
            Xunit.Assert.Equal("validation.invalid_request", invalid.Code);
        }

        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var result = await registry.InvokeAsync(token, owner, "x", cancellationToken: cancelled.Token);
        Xunit.Assert.Equal(OutcomeKind.Cancelled, result.Kind);
        Xunit.Assert.Equal(EffectCertainty.DidNotHappen, result.CancellationEffect);
        Xunit.Assert.Equal(0, calls);
    }

    [Xunit.Fact]
    public async Task HandlerFailuresAndRegistrationTokensStayWithinTheirOwnRegistry()
    {
        var owner = TestData.Host();
        var registry = TestData.Registry(owner);
        var other = TestData.Registry(owner);
        var failing = registry.Register<string, string>(TestData.Descriptor(),
            (_, _) => ValueTask.FromResult(Outcome.Failure<string>(TypedFailure.Create("resource.unavailable"))), Available);
        var otherToken = other.Register<string, string>(TestData.Descriptor(),
            (request, _) => ValueTask.FromResult(Outcome.Success(request)), Available);

        Refused(await registry.InvokeAsync(failing, owner, "x", cancellationToken: Xunit.TestContext.Current.CancellationToken),
            "resource.unavailable");
        // Same owner and same descriptor, but a token minted by a different registry must not be honoured.
        Refused(await registry.InvokeAsync(otherToken, owner, "x", cancellationToken: Xunit.TestContext.Current.CancellationToken),
            "perm.capability_denied");
        // An availability callback that yields nothing is a programming error, never an implicit "available".
        registry.Register<string, string>(TestData.Descriptor("annotations.append", "annotations.write"),
            (_, _) => ValueTask.FromResult(Outcome.Success("")), _ => null!);
        Xunit.Assert.Throws<InvalidOperationException>(() => registry.GetAvailability("annotations.append"));
    }

    private static void Refused<T>(Outcome<T> outcome, string code)
    {
        Xunit.Assert.True(outcome.TryGetFailure(out var failure));
        Xunit.Assert.Equal(code, failure.Code);
    }
}
