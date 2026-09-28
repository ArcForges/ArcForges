// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using IdentityGeneration = ArcForges.Foundation.IdentityGeneration;

namespace ArcForges.Capabilities.Tests;

public sealed class ArtifactHandlerRegistryTests
{
    [Xunit.Fact]
    public async Task HandlerSelectionIsKindScopedAndDeterministicByPreferenceThenPriority()
    {
        var registry = new ArtifactHandlerRegistry<string>(AppIdentity.ArcScope);
        int preferredCalls = 0;
        int priorityCalls = 0;
        var kindsSeenByHandlers = new List<string>();
        registry.Register("arcscope.report", "preferred", priority: 1,
            [ArtifactAction.Open, ArtifactAction.Preview],
            (candidate, _, _) =>
            {
                candidate.Kind = "companion.corrupted";
                return ValueTask.FromResult(Outcome.Success(true));
            },
            (candidate, _, _) =>
            {
                preferredCalls++;
                kindsSeenByHandlers.Add(candidate.Kind);
                return ValueTask.FromResult(Outcome.Success("preferred"));
            });
        registry.Register("arcscope.report", "priority", priority: 10,
            [ArtifactAction.Open],
            (_, _, _) => ValueTask.FromResult(Outcome.Success(true)),
            (_, _, _) =>
            {
                priorityCalls++;
                return ValueTask.FromResult(Outcome.Success("priority"));
            });
        registry.Register("arcscope.measurement", "measurement", priority: 100,
            [ArtifactAction.Open],
            (_, _, _) => ValueTask.FromResult(Outcome.Success(true)),
            (_, _, _) => ValueTask.FromResult(Outcome.Success("wrong kind")));

        var artifact = Artifact("arcscope.report");
        Xunit.Assert.Equal("priority", Value(await registry.DispatchAsync(artifact, ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken)));
        Xunit.Assert.Equal("preferred", Value(await registry.DispatchAsync(artifact, ArtifactAction.Open, "preferred", Xunit.TestContext.Current.CancellationToken)));
        Xunit.Assert.Equal("preferred", Value(await registry.DispatchAsync(artifact, ArtifactAction.Preview, "priority", Xunit.TestContext.Current.CancellationToken)));
        Xunit.Assert.Equal(2, preferredCalls);
        Xunit.Assert.Equal(1, priorityCalls);
        Xunit.Assert.Equal(2, kindsSeenByHandlers.Count);
        Xunit.Assert.All(kindsSeenByHandlers, kind => Xunit.Assert.Equal("arcscope.report", kind));
        Xunit.Assert.Equal("arcscope.report", artifact.Kind);

        Refused(await registry.DispatchAsync(Artifact("arcscope.unregistered"), ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken), "resource.unavailable");
        Refused(await registry.DispatchAsync(Artifact("companion.report", "companion"), ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken), "resource.unavailable");

        var foreignOwner = Artifact("arcscope.report");
        foreignOwner.Owner.Kind = "companion.report";
        Refused(await registry.DispatchAsync(foreignOwner, ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken), "validation.invalid_request");

        var malformedTimestamp = Artifact("arcscope.report");
        malformedTimestamp.CreatedAt.Nanos = 1_000_000_000;
        Refused(await registry.DispatchAsync(malformedTimestamp, ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken), "validation.invalid_request");

        malformedTimestamp = Artifact("arcscope.report");
        malformedTimestamp.CreatedAt.UnixSeconds = long.MaxValue;
        Refused(await registry.DispatchAsync(malformedTimestamp, ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken), "validation.invalid_request");
    }

    [Xunit.Fact]
    public async Task ArtifactPermissionIsRecheckedAndDenialDoesNotFallThroughToAnotherHandler()
    {
        var registry = new ArtifactHandlerRegistry<string>(AppIdentity.ArcScope);
        int lowerCalls = 0;
        int permissionChecks = 0;
        bool permitted = true;
        registry.Register("arcscope.report", "lower", priority: 1,
            [ArtifactAction.Open],
            (_, _, _) => ValueTask.FromResult(Outcome.Success(true)),
            (_, _, _) =>
            {
                lowerCalls++;
                return ValueTask.FromResult(Outcome.Success("lower"));
            });
        registry.Register("arcscope.report", "highest", priority: 100,
            [ArtifactAction.Open],
            (_, _, _) =>
            {
                permissionChecks++;
                return ValueTask.FromResult(Outcome.Success(permitted));
            },
            (_, _, _) => ValueTask.FromResult(Outcome.Success("highest")));

        var artifact = Artifact("arcscope.report");
        Xunit.Assert.Equal("highest", Value(await registry.DispatchAsync(artifact, ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken)));
        permitted = false;
        Refused(await registry.DispatchAsync(artifact, ArtifactAction.Open, cancellationToken: Xunit.TestContext.Current.CancellationToken), "perm.resource_denied");
        Xunit.Assert.Equal(2, permissionChecks);
        Xunit.Assert.Equal(0, lowerCalls);
    }

    [Xunit.Fact]
    public void RegistrationRejectsUnownedKindsInvalidActionsAndDuplicateHandlerIds()
    {
        var registry = new ArtifactHandlerRegistry<string>(AppIdentity.ArcScope);
        ArtifactPermissionCheck allow = (_, _, _) => ValueTask.FromResult(Outcome.Success(true));
        ArtifactHandlerAccess<string> access = (_, _, _) => ValueTask.FromResult(Outcome.Success("opened"));
        Xunit.Assert.Throws<ArgumentException>(() => registry.Register("companion.report", "handler", 0, [ArtifactAction.Open], allow, access));
        Xunit.Assert.Throws<ArgumentException>(() => registry.Register("arcscope.report", "handler", 0, [ArtifactAction.None], allow, access));
        registry.Register("arcscope.report", "handler", 0, [ArtifactAction.Open], allow, access);
        Xunit.Assert.Throws<InvalidOperationException>(() => registry.Register("arcscope.report", "handler", 1, [ArtifactAction.Open], allow, access));
    }

    private static ArtifactRef Artifact(string kind, string owner = "arcscope") => new()
    {
        ArtifactId = IdentityGeneration.NewArtifact().ToWire(),
        Kind = kind,
        Owner = new AggregateRef { Kind = owner + ".report", Id = IdentityGeneration.NewResource().ToWire() },
        Actor = new ActorChain
        {
            Initiator = IdentityGeneration.NewUser().ToWire(),
            Owner = IdentityGeneration.NewUser().ToWire(),
        },
        CreatedAt = new Instant { UnixSeconds = 1, Nanos = 0 },
        Availability = "available",
    };

    private static string Value(Outcome<string> outcome)
    {
        Xunit.Assert.True(outcome.TryGetValue(out var value));
        return value;
    }

    private static void Refused<T>(Outcome<T> outcome, string code)
    {
        Xunit.Assert.True(outcome.TryGetFailure(out var failure));
        Xunit.Assert.Equal(code, failure.Code);
        Xunit.Assert.Equal(EffectCertainty.DidNotHappen, failure.Effect);
        Xunit.Assert.Equal(RetryMode.Never, failure.Retry);
    }
}
